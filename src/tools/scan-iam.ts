import {
  IAMClient,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
} from '@aws-sdk/client-iam';
import type { Finding, ScanInput, ScanResult } from '../types.js';
import { collectPages, markerToken } from '../paginate.js';

const ACCESS_KEY_MAX_AGE_DAYS = 90;

// IAM is a global service — region param is accepted for consistency but not used in API calls.
// IAM is a global service: an access key or MFA setting has no region. The
// client still needs one to sign requests, but findings must not claim it —
// labelling a global finding "eu-west-1" sends people to the wrong console.
const GLOBAL = 'global';

export async function scanIam({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new IAMClient({ region, ...(credentials && { credentials }) });
  const findings: Finding[] = [];

  try {
    await checkRootAccount(client, GLOBAL, findings);
    await checkIamUsers(client, GLOBAL, findings);
    return { ok: true, findings };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

async function checkRootAccount(client: IAMClient, region: string, findings: Finding[]) {
  const summary = await client.send(new GetAccountSummaryCommand({}));
  const map = summary.SummaryMap ?? {};

  if (map['AccountAccessKeysPresent'] && map['AccountAccessKeysPresent'] > 0) {
    findings.push({
      service: 'IAM',
      resourceId: 'root',
      region,
      severity: 'HIGH',
      title: 'Root account has active access keys',
      description:
        'The AWS root account has programmatic access keys. Root keys have unrestricted access ' +
        'to everything in your account — if leaked, an attacker can do anything. ' +
        'AWS explicitly recommends deleting root access keys.',
      fixSteps: [
        'Sign in as root → click your account name → Security credentials.',
        'Under "Access keys", delete all root access keys.',
        'Use IAM users or roles for programmatic access instead.',
      ],
      estimatedFixMinutes: 5,
    });
  }

  if (!map['AccountMFAEnabled'] || map['AccountMFAEnabled'] === 0) {
    findings.push({
      service: 'IAM',
      resourceId: 'root',
      region,
      severity: 'HIGH',
      title: 'Root account does not have MFA enabled',
      description:
        'The AWS root account has no multi-factor authentication. ' +
        'If the root password is compromised, an attacker has full unrestricted access to your entire account.',
      fixSteps: [
        'Sign in as root → click your account name → Security credentials.',
        'Under "Multi-factor authentication (MFA)", assign an MFA device.',
        'A hardware MFA key (e.g. YubiKey) is ideal; a virtual MFA app also works.',
      ],
      estimatedFixMinutes: 10,
    });
  }
}

async function checkIamUsers(client: IAMClient, region: string, findings: Finding[]) {
  // ListUsers caps at 100 per page. Before this paginated, an account with
  // more than 100 users had the rest silently skipped, and the MFA finding
  // was reported as if it covered everyone.
  const users = await collectPages({
    fetchPage: (Marker) =>
      client.send(new ListUsersCommand({ ...(Marker !== undefined && { Marker }) })),
    itemsOf: (page) => page.Users,
    tokenOf: markerToken,
  });

  await Promise.all(
    users.map(async (user) => {
      const username = user.UserName ?? 'unknown';

      // Check for stale access keys
      const keysResponse = await client.send(new ListAccessKeysCommand({ UserName: username }));
      for (const key of keysResponse.AccessKeyMetadata ?? []) {
        if (key.Status !== 'Active') continue;

        const keyId = key.AccessKeyId ?? 'unknown';
        const lastUsedResponse = await client.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: keyId }));
        const lastUsed = lastUsedResponse.AccessKeyLastUsed?.LastUsedDate;
        const createdAt = key.CreateDate;

        const referenceDate = lastUsed ?? createdAt;
        if (!referenceDate) continue;

        const ageDays = Math.floor((Date.now() - referenceDate.getTime()) / (1000 * 60 * 60 * 24));

        if (ageDays > ACCESS_KEY_MAX_AGE_DAYS) {
          const neverUsed = !lastUsed;
          findings.push({
            service: 'IAM',
            resourceId: `${username}/${keyId}`,
            region,
            severity: neverUsed ? 'HIGH' : 'MEDIUM',
            title: neverUsed
              ? `IAM access key never used: ${username} (${keyId})`
              : `IAM access key not rotated in ${ageDays} days: ${username} (${keyId})`,
            description: neverUsed
              ? `User "${username}" has an active access key (${keyId}) that has never been used. ` +
                `Unused keys are a security risk — if leaked, they give permanent access with no audit trail.`
              : `User "${username}" has an active access key (${keyId}) that hasn't been used in ${ageDays} days. ` +
                `Keys should be rotated every ${ACCESS_KEY_MAX_AGE_DAYS} days to limit exposure if compromised.`,
            fixSteps: [
              neverUsed
                ? `Delete the key immediately: IAM → Users → ${username} → Security credentials → delete ${keyId}.`
                : `Rotate the key: create a new key, update wherever it's used, then delete the old one.`,
              `CLI: aws iam delete-access-key --user-name ${username} --access-key-id ${keyId}`,
            ],
            estimatedFixMinutes: neverUsed ? 2 : 15,
          });
        }
      }

      // Check for users without MFA
      const mfaResponse = await client.send(new ListMFADevicesCommand({ UserName: username }));
      if ((mfaResponse.MFADevices ?? []).length === 0) {
        findings.push({
          service: 'IAM',
          resourceId: username,
          region,
          severity: 'MEDIUM',
          title: `IAM user has no MFA: ${username}`,
          description:
            `User "${username}" can sign in with just a password — no second factor required. ` +
            `If the password is leaked or guessed, the account is compromised.`,
          fixSteps: [
            `IAM → Users → ${username} → Security credentials → Assign MFA device.`,
            `A virtual MFA app (Google Authenticator, Authy) takes about 2 minutes to set up.`,
          ],
          estimatedFixMinutes: 5,
        });
      }
    })
  );
}
