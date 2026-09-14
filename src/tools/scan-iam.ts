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

// Two different questions that were previously conflated. Rotation age comes
// from the key's CreateDate; inactivity comes from LastUsedDate. Reporting one
// as the other produced a finding titled "not rotated in N days" where N was
// days since last use — and, worse, missed the dangerous case entirely: a key
// created three years ago and used yesterday has an inactivity of 1 day, so it
// never fired at all.
const ACCESS_KEY_MAX_AGE_DAYS = 90;
const ACCESS_KEY_MAX_IDLE_DAYS = 90;

function daysSince(date: Date): number {
  return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
}

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

        const idleDays = lastUsed ? daysSince(lastUsed) : undefined;
        const ageDays = createdAt ? daysSince(createdAt) : undefined;

        // One finding per key, most urgent first, so a key that is both old and
        // idle doesn't produce two rows saying nearly the same thing.
        if (createdAt && idleDays === undefined && ageDays !== undefined && ageDays > ACCESS_KEY_MAX_AGE_DAYS) {
          findings.push({
            service: 'IAM',
            resourceId: `${username}/${keyId}`,
            region,
            severity: 'HIGH',
            title: `IAM access key never used: ${username} (${keyId})`,
            description:
              `User "${username}" has an active access key (${keyId}), created ${ageDays} days ago, ` +
              `that has never been used. Unused keys are a security risk: if leaked, they give ` +
              `permanent access with no audit trail.`,
            fixSteps: [
              `Delete the key: IAM → Users → ${username} → Security credentials → delete ${keyId}.`,
              `CLI: aws iam delete-access-key --user-name ${username} --access-key-id ${keyId}`,
            ],
            estimatedFixMinutes: 2,
          });
        } else if (idleDays !== undefined && idleDays > ACCESS_KEY_MAX_IDLE_DAYS) {
          findings.push({
            service: 'IAM',
            resourceId: `${username}/${keyId}`,
            region,
            severity: 'MEDIUM',
            title: `IAM access key unused for ${idleDays} days: ${username} (${keyId})`,
            description:
              `User "${username}" has an active access key (${keyId}) that hasn't been used in ` +
              `${idleDays} days. A key nobody uses is a way in that nobody is watching.`,
            fixSteps: [
              `Confirm nothing still depends on it, then delete: IAM → Users → ${username} → Security credentials.`,
              `CLI: aws iam delete-access-key --user-name ${username} --access-key-id ${keyId}`,
            ],
            estimatedFixMinutes: 10,
          });
        } else if (ageDays !== undefined && ageDays > ACCESS_KEY_MAX_AGE_DAYS) {
          findings.push({
            service: 'IAM',
            resourceId: `${username}/${keyId}`,
            region,
            severity: 'MEDIUM',
            title: `IAM access key is ${ageDays} days old: ${username} (${keyId})`,
            description:
              `User "${username}" has an active access key (${keyId}) created ${ageDays} days ago ` +
              `and still in use. Rotating every ${ACCESS_KEY_MAX_AGE_DAYS} days limits how long a ` +
              `leaked key stays useful.`,
            fixSteps: [
              `Rotate it: create a new key, update wherever it's used, confirm nothing broke, then delete the old one.`,
              `CLI: aws iam create-access-key --user-name ${username}`,
            ],
            estimatedFixMinutes: 15,
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
          title: `IAM user has no MFA device: ${username}`,
          // Deliberately conditional. ListMFADevices tells us no device is
          // registered; it says nothing about whether the user has a console
          // password at all. A programmatic-only service account has no MFA
          // device and cannot sign in with a password, so the old wording
          // ("can sign in with just a password") was simply false for those
          // users. Knowing which is which needs iam:GetLoginProfile or the
          // credential report, neither of which the audit role currently
          // grants — so the finding states what we can see and flags what we
          // can't, rather than guessing.
          description:
            `User "${username}" has no MFA device registered. If this user can sign in to the ` +
            `console, a leaked or guessed password is all an attacker needs. Our read-only access ` +
            `can't see whether a console password is set, so if this is a service account used ` +
            `only for API calls, there may be nothing to fix here.`,
          fixSteps: [
            `Check first whether this user has console access: IAM → Users → ${username} → Security credentials → "Console sign-in". If there's no password, no MFA is needed.`,
            `If they do sign in: same page → Assign MFA device.`,
            `A virtual MFA app (Google Authenticator, Authy) takes about 2 minutes to set up.`,
          ],
          estimatedFixMinutes: 5,
        });
      }
    })
  );
}
