import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import type { AwsCredentials } from './types.js';

export type AssumeRoleInput = {
  roleArn: string;
  externalId: string;
  region: string;
};

export type AssumeRoleResult =
  | { ok: true; credentials: AwsCredentials }
  | { ok: false; error: string };

// Assumes the customer's WhatsInMyCloudAudit role (created by
// cloudformation/readonly-role.yaml). sts:AssumeRole is the one non-read
// verb the scanner is allowed to call — it grants no access beyond what
// the customer's role policy permits.
export async function assumeAuditRole({ roleArn, externalId, region }: AssumeRoleInput): Promise<AssumeRoleResult> {
  const client = new STSClient({ region });

  try {
    const response = await client.send(
      new AssumeRoleCommand({
        RoleArn: roleArn,
        ExternalId: externalId,
        RoleSessionName: 'whatsinmycloud-audit',
        // 15 minutes: covers a scan (~40s) with wide margin, matches the
        // customer role's MaxSessionDuration, and keeps the window in which
        // issued credentials stay usable small. Must not exceed the role's
        // MaxSessionDuration or AssumeRole fails.
        DurationSeconds: 900,
      })
    );

    const c = response.Credentials;
    if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
      return { ok: false, error: 'AssumeRole succeeded but returned incomplete credentials' };
    }

    // Defence in depth: assert the credentials really belong to the account in
    // the role ARN before anything reads from them. It should be impossible for
    // these to differ — STS returns the account it assumed into — but a report
    // attributed to the wrong account is the worst failure this product could
    // have, so it's worth one string comparison rather than an assumption.
    // Uses the ARN already in the response; no extra API call.
    const expectedAccount = roleArn.match(/^arn:aws:iam::(\d{12}):/)?.[1];
    const assumedAccount = response.AssumedRoleUser?.Arn?.match(/^arn:aws:sts::(\d{12}):/)?.[1];
    if (!expectedAccount || !assumedAccount || expectedAccount !== assumedAccount) {
      return {
        ok: false,
        error: 'Assumed credentials do not belong to the requested account — refusing to scan',
      };
    }

    return {
      ok: true,
      credentials: {
        accessKeyId: c.AccessKeyId,
        secretAccessKey: c.SecretAccessKey,
        sessionToken: c.SessionToken,
      },
    };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}
