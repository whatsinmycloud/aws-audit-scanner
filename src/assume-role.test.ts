import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { assumeAuditRole } from './assume-role.js';

const stsMock = mockClient(STSClient);

const INPUT = {
  roleArn: 'arn:aws:iam::123456789012:role/WhatsInMyCloudAudit',
  externalId: 'test-external-id',
  region: 'eu-west-1',
};

describe('assumeAuditRole', () => {
  beforeEach(() => {
    stsMock.reset();
  });

  it('returns the temporary credentials on success', async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: 'ASIATEST',
        SecretAccessKey: 'secret',
        SessionToken: 'token',
        Expiration: new Date(),
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::123456789012:assumed-role/WhatsInMyCloudAudit/whatsinmycloud-audit',
        AssumedRoleId: 'AROATEST:whatsinmycloud-audit',
      },
    });

    const result = await assumeAuditRole(INPUT);

    expect(result).toEqual({
      ok: true,
      credentials: { accessKeyId: 'ASIATEST', secretAccessKey: 'secret', sessionToken: 'token' },
    });
  });

  it('sends the role ARN and external ID exactly as given', async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: 'ASIATEST',
        SecretAccessKey: 'secret',
        SessionToken: 'token',
        Expiration: new Date(),
      },
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::123456789012:assumed-role/WhatsInMyCloudAudit/whatsinmycloud-audit',
        AssumedRoleId: 'AROATEST:whatsinmycloud-audit',
      },
    });

    await assumeAuditRole(INPUT);

    expect(stsMock.commandCalls(AssumeRoleCommand)[0]?.args[0].input).toMatchObject({
      RoleArn: INPUT.roleArn,
      ExternalId: INPUT.externalId,
      RoleSessionName: 'whatsinmycloud-audit',
    });
  });

  it('returns ok: false when STS rejects the assumption (wrong external ID, missing role)', async () => {
    stsMock.on(AssumeRoleCommand).rejects(
      new Error('User is not authorized to perform: sts:AssumeRole')
    );

    const result = await assumeAuditRole(INPUT);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('not authorized');
  });

  it('returns ok: false when STS responds without complete credentials', async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: { AccessKeyId: 'ASIATEST' } as never,
    });

    const result = await assumeAuditRole(INPUT);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('incomplete credentials');
  });
});

describe('assumeAuditRole — account assertion', () => {
  beforeEach(() => stsMock.reset());

  const credentials = {
    AccessKeyId: 'ASIATEST',
    SecretAccessKey: 'secret',
    SessionToken: 'token',
    Expiration: new Date(),
  };

  // Should be impossible — STS returns the account it assumed into — but a
  // report attributed to the wrong account is the worst failure this product
  // could have, so the invariant is asserted rather than assumed.
  it('refuses credentials belonging to a different account than the role ARN', async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: credentials,
      AssumedRoleUser: {
        Arn: 'arn:aws:sts::999988887777:assumed-role/WhatsInMyCloudAudit/whatsinmycloud-audit',
        AssumedRoleId: 'AROAOTHER:whatsinmycloud-audit',
      },
    });

    const result = await assumeAuditRole(INPUT);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatch(/do not belong to the requested account/i);
  });

  it('refuses when the assumed identity is missing entirely', async () => {
    stsMock.on(AssumeRoleCommand).resolves({ Credentials: credentials });

    const result = await assumeAuditRole(INPUT);

    expect(result.ok).toBe(false);
  });
});
