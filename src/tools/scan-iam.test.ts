import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  IAMClient,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  GetLoginProfileCommand,
} from '@aws-sdk/client-iam';
import { scanIam } from './scan-iam.js';

const iamMock = mockClient(IAMClient);

const HEALTHY_SUMMARY = { SummaryMap: { AccountAccessKeysPresent: 0, AccountMFAEnabled: 1 } };
// GetLoginProfile answers "can this user sign in to the console": a profile
// means yes, NoSuchEntity means no, and a denial (an audit role deployed
// before iam:GetLoginProfile was granted) means we must not guess.
const noSuchEntity = Object.assign(new Error('no login profile'), { name: 'NoSuchEntityException' });
const accessDenied = Object.assign(new Error('not authorized'), { name: 'AccessDenied' });

const MFA_DEVICE = { MFADevices: [{ UserName: 'stephen', SerialNumber: 'arn:mfa', EnableDate: new Date() }] };

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

// ServiceName/Region are required by the SDK type; LastUsedDate omitted = never used
function lastUsed(date?: Date) {
  return {
    AccessKeyLastUsed: { ServiceName: 's3', Region: 'eu-west-1', ...(date && { LastUsedDate: date }) },
  };
}

describe('scanIam', () => {
  beforeEach(() => {
    iamMock.reset();
  });

  it('returns no findings for a healthy account', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'stephen', Path: '/', UserId: 'u1', Arn: 'arn:u1', CreateDate: daysAgo(400) }] });
    iamMock.on(ListAccessKeysCommand).resolves({
      AccessKeyMetadata: [{ AccessKeyId: 'AKIAFRESH', Status: 'Active', CreateDate: daysAgo(10) }],
    });
    iamMock.on(GetAccessKeyLastUsedCommand).resolves(lastUsed(daysAgo(1)));
    iamMock.on(ListMFADevicesCommand).resolves(MFA_DEVICE);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags root access keys and missing root MFA as HIGH', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves({
      SummaryMap: { AccountAccessKeysPresent: 1, AccountMFAEnabled: 0 },
    });
    iamMock.on(ListUsersCommand).resolves({ Users: [] });

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.severity === 'HIGH' && f.resourceId === 'root')).toBe(true);
    const titles = result.findings.map((f) => f.title).join('\n');
    expect(titles).toContain('access keys');
    expect(titles).toContain('MFA');
  });

  it('reports an idle key as idle, not as unrotated', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'stephen', Path: '/', UserId: 'u1', Arn: 'arn:u1', CreateDate: daysAgo(400) }] });
    iamMock.on(ListAccessKeysCommand).resolves({
      AccessKeyMetadata: [{ AccessKeyId: 'AKIASTALE', Status: 'Active', CreateDate: daysAgo(400) }],
    });
    iamMock.on(GetAccessKeyLastUsedCommand).resolves(lastUsed(daysAgo(120)));
    iamMock.on(ListMFADevicesCommand).resolves(MFA_DEVICE);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      severity: 'MEDIUM',
      resourceId: 'stephen/AKIASTALE',
    });
    // Was titled "not rotated in 120 days", where 120 was days since last use.
    // Inactivity and rotation age are different questions and the title now
    // says which one this is.
    expect(result.findings[0]?.title).toContain('unused for 120 days');
    expect(result.findings[0]?.title).not.toContain('rotated');
  });

  it('flags a key that is old but still in active use', async () => {
    // The case the old code missed completely: age was measured from
    // LastUsedDate, so a key created three years ago and used yesterday
    // looked one day old and produced no finding at all.
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'stephen', Path: '/', UserId: 'u1', Arn: 'arn:u1', CreateDate: daysAgo(1200) }] });
    iamMock.on(ListAccessKeysCommand).resolves({
      AccessKeyMetadata: [{ AccessKeyId: 'AKIAOLDACTIVE', Status: 'Active', CreateDate: daysAgo(1100) }],
    });
    iamMock.on(GetAccessKeyLastUsedCommand).resolves(lastUsed(daysAgo(1)));
    iamMock.on(ListMFADevicesCommand).resolves(MFA_DEVICE);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.title).toContain('1100 days old');
  });

  function userWithoutMfa(name: string) {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: name, Path: '/', UserId: 'u2', Arn: 'arn:u2', CreateDate: daysAgo(30) }] });
    iamMock.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });
    iamMock.on(ListMFADevicesCommand).resolves({ MFADevices: [] });
  }

  // The false positive this replaced: every programmatic-only service account
  // was told it "can sign in with just a password", which it cannot.
  it('raises nothing for a user with no console password', async () => {
    userWithoutMfa('ci-deploy');
    iamMock.on(GetLoginProfileCommand).rejects(noSuchEntity);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.filter((f) => f.title.includes('MFA device'))).toHaveLength(0);
  });

  it('raises MEDIUM and says so plainly when the user does have console access', async () => {
    userWithoutMfa('stephen');
    iamMock.on(GetLoginProfileCommand).resolves({});

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const mfa = result.findings.find((f) => f.title.includes('MFA device'));
    expect(mfa?.severity).toBe('MEDIUM');
    expect(mfa?.title).toContain('has console access and no MFA device');
  });

  it('downgrades to LOW and admits the gap when the permission is missing', async () => {
    userWithoutMfa('stephen');
    iamMock.on(GetLoginProfileCommand).rejects(accessDenied);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const mfa = result.findings.find((f) => f.title.includes('MFA device'));
    expect(mfa?.severity).toBe('LOW');
    expect(mfa?.title).toContain('console access unknown');
    expect(mfa?.description).toContain('iam:GetLoginProfile');
    expect(mfa?.description).not.toContain('can sign in with just a password');
  });

  it('flags an old never-used access key as HIGH', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'stephen', Path: '/', UserId: 'u1', Arn: 'arn:u1', CreateDate: daysAgo(400) }] });
    iamMock.on(ListAccessKeysCommand).resolves({
      AccessKeyMetadata: [{ AccessKeyId: 'AKIAUNUSED', Status: 'Active', CreateDate: daysAgo(120) }],
    });
    iamMock.on(GetAccessKeyLastUsedCommand).resolves(lastUsed());
    iamMock.on(ListMFADevicesCommand).resolves(MFA_DEVICE);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('HIGH');
    expect(result.findings[0]?.title).toContain('never used');
  });

  it('ignores inactive access keys', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'stephen', Path: '/', UserId: 'u1', Arn: 'arn:u1', CreateDate: daysAgo(400) }] });
    iamMock.on(ListAccessKeysCommand).resolves({
      AccessKeyMetadata: [{ AccessKeyId: 'AKIAOLD', Status: 'Inactive', CreateDate: daysAgo(500) }],
    });
    iamMock.on(ListMFADevicesCommand).resolves(MFA_DEVICE);

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
    expect(iamMock.commandCalls(GetAccessKeyLastUsedCommand)).toHaveLength(0);
  });

  it('flags a user without MFA as MEDIUM', async () => {
    iamMock.on(GetAccountSummaryCommand).resolves(HEALTHY_SUMMARY);
    iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'ci-bot', Path: '/', UserId: 'u2', Arn: 'arn:u2', CreateDate: daysAgo(30) }] });
    iamMock.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });
    iamMock.on(ListMFADevicesCommand).resolves({ MFADevices: [] });

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      severity: 'MEDIUM',
      resourceId: 'ci-bot',
    });
  });

  it('returns ok: false when the account summary call fails', async () => {
    iamMock.on(GetAccountSummaryCommand).rejects(new Error('AccessDenied'));

    const result = await scanIam({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('AccessDenied');
  });
});

describe('scanIam — region labelling', () => {
  it('marks findings global, since IAM has no region', async () => {
    iamMock.reset();
    iamMock.on(GetAccountSummaryCommand).resolves({ SummaryMap: { AccountMFAEnabled: 0 } });
    iamMock.on(ListUsersCommand).resolves({ Users: [] });

    // Scanned from eu-west-1, but an MFA setting does not live in eu-west-1.
    const result = await scanIam({ region: 'eu-west-1' });

    if (!result.ok) throw new Error('expected ok');
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.region).toBe('global');
    }
  });
});
