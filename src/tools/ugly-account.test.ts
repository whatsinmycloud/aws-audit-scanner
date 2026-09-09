import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeVolumesCommand,
  DescribeSecurityGroupsCommand,
  InstanceStateName,
  VolumeType,
} from '@aws-sdk/client-ec2';
import type { Reservation, Volume, SecurityGroup } from '@aws-sdk/client-ec2';
import {
  IAMClient,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  ListMFADevicesCommand,
} from '@aws-sdk/client-iam';
import { scanStoppedEc2 } from './scan-ec2.js';
import { scanUnattachedEbs } from './scan-ebs.js';
import { scanSecurityGroups } from './scan-security-groups.js';
import { scanIam } from './scan-iam.js';

// Fixtures for an account far messier than the ones we own. Every scan we had
// ever run was against two small accounts of Stephen's, so "70 scans, 0 failed"
// was measuring our own implementations, not the space of real AWS accounts.
// Two failures came out of that gap: a token ceiling that broke on the first
// real account (2026-09-07), and unpaginated list calls that would have
// under-reported silently — a wrong number in a security report, which is
// worse than an error because nothing signals it is wrong.
//
// Sizes here are just past each API's real page boundary: IAM ListUsers caps
// at 100, DescribeVolumes at 500, DescribeInstances and
// DescribeSecurityGroups at 1000.

const ec2Mock = mockClient(EC2Client);
const iamMock = mockClient(IAMClient);

const REGION = 'eu-west-1';

function reservationsOf(ids: string[]): Reservation[] {
  return ids.map((id) => ({
    Instances: [
      {
        InstanceId: id,
        InstanceType: 't3.micro',
        State: { Name: InstanceStateName.stopped },
        Tags: [],
      },
    ],
  }));
}

function volumesOf(ids: string[]): Volume[] {
  return ids.map((id) => ({ VolumeId: id, Size: 8, VolumeType: VolumeType.gp3, Tags: [] }));
}

function ids(prefix: string, count: number, from = 0): string[] {
  return Array.from({ length: count }, (_, i) => `${prefix}-${from + i}`);
}

describe('an account far bigger than one page', () => {
  beforeEach(() => {
    ec2Mock.reset();
    iamMock.reset();
  });

  it('counts every stopped instance across three pages, not just the first', async () => {
    ec2Mock
      .on(DescribeInstancesCommand)
      .resolvesOnce({ Reservations: reservationsOf(ids('i', 1000)), NextToken: 'p2' })
      .resolvesOnce({ Reservations: reservationsOf(ids('i', 1000, 1000)), NextToken: 'p3' })
      .resolves({ Reservations: reservationsOf(ids('i', 250, 2000)) });

    const result = await scanStoppedEc2({ region: REGION });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(2250);
    // The last page has to be present — truncation would still leave a
    // plausible-looking report, just a wrong one.
    expect(result.findings.some((f) => f.resourceId === 'i-2249')).toBe(true);
  });

  it('counts every unattached volume past the 500-per-page boundary', async () => {
    ec2Mock
      .on(DescribeVolumesCommand)
      .resolvesOnce({ Volumes: volumesOf(ids('vol', 500)), NextToken: 'p2' })
      .resolves({ Volumes: volumesOf(ids('vol', 137, 500)) });

    const result = await scanUnattachedEbs({ region: REGION });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(637);
    expect(result.findings.some((f) => f.resourceId === 'vol-636')).toBe(true);
  });

  it('checks security groups on later pages for world-open ports', async () => {
    const harmless: SecurityGroup[] = ids('sg-ok', 1000).map((id) => ({
      GroupId: id,
      GroupName: id,
      IpPermissions: [],
    }));
    // The dangerous one sits on page two, where an unpaginated scan would
    // never have looked.
    const dangerous: SecurityGroup = {
      GroupId: 'sg-open-ssh',
      GroupName: 'legacy-bastion',
      IpPermissions: [
        {
          IpProtocol: 'tcp',
          FromPort: 22,
          ToPort: 22,
          IpRanges: [{ CidrIp: '0.0.0.0/0' }],
        },
      ],
    };

    ec2Mock
      .on(DescribeSecurityGroupsCommand)
      .resolvesOnce({ SecurityGroups: harmless, NextToken: 'p2' })
      .resolves({ SecurityGroups: [dangerous] });

    const result = await scanSecurityGroups({ region: REGION });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.some((f) => f.resourceId === 'sg-open-ssh')).toBe(true);
  });

  it('checks every IAM user for MFA, not the first hundred', async () => {
    // The sharpest case: ListUsers returns 100 by default. An account with 150
    // users used to report on 100 of them and say nothing about the rest.
    iamMock.on(GetAccountSummaryCommand).resolves({
      SummaryMap: { AccountAccessKeysPresent: 0, AccountMFAEnabled: 1 },
    });
    iamMock
      .on(ListUsersCommand)
      .resolvesOnce({
        Users: ids('user', 100).map((UserName) => ({
          UserName,
          UserId: UserName,
          Arn: `arn:aws:iam::1:user/${UserName}`,
          Path: '/',
          CreateDate: new Date(),
        })),
        IsTruncated: true,
        Marker: 'page2',
      })
      .resolves({
        Users: ids('user', 50, 100).map((UserName) => ({
          UserName,
          UserId: UserName,
          Arn: `arn:aws:iam::1:user/${UserName}`,
          Path: '/',
          CreateDate: new Date(),
        })),
        IsTruncated: false,
      });
    iamMock.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });
    // Nobody has MFA, so every user should produce a finding.
    iamMock.on(ListMFADevicesCommand).resolves({ MFADevices: [] });

    const result = await scanIam({ region: REGION });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const noMfa = result.findings.filter((f) => f.title.startsWith('IAM user has no MFA'));
    expect(noMfa).toHaveLength(150);
    expect(noMfa.some((f) => f.title.includes('user-149'))).toBe(true);
  });

  it('stops following the Marker when IsTruncated is false, even if one is returned', async () => {
    // IAM can hand back a Marker on the final page. Following it would re-read
    // page one forever and double every finding.
    iamMock.on(GetAccountSummaryCommand).resolves({
      SummaryMap: { AccountAccessKeysPresent: 0, AccountMFAEnabled: 1 },
    });
    iamMock.on(ListUsersCommand).resolves({
      Users: [
        {
          UserName: 'only-user',
          UserId: 'u1',
          Arn: 'arn:aws:iam::1:user/only-user',
          Path: '/',
          CreateDate: new Date(),
        },
      ],
      IsTruncated: false,
      Marker: 'a-stale-marker',
    });
    iamMock.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });
    iamMock.on(ListMFADevicesCommand).resolves({ MFADevices: [] });

    const result = await scanIam({ region: REGION });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.filter((f) => f.title.startsWith('IAM user has no MFA'))).toHaveLength(1);
  });
});
