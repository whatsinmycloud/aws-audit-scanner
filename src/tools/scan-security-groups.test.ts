import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import type { SecurityGroup } from '@aws-sdk/client-ec2';
import { scanSecurityGroups } from './scan-security-groups.js';

const ec2Mock = mockClient(EC2Client);

function securityGroup(overrides: Partial<SecurityGroup>): SecurityGroup {
  return { GroupId: 'sg-0abc123', GroupName: 'test-sg', VpcId: 'vpc-1', ...overrides };
}

describe('scanSecurityGroups', () => {
  beforeEach(() => {
    ec2Mock.reset();
  });

  it('flags SSH open to the world as HIGH', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('HIGH');
    expect(result.findings[0]?.title).toContain('SSH');
  });

  it('flags an all-traffic rule open to the world as HIGH', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.title).toContain('ALL traffic');
  });

  it('catches a sensitive port inside a wider port range', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 3000,
              ToPort: 4000,
              IpRanges: [{ CidrIp: '0.0.0.0/0' }],
            },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // 3306 (MySQL) and 3389 (RDP) both fall inside 3000-4000
    expect(result.findings).toHaveLength(2);
    const titles = result.findings.map((f) => f.title).join('\n');
    expect(titles).toContain('MySQL');
    expect(titles).toContain('RDP');
  });

  it('detects IPv6 exposure (::/0)', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 5432, ToPort: 5432, Ipv6Ranges: [{ CidrIpv6: '::/0' }] },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.title).toContain('PostgreSQL');
  });

  it('ignores sensitive ports restricted to a private range', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '10.0.0.0/8' }] },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('ignores non-sensitive ports open to the world (e.g. HTTPS)', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('returns ok: false when the API call fails', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).rejects(new Error('RequestLimitExceeded'));

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('RequestLimitExceeded');
  });

  it('warns to verify nothing depends on the rule before revoking it — both finding types', async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
      SecurityGroups: [
        securityGroup({
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
            { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          ],
        }),
      ],
    });

    const result = await scanSecurityGroups({ region: 'eu-west-1' });

    if (!result.ok) throw new Error('expected ok');
    expect(result.findings).toHaveLength(2);
    for (const finding of result.findings) {
      expect(finding.fixSteps.some((step) => /verify.*before.*revok|verify.*before.*remov/i.test(step))).toBe(true);
    }
  });
});
