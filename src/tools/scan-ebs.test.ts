import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { EC2Client, DescribeVolumesCommand } from '@aws-sdk/client-ec2';
import { scanUnattachedEbs } from './scan-ebs.js';

const ec2Mock = mockClient(EC2Client);

describe('scanUnattachedEbs', () => {
  beforeEach(() => {
    ec2Mock.reset();
  });

  it('returns no findings when every volume is attached', async () => {
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });

    const result = await scanUnattachedEbs({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags an unattached volume with the correct monthly cost', async () => {
    ec2Mock.on(DescribeVolumesCommand).resolves({
      Volumes: [
        {
          VolumeId: 'vol-0abc123',
          Size: 100,
          VolumeType: 'gp3',
          CreateTime: new Date('2026-01-15T00:00:00Z'),
          Tags: [{ Key: 'Name', Value: 'orphaned-data' }],
        },
      ],
    });

    const result = await scanUnattachedEbs({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      service: 'EBS',
      resourceId: 'vol-0abc123',
      severity: 'MEDIUM',
      // 100 GB × $0.08/GB/month for gp3
      estimatedMonthlySavingsUsd: 8,
    });
    expect(result.findings[0]?.description).toContain('2026-01-15');
  });

  it('falls back to the gp2 rate for unknown volume types', async () => {
    ec2Mock.on(DescribeVolumesCommand).resolves({
      Volumes: [{ VolumeId: 'vol-1', Size: 10, VolumeType: 'standard' }],
    });

    const result = await scanUnattachedEbs({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings[0]?.estimatedMonthlySavingsUsd).toBe(1);
  });

  it('returns ok: false when the API call fails', async () => {
    ec2Mock.on(DescribeVolumesCommand).rejects(new Error('UnauthorizedOperation'));

    const result = await scanUnattachedEbs({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('UnauthorizedOperation');
  });
});
