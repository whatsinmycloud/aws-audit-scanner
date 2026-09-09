import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  EC2Client,
  DescribeRegionsCommand,
  DescribeInstancesCommand,
  DescribeVolumesCommand,
} from '@aws-sdk/client-ec2';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { sweepOtherRegions } from './region-sweep.js';

const ec2Mock = mockClient(EC2Client);
const rdsMock = mockClient(RDSClient);

const THREE_REGIONS = {
  Regions: [
    { RegionName: 'eu-west-1' },
    { RegionName: 'us-east-1' },
    { RegionName: 'eu-central-1' },
  ],
};

describe('sweepOtherRegions', () => {
  beforeEach(() => {
    ec2Mock.reset();
    rdsMock.reset();
  });

  it('returns no findings when the other regions are empty', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(THREE_REGIONS);
    ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
    rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

    const result = await sweepOtherRegions({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags a region with forgotten resources, excluding the scanned region', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(THREE_REGIONS);
    // The mock answers identically for every region, so both probed regions
    // "contain" these resources — the scanned region must still be absent.
    ec2Mock.on(DescribeInstancesCommand).resolves({
      Reservations: [
        {
          Instances: [
            { InstanceId: 'i-1', State: { Name: 'running' } },
            { InstanceId: 'i-2', State: { Name: 'stopped' } },
            { InstanceId: 'i-3', State: { Name: 'terminated' } },
          ],
        },
      ],
    });
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [{ VolumeId: 'vol-1' }] });
    rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

    const result = await sweepOtherRegions({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.map((f) => f.region).sort()).toEqual(['eu-central-1', 'us-east-1']);
    const finding = result.findings[0];
    expect(finding?.severity).toBe('MEDIUM');
    // terminated instances don't count
    expect(finding?.description).toContain('2 EC2 instance(s), 1 of them running');
    expect(finding?.description).toContain('1 EBS volume(s)');
    expect(finding?.description).not.toContain('RDS');
  });

  it('counts RDS databases even when EC2 is empty', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves({
      Regions: [{ RegionName: 'eu-west-1' }, { RegionName: 'us-east-1' }],
    });
    ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
    rdsMock.on(DescribeDBInstancesCommand).resolves({
      DBInstances: [{ DBInstanceIdentifier: 'forgotten-db' }],
    });

    const result = await sweepOtherRegions({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.resourceId).toBe('us-east-1');
    expect(result.findings[0]?.description).toContain('1 RDS database(s)');
  });

  it('returns ok: false when listing regions fails', async () => {
    ec2Mock.on(DescribeRegionsCommand).rejects(new Error('UnauthorizedOperation'));

    const result = await sweepOtherRegions({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('UnauthorizedOperation');
  });

  it('returns ok: false when every region probe fails', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(THREE_REGIONS);
    ec2Mock.on(DescribeInstancesCommand).rejects(new Error('RequestExpired'));
    ec2Mock.on(DescribeVolumesCommand).rejects(new Error('RequestExpired'));
    rdsMock.on(DescribeDBInstancesCommand).rejects(new Error('RequestExpired'));

    const result = await sweepOtherRegions({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('RequestExpired');
  });
});
