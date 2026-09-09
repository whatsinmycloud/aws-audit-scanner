import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  EC2Client,
  DescribeRegionsCommand,
  DescribeInstancesCommand,
  DescribeVolumesCommand,
} from '@aws-sdk/client-ec2';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { discoverActiveRegions, MAX_DEEP_SCAN_REGIONS } from './discover.js';

const ec2Mock = mockClient(EC2Client);
const rdsMock = mockClient(RDSClient);

function regions(...names: string[]) {
  return { Regions: names.map((n) => ({ RegionName: n })) };
}

function emptyProbes() {
  ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });
  ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
  rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
}

describe('discoverActiveRegions', () => {
  beforeEach(() => {
    ec2Mock.reset();
    rdsMock.reset();
  });

  it('falls back to the seed region when the whole account is empty', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(regions('eu-west-1', 'us-east-1', 'eu-central-1'));
    emptyProbes();

    const result = await discoverActiveRegions({ seedRegion: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.discovery.deepScanRegions).toEqual(['eu-west-1']);
    // The seed is being deep-scanned, so it isn't listed as empty too.
    expect(result.discovery.emptyRegions.sort()).toEqual(['eu-central-1', 'us-east-1']);
    expect(result.discovery.activeButSkipped).toEqual([]);
    expect(result.discovery.regionsChecked).toBe(3);
  });

  it('deep-scans every region with resources (mock answers for all regions alike)', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(regions('eu-west-1', 'us-east-1'));
    ec2Mock.on(DescribeInstancesCommand).resolves({
      Reservations: [{ Instances: [{ InstanceId: 'i-1', State: { Name: 'running' } }] }],
    });
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
    rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

    const result = await discoverActiveRegions({ seedRegion: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.discovery.deepScanRegions.sort()).toEqual(['eu-west-1', 'us-east-1']);
    expect(result.discovery.emptyRegions).toEqual([]);
  });

  it('caps deep-scan regions and reports the overflow', async () => {
    const many = Array.from({ length: MAX_DEEP_SCAN_REGIONS + 2 }, (_, i) => `region-${i}-1`);
    ec2Mock.on(DescribeRegionsCommand).resolves(regions(...many));
    ec2Mock.on(DescribeInstancesCommand).resolves({
      Reservations: [{ Instances: [{ InstanceId: 'i-1', State: { Name: 'running' } }] }],
    });
    ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
    rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

    const result = await discoverActiveRegions({ seedRegion: 'region-0-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.discovery.deepScanRegions).toHaveLength(MAX_DEEP_SCAN_REGIONS);
    expect(result.discovery.activeButSkipped).toHaveLength(2);
  });

  it('fails when regions cannot be listed (role predates discovery permissions)', async () => {
    ec2Mock.on(DescribeRegionsCommand).rejects(new Error('UnauthorizedOperation'));

    const result = await discoverActiveRegions({ seedRegion: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('UnauthorizedOperation');
  });

  it('fails when every probe fails', async () => {
    ec2Mock.on(DescribeRegionsCommand).resolves(regions('eu-west-1', 'us-east-1'));
    ec2Mock.on(DescribeInstancesCommand).rejects(new Error('RequestExpired'));
    ec2Mock.on(DescribeVolumesCommand).rejects(new Error('RequestExpired'));
    rdsMock.on(DescribeDBInstancesCommand).rejects(new Error('RequestExpired'));

    const result = await discoverActiveRegions({ seedRegion: 'eu-west-1' });

    expect(result.ok).toBe(false);
  });
});
