import {
  EC2Client,
  DescribeRegionsCommand,
  DescribeInstancesCommand,
  DescribeVolumesCommand,
} from '@aws-sdk/client-ec2';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import type { AwsCredentials, Finding, ScanInput, ScanResult } from '../types.js';

export type RegionPresence = {
  region: string;
  instanceCount: number;
  runningCount: number;
  volumeCount: number;
  dbInstanceCount: number;
};

// Presence probe across every enabled region the scan didn't cover. Forgotten
// resources in a forgotten region are exactly what this audit exists to catch;
// the full scan stays single-region, so this reports counts, not findings-level
// detail, and the agent turns any hits into a "scan that region too" finding.
export async function sweepOtherRegions({ region: scannedRegion, credentials }: ScanInput): Promise<ScanResult> {
  const ec2 = new EC2Client({ region: scannedRegion, ...(credentials && { credentials }) });

  try {
    const { Regions } = await ec2.send(new DescribeRegionsCommand({}));
    const otherRegions = (Regions ?? [])
      .map((r) => r.RegionName)
      .filter((name): name is string => Boolean(name) && name !== scannedRegion);

    const probes = await Promise.allSettled(otherRegions.map((r) => probeRegion(r, credentials)));

    // One region's API misbehaving shouldn't sink the sweep — skip it and
    // report the rest. Only fail when every probe failed (credentials/network).
    const succeeded = probes.filter((p): p is PromiseFulfilledResult<RegionPresence> => p.status === 'fulfilled');
    if (otherRegions.length > 0 && succeeded.length === 0) {
      const firstFailure = probes[0] as PromiseRejectedResult;
      return { ok: false, error: String(firstFailure.reason) };
    }

    const findings = succeeded
      .map((p) => p.value)
      .filter(hasResources)
      .map((presence) => toFinding(presence, scannedRegion));

    return { ok: true, findings };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

export async function probeRegion(region: string, credentials?: AwsCredentials): Promise<RegionPresence> {
  const clientConfig = { region, ...(credentials && { credentials }) };
  const ec2 = new EC2Client(clientConfig);
  const rds = new RDSClient(clientConfig);

  // First page of each is enough for a presence probe — this asks "is there
  // anything here?", not "what exactly is here?".
  const [instancesRes, volumesRes, dbRes] = await Promise.all([
    ec2.send(new DescribeInstancesCommand({})),
    ec2.send(new DescribeVolumesCommand({})),
    rds.send(new DescribeDBInstancesCommand({})),
  ]);

  const instances = (instancesRes.Reservations ?? [])
    .flatMap((r) => r.Instances ?? [])
    .filter((i) => i.State?.Name !== 'terminated');

  return {
    region,
    instanceCount: instances.length,
    runningCount: instances.filter((i) => i.State?.Name === 'running').length,
    volumeCount: volumesRes.Volumes?.length ?? 0,
    dbInstanceCount: dbRes.DBInstances?.length ?? 0,
  };
}

export function hasResources(p: RegionPresence): boolean {
  return p.instanceCount > 0 || p.volumeCount > 0 || p.dbInstanceCount > 0;
}

export function resourceCount(p: RegionPresence): number {
  return p.instanceCount + p.volumeCount + p.dbInstanceCount;
}

function toFinding(p: RegionPresence, scannedRegion: string): Finding {
  const counts: string[] = [];
  if (p.instanceCount > 0) counts.push(`${p.instanceCount} EC2 instance(s), ${p.runningCount} of them running`);
  if (p.volumeCount > 0) counts.push(`${p.volumeCount} EBS volume(s)`);
  if (p.dbInstanceCount > 0) counts.push(`${p.dbInstanceCount} RDS database(s)`);

  return {
    service: 'Region sweep',
    resourceId: p.region,
    region: p.region,
    severity: 'MEDIUM',
    title: `Resources found in ${p.region} — a region this scan didn't cover`,
    description:
      `While auditing ${scannedRegion}, we found ${counts.join(', ')} in ${p.region}. ` +
      `Resources in regions you don't normally look at are a common source of forgotten ` +
      `spend and unreviewed security exposure — this scan did not audit them in detail.`,
    fixSteps: [
      `Switch your AWS console to ${p.region} and check EC2 → Instances/Volumes and RDS → Databases.`,
      `If it's forgotten, clean it up; if it's deliberate, all good — just confirm you know what it is.`,
      `Run another scan at https://whatsinmycloud.com/scan with ${p.region} as the region for the full audit.`,
      `CLI: aws ec2 describe-instances --region ${p.region}`,
    ],
    estimatedFixMinutes: 10,
  };
}
