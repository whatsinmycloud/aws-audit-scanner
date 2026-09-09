import { EC2Client, DescribeVolumesCommand, VolumeState } from '@aws-sdk/client-ec2';
import type { Finding, ScanInput, ScanResult } from '../types.js';
import { collectPages } from '../paginate.js';

const EBS_GP2_COST_PER_GB = 0.10;  // $/GB/month
const EBS_GP3_COST_PER_GB = 0.08;
const EBS_IO1_COST_PER_GB = 0.125;

export async function scanUnattachedEbs({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new EC2Client({ region, ...(credentials && { credentials }) });

  try {
    const volumes = await collectPages({
      fetchPage: (NextToken) =>
        client.send(
          new DescribeVolumesCommand({
            Filters: [{ Name: 'status', Values: [VolumeState.available] }],
            ...(NextToken !== undefined && { NextToken }),
          })
        ),
      itemsOf: (page) => page.Volumes,
      tokenOf: (page) => page.NextToken,
    });

    const findings: Finding[] = [];

    for (const volume of volumes) {
      const volumeId = volume.VolumeId ?? 'unknown';
      const sizeGb = volume.Size ?? 0;
      const volumeType = volume.VolumeType ?? 'gp2';
      const name = volume.Tags?.find((t) => t.Key === 'Name')?.Value ?? '(no name)';
      const monthlyCost = estimateMonthlyCost(sizeGb, volumeType);

      findings.push({
        service: 'EBS',
        resourceId: volumeId,
        region,
        severity: 'MEDIUM',
        title: `Unattached EBS volume: ${name} (${volumeId})`,
        description:
          `${sizeGb} GB ${volumeType} volume is not attached to any instance ` +
          `and is costing ~$${monthlyCost.toFixed(2)}/month for nothing. ` +
          `Created: ${volume.CreateTime?.toISOString().split('T')[0] ?? 'unknown'}.`,
        estimatedMonthlySavingsUsd: monthlyCost,
        fixSteps: [
          `Open the EC2 console → Volumes in ${region} and find ${volumeId}.`,
          `Create a snapshot first if you might need the data: Actions → Create Snapshot.`,
          `Then delete it: Actions → Delete Volume.`,
          `CLI: aws ec2 delete-volume --volume-id ${volumeId} --region ${region}`,
        ],
        estimatedFixMinutes: 3,
      });
    }

    return { ok: true, findings };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

function estimateMonthlyCost(sizeGb: number, volumeType: string): number {
  const rateMap: Record<string, number> = {
    gp2: EBS_GP2_COST_PER_GB,
    gp3: EBS_GP3_COST_PER_GB,
    io1: EBS_IO1_COST_PER_GB,
    io2: EBS_IO1_COST_PER_GB,
    st1: 0.045,
    sc1: 0.025,
  };
  const rate = rateMap[volumeType] ?? EBS_GP2_COST_PER_GB;
  return sizeGb * rate;
}
