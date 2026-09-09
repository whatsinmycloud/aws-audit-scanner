import { EC2Client, DescribeInstancesCommand, InstanceStateName } from '@aws-sdk/client-ec2';
import type { Finding, ScanInput, ScanResult } from '../types.js';
import { collectPages } from '../paginate.js';

// Stopped EC2 instances still incur EBS storage costs and clutter your account.
// Most forgotten instances are in stopped state for weeks before anyone notices.
export async function scanStoppedEc2({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new EC2Client({ region, ...(credentials && { credentials }) });

  try {
    const reservations = await collectPages({
      fetchPage: (NextToken) =>
        client.send(
          new DescribeInstancesCommand({
            Filters: [{ Name: 'instance-state-name', Values: [InstanceStateName.stopped] }],
            ...(NextToken !== undefined && { NextToken }),
          })
        ),
      itemsOf: (page) => page.Reservations,
      tokenOf: (page) => page.NextToken,
    });

    const findings: Finding[] = [];

    for (const reservation of reservations) {
      for (const instance of reservation.Instances ?? []) {
        const instanceId = instance.InstanceId ?? 'unknown';
        const instanceType = instance.InstanceType ?? 'unknown';
        const name = instance.Tags?.find((t) => t.Key === 'Name')?.Value ?? '(no name)';
        const stoppedAt = instance.StateTransitionReason ?? 'unknown';

        findings.push({
          service: 'EC2',
          resourceId: instanceId,
          region,
          severity: 'MEDIUM',
          title: `Stopped EC2 instance: ${name} (${instanceId})`,
          description:
            `Instance ${instanceId} (${instanceType}) has been stopped. ` +
            `Stopped instances still incur costs for attached EBS volumes. ` +
            `Last state change: ${stoppedAt}.`,
          estimatedMonthlySavingsUsd: estimateEbsCostUsd(instanceType),
          fixSteps: [
            `Open the EC2 console in ${region} and find instance ${instanceId}.`,
            `If you no longer need it: Actions → Instance State → Terminate.`,
            `If you might need it again: create an AMI snapshot first, then terminate.`,
            `CLI: aws ec2 terminate-instances --instance-ids ${instanceId} --region ${region}`,
          ],
          estimatedFixMinutes: 5,
        });
      }
    }

    return { ok: true, findings };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

// Rough EBS cost estimate based on instance type family (most stopped instances have gp2/gp3 root volumes)
function estimateEbsCostUsd(instanceType: string): number {
  if (instanceType.startsWith('t2') || instanceType.startsWith('t3')) return 2;
  if (instanceType.startsWith('m5') || instanceType.startsWith('m6')) return 4;
  if (instanceType.startsWith('c5') || instanceType.startsWith('c6')) return 4;
  if (instanceType.startsWith('r5') || instanceType.startsWith('r6')) return 6;
  return 3;
}
