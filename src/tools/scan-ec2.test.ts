import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { scanStoppedEc2 } from './scan-ec2.js';

const ec2Mock = mockClient(EC2Client);

describe('scanStoppedEc2', () => {
  beforeEach(() => {
    ec2Mock.reset();
  });

  it('returns no findings when there are no stopped instances', async () => {
    ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });

    const result = await scanStoppedEc2({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags a stopped instance as MEDIUM with an EBS cost estimate', async () => {
    ec2Mock.on(DescribeInstancesCommand).resolves({
      Reservations: [
        {
          Instances: [
            {
              InstanceId: 'i-0abc123',
              InstanceType: 't3.micro',
              Tags: [{ Key: 'Name', Value: 'old-dev-server' }],
              StateTransitionReason: 'User initiated (2026-05-01 10:00:00 GMT)',
            },
          ],
        },
      ],
    });

    const result = await scanStoppedEc2({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding).toMatchObject({
      service: 'EC2',
      resourceId: 'i-0abc123',
      region: 'eu-west-1',
      severity: 'MEDIUM',
      estimatedMonthlySavingsUsd: 2,
    });
    expect(finding?.title).toContain('old-dev-server');
    expect(finding?.fixSteps.join('\n')).toContain('i-0abc123');
  });

  it('filters the API call to stopped instances only', async () => {
    ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });

    await scanStoppedEc2({ region: 'eu-west-1' });

    const call = ec2Mock.commandCalls(DescribeInstancesCommand)[0];
    expect(call?.args[0].input.Filters).toEqual([
      { Name: 'instance-state-name', Values: ['stopped'] },
    ]);
  });

  it('returns ok: false when the API call fails', async () => {
    ec2Mock.on(DescribeInstancesCommand).rejects(new Error('AccessDenied'));

    const result = await scanStoppedEc2({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('AccessDenied');
  });
});
