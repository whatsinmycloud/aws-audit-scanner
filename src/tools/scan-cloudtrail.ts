import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from '@aws-sdk/client-cloudtrail';
import type { Finding, ScanInput, ScanResult } from '../types.js';

export async function scanCloudTrail({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new CloudTrailClient({ region, ...(credentials && { credentials }) });

  try {
    const { trailList: trails = [] } = await client.send(
      new DescribeTrailsCommand({ includeShadowTrails: false })
    );

    // No trails at all — nothing is being logged
    if (trails.length === 0) {
      return {
        ok: true,
        findings: [
          {
            service: 'CloudTrail',
            resourceId: region,
            region,
            severity: 'HIGH',
            title: `CloudTrail is not configured in ${region}`,
            description:
              `No CloudTrail trails exist in ${region}. ` +
              `Without CloudTrail, you have no record of who did what in your AWS account — ` +
              `no audit trail for security incidents, no way to investigate unexpected changes.`,
            fixSteps: [
              `Open CloudTrail in the AWS console → Create trail.`,
              `Enable for all regions, store logs in a new S3 bucket.`,
              `Enable log file validation so you can detect if logs are tampered with.`,
              `CLI: aws cloudtrail create-trail --name main-trail --s3-bucket-name your-cloudtrail-bucket --is-multi-region-trail --region ${region}`,
            ],
            estimatedFixMinutes: 10,
          },
        ],
      };
    }

    const findings: Finding[] = [];

    for (const trail of trails) {
      const trailName = trail.Name ?? 'unknown';
      const trailArn = trail.TrailARN ?? trailName;

      // Check if logging is actually active
      const status = await client.send(new GetTrailStatusCommand({ Name: trailArn }));

      if (!status.IsLogging) {
        findings.push({
          service: 'CloudTrail',
          resourceId: trailArn,
          region,
          severity: 'HIGH',
          title: `CloudTrail logging is paused: ${trailName}`,
          description:
            `Trail "${trailName}" exists but logging is currently stopped. ` +
            `API calls made while logging is paused leave no audit record.`,
          fixSteps: [
            `Open CloudTrail → Trails → ${trailName} → click "Start logging".`,
            `CLI: aws cloudtrail start-logging --name ${trailArn} --region ${region}`,
          ],
          estimatedFixMinutes: 2,
        });
      }

      // Warn if trail doesn't cover all regions
      if (!trail.IsMultiRegionTrail) {
        findings.push({
          service: 'CloudTrail',
          resourceId: trailArn,
          region,
          severity: 'MEDIUM',
          title: `CloudTrail only covers one region: ${trailName}`,
          description:
            `Trail "${trailName}" only logs activity in ${region}. ` +
            `Activity in other regions (including global services like IAM) may not be captured.`,
          fixSteps: [
            `Open CloudTrail → Trails → ${trailName} → Edit → enable "Apply trail to all regions".`,
            `CLI: aws cloudtrail update-trail --name ${trailArn} --is-multi-region-trail --region ${region}`,
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
