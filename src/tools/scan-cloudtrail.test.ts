import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} from '@aws-sdk/client-cloudtrail';
import { scanCloudTrail } from './scan-cloudtrail.js';

const cloudTrailMock = mockClient(CloudTrailClient);

const HEALTHY_TRAIL = {
  Name: 'main-trail',
  TrailARN: 'arn:aws:cloudtrail:eu-west-1:123456789012:trail/main-trail',
  IsMultiRegionTrail: true,
};

describe('scanCloudTrail', () => {
  beforeEach(() => {
    cloudTrailMock.reset();
  });

  it('returns no findings for a multi-region trail that is logging', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).resolves({ trailList: [HEALTHY_TRAIL] });
    cloudTrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: true });

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags a region with no trails at all as HIGH', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).resolves({ trailList: [] });

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      service: 'CloudTrail',
      severity: 'HIGH',
      resourceId: 'eu-west-1',
    });
  });

  it('flags a trail with paused logging as HIGH', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).resolves({ trailList: [HEALTHY_TRAIL] });
    cloudTrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: false });

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('HIGH');
    expect(result.findings[0]?.title).toContain('paused');
  });

  it('flags a single-region trail as MEDIUM', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).resolves({
      trailList: [{ ...HEALTHY_TRAIL, IsMultiRegionTrail: false }],
    });
    cloudTrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: true });

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('MEDIUM');
    expect(result.findings[0]?.title).toContain('one region');
  });

  it('reports paused logging and single-region together', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).resolves({
      trailList: [{ ...HEALTHY_TRAIL, IsMultiRegionTrail: false }],
    });
    cloudTrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: false });

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.map((f) => f.severity).sort()).toEqual(['HIGH', 'MEDIUM']);
  });

  it('returns ok: false when the API call fails', async () => {
    cloudTrailMock.on(DescribeTrailsCommand).rejects(new Error('AccessDeniedException'));

    const result = await scanCloudTrail({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('AccessDeniedException');
  });
});
