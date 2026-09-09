import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  S3Client,
  ListBucketsCommand,
  GetBucketPolicyCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { scanS3PublicAccess } from './scan-s3.js';

const s3Mock = mockClient(S3Client);

function awsError(name: string): Error {
  return Object.assign(new Error(name), { name });
}

const FULL_BLOCK = {
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: true,
    IgnorePublicAcls: true,
    BlockPublicPolicy: true,
    RestrictPublicBuckets: true,
  },
};

describe('scanS3PublicAccess', () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it('returns no findings for a private bucket with all guardrails enabled', async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'safe-bucket' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).rejects(awsError('NoSuchBucketPolicy'));
    s3Mock.on(GetPublicAccessBlockCommand).resolves(FULL_BLOCK);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('flags a confirmed-public bucket as HIGH, without stacking a guardrail finding', async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'exposed-bucket' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).resolves({ PolicyStatus: { IsPublic: true } });
    s3Mock.on(GetPublicAccessBlockCommand).rejects(
      awsError('NoSuchPublicAccessBlockConfiguration')
    );

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      service: 'S3',
      resourceId: 'exposed-bucket',
      severity: 'HIGH',
    });
  });

  it('flags missing guardrails as MEDIUM when the bucket is not confirmed public', async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'unguarded-bucket' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).rejects(awsError('NoSuchBucketPolicy'));
    s3Mock.on(GetPublicAccessBlockCommand).rejects(
      awsError('NoSuchPublicAccessBlockConfiguration')
    );

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      resourceId: 'unguarded-bucket',
      severity: 'MEDIUM',
    });
  });

  it('flags partial Block Public Access settings as MEDIUM', async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'half-guarded' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).resolves({ PolicyStatus: { IsPublic: false } });
    s3Mock.on(GetPublicAccessBlockCommand).resolves({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: false,
        RestrictPublicBuckets: false,
      },
    });

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('MEDIUM');
  });

  it('does not false-positive when the policy status check is denied', async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'opaque-bucket' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).rejects(awsError('AccessDenied'));
    s3Mock.on(GetPublicAccessBlockCommand).resolves(FULL_BLOCK);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result).toEqual({ ok: true, findings: [] });
  });

  it('scans every bucket, not just the first', async () => {
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: 'safe-bucket' }, { Name: 'exposed-bucket' }],
    });
    s3Mock
      .on(GetBucketPolicyStatusCommand, { Bucket: 'safe-bucket' })
      .rejects(awsError('NoSuchBucketPolicy'));
    s3Mock
      .on(GetBucketPolicyStatusCommand, { Bucket: 'exposed-bucket' })
      .resolves({ PolicyStatus: { IsPublic: true } });
    s3Mock.on(GetPublicAccessBlockCommand).resolves(FULL_BLOCK);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.resourceId).toBe('exposed-bucket');
  });

  it('returns ok: false when listing buckets fails', async () => {
    s3Mock.on(ListBucketsCommand).rejects(new Error('ExpiredToken'));

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('ExpiredToken');
  });
});

describe('scanS3PublicAccess — what the public can actually do', () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  function publicBucketWithPolicy(policy: string | undefined, denied = false) {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'exposed' }] });
    s3Mock.on(GetBucketPolicyStatusCommand).resolves({ PolicyStatus: { IsPublic: true } });
    if (denied) {
      s3Mock.on(GetBucketPolicyCommand).rejects(awsError('AccessDenied'));
    } else {
      s3Mock.on(GetBucketPolicyCommand).resolves(policy ? { Policy: policy } : {});
    }
  }

  const writablePolicy = JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: '*', Action: ['s3:GetObject', 's3:PutObject'], Resource: '*' }],
  });
  const readOnlyPolicy = JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }],
  });

  it('calls out anonymous upload rather than describing it as merely readable', async () => {
    publicBucketWithPolicy(writablePolicy);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const [finding] = result.findings;
    expect(finding!.title).toMatch(/upload/i);
    expect(finding!.description).toMatch(/overwrite or delete/i);
  });

  it('reassures that a read-only public bucket cannot be enumerated', async () => {
    publicBucketWithPolicy(readOnlyPolicy);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    if (!result.ok) throw new Error('expected ok');
    const [finding] = result.findings;
    expect(finding!.title).toMatch(/publicly readable/i);
    expect(finding!.description).toMatch(/Listing is not permitted/i);
  });

  // A role created before s3:GetBucketPolicy existed must still get a report.
  it('degrades to the generic public warning when the policy cannot be read', async () => {
    publicBucketWithPolicy(undefined, true);

    const result = await scanS3PublicAccess({ region: 'eu-west-1' });

    if (!result.ok) throw new Error('expected ok');
    expect(result.findings).toHaveLength(1);
    const [finding] = result.findings;
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.description).toMatch(/grants public read access/i);
    // No claim either way about listing, since we genuinely don't know.
    expect(finding!.description).not.toMatch(/Listing is not permitted/i);
  });
});
