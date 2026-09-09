import {
  S3Client,
  ListBucketsCommand,
  GetBucketPolicyCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { analysePublicPolicy, type PublicBucketAccess } from './s3-policy.js';
import type { Finding, ScanInput, ScanResult } from '../types.js';

// ListBuckets returns every bucket in the account regardless of where it lives,
// so the region we happen to be scanning from says nothing about where a bucket
// is. Reporting the scan region would be a guess that is wrong for any bucket
// outside it — and a wrong region sends someone to a console page where their
// bucket appears to be missing. Bucket names are globally unique, so the name
// alone is enough to act on. (Getting the true region would need
// s3:GetBucketLocation — another permission, for modest benefit.)
const GLOBAL = 'global';

export async function scanS3PublicAccess({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new S3Client({ region, ...(credentials && { credentials }) });

  try {
    const { Buckets: buckets = [] } = await client.send(new ListBucketsCommand({}));

    const perBucket = await Promise.all(
      buckets.map(async (bucket) => {
        const name = bucket.Name;
        if (!name) return [];
        return checkBucket(client, name, GLOBAL);
      })
    );

    return { ok: true, findings: perBucket.flat() };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

async function checkBucket(client: S3Client, name: string, region: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // HIGH: bucket policy actively grants public access (confirmed by AWS)
  const activelyPublic = await isPolicyPublic(client, name);
  if (activelyPublic) {
    // What the public can actually DO changes both the severity and the fix.
    // Undefined = we couldn't read the policy (older role without
    // s3:GetBucketPolicy), so fall back to the generic public-access wording.
    const access = await publicAccessDetail(client, name);
    findings.push(publicBucketFinding(name, region, access));

    // No point adding a guardrail finding on top of a confirmed-public finding
    return findings;
  }

  // MEDIUM: guardrails are missing, but no active public policy detected
  const fullyBlocked = await hasFullPublicAccessBlock(client, name);
  if (!fullyBlocked) {
    findings.push({
      service: 'S3',
      resourceId: name,
      region,
      severity: 'MEDIUM',
      title: `S3 bucket missing public access guardrails: ${name}`,
      description:
        `Bucket "${name}" does not have all four Block Public Access settings enabled. ` +
        `It is not currently public, but the safety net is missing — ` +
        `a misconfigured policy or ACL could accidentally expose it in future.`,
      fixSteps: [
        `Open the S3 console → bucket "${name}" → Permissions → Block public access → Edit.`,
        `Enable all four checkboxes and save.`,
        `CLI: aws s3api put-public-access-block --bucket ${name} ` +
          `--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,` +
          `BlockPublicPolicy=true,RestrictPublicBuckets=true`,
        `⚠️  Skip this if the bucket intentionally serves public content (e.g. a static website).`,
      ],
      estimatedFixMinutes: 2,
    });
  }

  return findings;
}

// Anonymous write is a different category of problem from anonymous read: a
// stranger can host content on the customer's infrastructure, overwrite objects
// their app serves back to users, and run up their storage bill.
function publicBucketFinding(
  name: string,
  region: string,
  access: PublicBucketAccess | undefined
): Finding {
  const blockCli =
    `aws s3api put-public-access-block --bucket ${name} ` +
    `--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,` +
    `BlockPublicPolicy=true,RestrictPublicBuckets=true`;

  if (access?.write) {
    return {
      service: 'S3',
      resourceId: name,
      region,
      severity: 'HIGH',
      title: `Anyone on the internet can upload to S3 bucket: ${name}`,
      description:
        `Bucket "${name}" has a policy granting write access to everyone. ` +
        `Any stranger can upload files, and overwrite or delete what is already there. ` +
        `That means hosting arbitrary content on your infrastructure, tampering with ` +
        `files your application serves back to users, and storage costs you did not incur. ` +
        `This is more serious than a bucket that is merely readable.`,
      fixSteps: [
        `Open the S3 console → bucket "${name}" → Permissions → Bucket Policy.`,
        `Remove s3:PutObject (and any other write action) from any statement whose Principal is "*".`,
        `If your application genuinely uploads to this bucket from a browser, do not leave it open — ` +
          `switch to presigned URLs, which grant one short-lived upload at a time.`,
        `Keep s3:GetObject only if the files are meant to be public.`,
        `Then review whether the bucket should be public at all: ${blockCli}`,
      ],
      estimatedFixMinutes: 15,
    };
  }

  // Read-only public access is often deliberate (static assets, downloads), so
  // say precisely what is exposed instead of implying the whole bucket leaked.
  const listNote = access
    ? access.list
      ? ` Anyone can also list every key in the bucket, so the contents can be enumerated and downloaded wholesale.`
      : ` Listing is not permitted, so objects can only be fetched by anyone who already knows the exact key.`
    : // Say we don't know, rather than leaving a gap: given only "anyone can
      // read it", the report writer fills in the worst case and claims the whole
      // bucket can be downloaded, which may well be untrue.
      ` We could not read the bucket policy to determine whether the contents can also be listed ` +
      `(the audit role predates that permission — redeploying it enables this check). ` +
      `Do not assume the whole bucket can be enumerated.`;

  return {
    service: 'S3',
    resourceId: name,
    region,
    severity: 'HIGH',
    title: access?.list
      ? `S3 bucket is public and its contents can be listed: ${name}`
      : `S3 bucket is publicly readable: ${name}`,
    description:
      `Bucket "${name}" has a bucket policy that grants public read access. ` +
      `Anyone on the internet can read its contents.${listNote} ` +
      `If this bucket is intentionally public (static assets, downloads), that may be fine — ` +
      `confirm nothing private has been placed in it.`,
    fixSteps: [
      `Open the S3 console → bucket "${name}" → Permissions tab.`,
      `Review the Bucket Policy and remove any statements that grant access to "*" (everyone).`,
      ...(access?.list
        ? [`At minimum remove s3:ListBucket, so the bucket cannot be enumerated even if files stay public.`]
        : []),
      `If the bucket must stay public, keep only s3:GetObject and enable the two ACL guardrails ` +
        `(BlockPublicAcls, IgnorePublicAcls) — these do not affect your policy-based public read.`,
      `To make it fully private instead: ${blockCli}`,
    ],
    estimatedFixMinutes: 10,
  };
}

// Reads the policy document to see what the public is actually granted.
// Requires s3:GetBucketPolicy; undefined means we could not read it (a role
// deployed before that permission existed), and callers degrade gracefully
// rather than failing the scan.
async function publicAccessDetail(
  client: S3Client,
  name: string
): Promise<PublicBucketAccess | undefined> {
  try {
    const response = await client.send(new GetBucketPolicyCommand({ Bucket: name }));
    return response.Policy ? analysePublicPolicy(response.Policy) : undefined;
  } catch {
    return undefined;
  }
}

// Returns true only if AWS confirms the bucket policy grants public access.
async function isPolicyPublic(client: S3Client, name: string): Promise<boolean> {
  try {
    const response = await client.send(new GetBucketPolicyStatusCommand({ Bucket: name }));
    return response.PolicyStatus?.IsPublic ?? false;
  } catch (err: unknown) {
    // NoSuchBucketPolicy = no policy at all = not public via policy
    if (isAwsError(err, 'NoSuchBucketPolicy')) return false;
    // Any other error (permissions etc.) — assume not public, don't false-positive
    return false;
  }
}

// Returns true only if all four Block Public Access settings are enabled.
async function hasFullPublicAccessBlock(client: S3Client, name: string): Promise<boolean> {
  try {
    const response = await client.send(new GetPublicAccessBlockCommand({ Bucket: name }));
    const c = response.PublicAccessBlockConfiguration;
    return !!(c?.BlockPublicAcls && c.IgnorePublicAcls && c.BlockPublicPolicy && c.RestrictPublicBuckets);
  } catch (err: unknown) {
    // NoSuchPublicAccessBlockConfiguration = no block configured at all
    if (isAwsError(err, 'NoSuchPublicAccessBlockConfiguration')) return false;
    return false;
  }
}

function isAwsError(err: unknown, code: string): boolean {
  return err instanceof Error && (err as Error & { Code?: string; name?: string }).name === code;
}
