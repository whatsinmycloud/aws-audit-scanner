# What access does WhatsInMyCloud get?

Short version: **we can look, we can't touch.** The audit role grants exactly
the read-only API calls our scanner makes — listed below, one by one.
There are no write, create, modify, or delete permissions of any kind.

## How access works

1. You deploy [readonly-role.yaml](https://github.com/whatsinmycloud/readonly-role/blob/main/readonly-role.yaml) in your AWS account
   (CloudFormation → Create stack). You can read every line of it first.
2. The role can only be assumed by WhatsInMyCloud's AWS account, and only
   with the unique external ID we give you — nobody else can use it, and we
   can't be tricked into scanning your account for someone else.
3. Optionally, the `ScannerRoleName` parameter locks access down further: only
   our scanner's exact IAM role can assume the audit role, not anything else
   in our account. The name is `WhatsInMyCloudScanner` — use it if you want
   the tightest grant.
   (It's a role *name*, not an ARN, so it can only ever resolve inside the
   WhatsInMyCloud account you specified — a wrong account can't be expressed.)
4. Sessions last at most 1 hour.
5. To revoke access, delete the stack. Access ends immediately.

## The complete permission list

### EC2 — find idle instances, unattached volumes, open firewall ports

| Permission | What it lets us see |
|---|---|
| `ec2:DescribeInstances` | Your EC2 instances (type, state, launch time) |
| `ec2:DescribeVolumes` | Your EBS volumes (size, attachment state) |
| `ec2:DescribeSecurityGroups` | Firewall rules — to flag ports open to the whole internet |
| `ec2:DescribeRegions` | Which regions are enabled, so the scan covers all of them rather than guessing |

### RDS — spot forgotten databases in regions you've stopped using

| Permission | What it lets us see |
|---|---|
| `rds:DescribeDBInstances` | Whether a region has database instances, so an idle region isn't reported as empty |

### S3 — find publicly exposed buckets

| Permission | What it lets us see |
|---|---|
| `s3:ListAllMyBuckets` | Your bucket names |
| `s3:GetBucketPolicyStatus` | Whether a bucket's policy makes it public |
| `s3:GetBucketPublicAccessBlock` | Whether public-access guardrails are enabled |
| `s3:GetBucketPolicy` | The policy document of a public bucket — so we can tell you whether the public can upload, list, or only fetch a known key |

We **cannot** read any object in any bucket. There is no `s3:GetObject` here.
`s3:GetBucketPolicy` returns the permissions document, not your data.

### IAM — find unused users, stale access keys, missing MFA

| Permission | What it lets us see |
|---|---|
| `iam:ListUsers` | Your IAM user names and creation dates |
| `iam:ListAccessKeys` | Access key IDs and their age (never the secrets) |
| `iam:GetAccessKeyLastUsed` | When each key was last used |
| `iam:ListMFADevices` | Whether users have MFA enabled |
| `iam:GetAccountSummary` | Account-level counts (e.g. root MFA status) |
| `iam:GetLoginProfile` | Whether a user has a console password, so a service account isn't flagged for missing console MFA. Returns metadata only, never the password. Scoped to users in your own account. |

| `iam:ListRoleTags` | The version tag on the audit role this stack creates, and no other role — so we can tell you if your integration is out of date |

We **cannot** see passwords, secret keys, or create/modify any user or policy.

### CloudTrail — check audit logging is on

| Permission | What it lets us see |
|---|---|
| `cloudtrail:DescribeTrails` | Your trail configuration |
| `cloudtrail:GetTrailStatus` | Whether logging is actually running |

We **cannot** read the log contents themselves.

## What we can never do

- Create, modify, or delete anything
- Read file contents in S3
- See secrets, passwords, or private keys
- Access your account without the external ID
- Keep access after you delete the stack
