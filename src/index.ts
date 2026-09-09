import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { scanStoppedEc2 } from './tools/scan-ec2.js';
import { scanUnattachedEbs } from './tools/scan-ebs.js';
import { scanS3PublicAccess } from './tools/scan-s3.js';
import { scanSecurityGroups } from './tools/scan-security-groups.js';
import { scanIam } from './tools/scan-iam.js';
import { scanCloudTrail } from './tools/scan-cloudtrail.js';
import { sweepOtherRegions } from './tools/region-sweep.js';
import type { ScanResult } from './types.js';

const server = new McpServer({
  name: 'aws-audit-scanner',
  version: '0.1.0',
});

const regionParam = { region: z.string().describe('AWS region to scan, e.g. eu-west-1') };

server.tool('scan_stopped_ec2', 'Find stopped EC2 instances still incurring EBS costs.', regionParam,
  async ({ region }) => toContent(await scanStoppedEc2({ region })));

server.tool('scan_unattached_ebs', 'Find EBS volumes not attached to any instance.', regionParam,
  async ({ region }) => toContent(await scanUnattachedEbs({ region })));

server.tool('scan_s3_public_access', 'Find S3 buckets that are publicly accessible or missing guardrails.', regionParam,
  async ({ region }) => toContent(await scanS3PublicAccess({ region })));

server.tool('scan_security_groups', 'Find security groups with dangerous ports open to the internet.', regionParam,
  async ({ region }) => toContent(await scanSecurityGroups({ region })));

server.tool('scan_iam', 'Find IAM issues: root access keys, missing MFA, stale access keys.', regionParam,
  async ({ region }) => toContent(await scanIam({ region })));

server.tool('scan_cloudtrail', 'Check if CloudTrail logging is enabled and covering all regions.', regionParam,
  async ({ region }) => toContent(await scanCloudTrail({ region })));

server.tool('sweep_other_regions', 'Presence-check every other enabled region for forgotten EC2/EBS/RDS resources.', regionParam,
  async ({ region }) => toContent(await sweepOtherRegions({ region })));

function toContent(result: ScanResult) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
  };
}

const transport = new StdioServerTransport();
await server.connect(transport);
