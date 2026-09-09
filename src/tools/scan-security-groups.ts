import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import type { Finding, ScanInput, ScanResult } from '../types.js';
import { collectPages } from '../paginate.js';

// Ports that should never be open to the entire internet.
const SENSITIVE_PORTS: Record<number, string> = {
  22: 'SSH',
  3389: 'RDP (Windows Remote Desktop)',
  5432: 'PostgreSQL',
  3306: 'MySQL',
  27017: 'MongoDB',
  6379: 'Redis',
  9200: 'Elasticsearch',
  5601: 'Kibana',
};

const OPEN_TO_WORLD = ['0.0.0.0/0', '::/0'];

export async function scanSecurityGroups({ region, credentials }: ScanInput): Promise<ScanResult> {
  const client = new EC2Client({ region, ...(credentials && { credentials }) });

  try {
    const securityGroups = await collectPages({
      fetchPage: (NextToken) =>
        client.send(
          new DescribeSecurityGroupsCommand({ ...(NextToken !== undefined && { NextToken }) })
        ),
      itemsOf: (page) => page.SecurityGroups,
      tokenOf: (page) => page.NextToken,
    });
    const findings: Finding[] = [];

    for (const sg of securityGroups) {
      const sgId = sg.GroupId ?? 'unknown';
      const sgName = sg.GroupName ?? '(no name)';
      const vpcId = sg.VpcId ?? 'no VPC';

      for (const rule of sg.IpPermissions ?? []) {
        const fromPort = rule.FromPort;
        const toPort = rule.ToPort;
        const protocol = rule.IpProtocol;

        // -1 means all traffic — always serious
        const isAllTraffic = protocol === '-1';

        const openCidrs = [
          ...(rule.IpRanges ?? []).map((r) => r.CidrIp).filter((c): c is string => OPEN_TO_WORLD.includes(c ?? '')),
          ...(rule.Ipv6Ranges ?? []).map((r) => r.CidrIpv6).filter((c): c is string => OPEN_TO_WORLD.includes(c ?? '')),
        ];

        if (openCidrs.length === 0) continue;

        if (isAllTraffic) {
          findings.push({
            service: 'EC2 Security Group',
            resourceId: sgId,
            region,
            severity: 'HIGH',
            title: `Security group allows ALL traffic from the internet: ${sgName} (${sgId})`,
            description:
              `Security group "${sgName}" (${sgId}) in ${vpcId} has an inbound rule allowing ` +
              `ALL ports and protocols from ${openCidrs.join(', ')}. ` +
              `This exposes every service on attached resources to the entire internet.`,
            fixSteps: [
              `Open the EC2 console → Security Groups → find ${sgId}.`,
              `Check what's attached to this group first — verify nothing depends on this rule before removing it.`,
              `Edit inbound rules and remove any rule with source 0.0.0.0/0 or ::/0 that allows all traffic.`,
              `Replace with your specific IP range, or use a VPN/bastion host pattern.`,
            ],
            estimatedFixMinutes: 10,
          });
          continue;
        }

        // Check if any sensitive port falls within the rule's port range
        for (const [port, serviceName] of Object.entries(SENSITIVE_PORTS)) {
          const portNum = Number(port);
          const inRange =
            fromPort !== undefined &&
            toPort !== undefined &&
            portNum >= fromPort &&
            portNum <= toPort;

          if (!inRange) continue;

          findings.push({
            service: 'EC2 Security Group',
            resourceId: sgId,
            region,
            severity: 'HIGH',
            title: `${serviceName} (port ${port}) open to the internet: ${sgName} (${sgId})`,
            description:
              `Security group "${sgName}" (${sgId}) allows inbound ${serviceName} traffic ` +
              `on port ${port} from ${openCidrs.join(', ')}. ` +
              `Anyone on the internet can attempt to connect to this port on any attached resource.`,
            fixSteps: [
              `Open the EC2 console → Security Groups → find ${sgId}.`,
              `Edit inbound rules and change the source from 0.0.0.0/0 to your specific IP or CIDR range.`,
              `If remote access is needed, consider a VPN or bastion host instead of direct internet exposure.`,
              `Verify nothing depends on this rule before revoking it — check what's attached to this group.`,
              `CLI: aws ec2 revoke-security-group-ingress --group-id ${sgId} --protocol tcp --port ${port} --cidr 0.0.0.0/0 --region ${region}`,
            ],
            estimatedFixMinutes: 5,
          });
        }
      }
    }

    return { ok: true, findings };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}
