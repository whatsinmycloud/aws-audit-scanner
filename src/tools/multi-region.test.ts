import { describe, it, expect } from 'vitest';
import { acrossRegions } from './multi-region.js';
import type { Finding, ScanInput, ScanResult } from '../types.js';

function finding(region: string): Finding {
  return {
    service: 'EC2',
    resourceId: `i-${region}`,
    region,
    severity: 'MEDIUM',
    title: `finding in ${region}`,
    description: 'test',
    fixSteps: [],
    estimatedFixMinutes: 1,
  };
}

describe('acrossRegions', () => {
  it('merges findings from every region', async () => {
    const scan = async ({ region }: ScanInput): Promise<ScanResult> => ({
      ok: true,
      findings: [finding(region)],
    });

    const result = await acrossRegions(['eu-west-1', 'us-east-1'], undefined, scan);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.map((f) => f.region)).toEqual(['eu-west-1', 'us-east-1']);
  });

  it('tolerates one failing region and keeps the rest', async () => {
    const scan = async ({ region }: ScanInput): Promise<ScanResult> =>
      region === 'us-east-1'
        ? { ok: false, error: 'throttled' }
        : { ok: true, findings: [finding(region)] };

    const result = await acrossRegions(['eu-west-1', 'us-east-1'], undefined, scan);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.map((f) => f.region)).toEqual(['eu-west-1']);
  });

  it('fails when every region fails', async () => {
    const scan = async (): Promise<ScanResult> => ({ ok: false, error: 'AccessDenied' });

    const result = await acrossRegions(['eu-west-1', 'us-east-1'], undefined, scan);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('AccessDenied');
  });
});
