import type { AwsCredentials, ScanInput, ScanResult } from '../types.js';

// Fan a single-region scan tool out across the deep-scan regions and merge
// the findings (each finding already carries its region). Runs in parallel —
// the wall-time cost of multi-region is one region's worth of API latency.
export async function acrossRegions(
  regions: string[],
  credentials: AwsCredentials | undefined,
  scan: (input: ScanInput) => Promise<ScanResult>
): Promise<ScanResult> {
  const results = await Promise.all(regions.map((region) => scan({ region, credentials })));

  const succeeded = results.filter((r): r is Extract<ScanResult, { ok: true }> => r.ok);

  // Tolerate a single region's API hiccup (its findings are simply missing),
  // but surface a total failure — that's credentials or connectivity.
  if (regions.length > 0 && succeeded.length === 0) {
    const firstFailure = results.find((r) => !r.ok);
    return firstFailure ?? { ok: false, error: 'No regions were scanned' };
  }

  return { ok: true, findings: succeeded.flatMap((r) => r.findings) };
}
