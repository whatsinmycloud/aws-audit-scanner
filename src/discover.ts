import { EC2Client, DescribeRegionsCommand } from '@aws-sdk/client-ec2';
import {
  hasResources,
  probeRegion,
  resourceCount,
  type RegionPresence,
} from './tools/region-sweep.js';
import type { AwsCredentials } from './types.js';

// Deep-scanning every enabled region would multiply agent tokens for nothing —
// most accounts live in one or two. Discovery probes everywhere (cheap, parallel
// Describe calls), then the expensive full scan covers only regions that have
// resources, capped so a sprawling account can't blow the request timeout.
//
// Raised 5 → 10 on 2026-07-28 after the first real multi-region measurement:
// deep-scanning 5 regions took roughly the same wall clock as 1 (the fan-out is
// parallel), against a 300s ceiling on the browser path. The cap was costing us
// a finding that says "we didn't finish auditing your account" — a bad trade for
// a product selling thoroughness — so it now sits well above what almost any
// real account needs, while still bounding a pathological one.
export const MAX_DEEP_SCAN_REGIONS = 10;

export type RegionDiscovery = {
  // Regions with resources, busiest first, capped — these get the full scan.
  deepScanRegions: string[];
  // Verified empty: probed, nothing found.
  emptyRegions: string[];
  // Have resources but fell over the cap — reported, not deep-scanned.
  activeButSkipped: string[];
  regionsChecked: number;
};

export type DiscoveryResult =
  | { ok: true; discovery: RegionDiscovery }
  | { ok: false; error: string };

export type DiscoverInput = {
  // Used for the DescribeRegions call and as the deep-scan fallback when the
  // whole account is empty (so security-posture checks still review something).
  seedRegion: string;
  credentials?: AwsCredentials | undefined;
};

export async function discoverActiveRegions({
  seedRegion,
  credentials,
}: DiscoverInput): Promise<DiscoveryResult> {
  const ec2 = new EC2Client({ region: seedRegion, ...(credentials && { credentials }) });

  try {
    const { Regions } = await ec2.send(new DescribeRegionsCommand({}));
    const regionNames = (Regions ?? [])
      .map((r) => r.RegionName)
      .filter((name): name is string => Boolean(name));

    const probes = await Promise.allSettled(regionNames.map((r) => probeRegion(r, credentials)));
    const probed = probes
      .filter((p): p is PromiseFulfilledResult<RegionPresence> => p.status === 'fulfilled')
      .map((p) => p.value);

    // One flaky region is skipped silently; every probe failing means the
    // credentials or network are broken and the caller should know.
    if (regionNames.length > 0 && probed.length === 0) {
      const firstFailure = probes[0] as PromiseRejectedResult;
      return { ok: false, error: String(firstFailure.reason) };
    }

    return { ok: true, discovery: summarize(probed, seedRegion) };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

function summarize(probed: RegionPresence[], seedRegion: string): RegionDiscovery {
  const active = probed
    .filter(hasResources)
    .sort((a, b) => resourceCount(b) - resourceCount(a));
  const deepScanRegions = active.slice(0, MAX_DEEP_SCAN_REGIONS).map((p) => p.region);

  // A brand-new account with nothing anywhere still deserves a look at its
  // default security posture (open default SGs, no CloudTrail), so fall back
  // to the seed region rather than scanning nothing.
  if (deepScanRegions.length === 0) {
    deepScanRegions.push(seedRegion);
  }

  return {
    deepScanRegions,
    emptyRegions: probed
      .filter((p) => !hasResources(p))
      .map((p) => p.region)
      .filter((r) => !deepScanRegions.includes(r)),
    activeButSkipped: active.slice(MAX_DEEP_SCAN_REGIONS).map((p) => p.region),
    regionsChecked: probed.length,
  };
}
