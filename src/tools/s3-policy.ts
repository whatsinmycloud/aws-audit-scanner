// Works out WHAT the public can do with a bucket, not just whether it's public.
//
// GetBucketPolicyStatus answers one boolean — "is this bucket public?" — which
// is why an earlier version of the report described a world-WRITABLE bucket as
// merely "readable by anyone" (found on a real account, 2026-07-28). Reading the
// policy document itself lets us separate three very different situations:
//   - anyone can upload/overwrite objects   (severe: hosting, defacement, cost)
//   - anyone can list every key             (turns public files into an index)
//   - anyone can fetch a key they know      (often deliberate, e.g. static assets)

export type PublicBucketAccess = {
  read: boolean;
  write: boolean;
  list: boolean;
  // Public statements gated by a Condition (source IP, VPCE, etc.). Not treated
  // as public here — we can't evaluate the condition, and calling a
  // condition-restricted bucket "open to the internet" would be a false alarm.
  conditionalStatements: number;
};

const WRITE_ACTIONS = [
  's3:putobject',
  's3:putobjectacl',
  's3:deleteobject',
  's3:deleteobjectversion',
  's3:restoreobject',
  's3:abortmultipartupload',
];
const READ_ACTIONS = ['s3:getobject', 's3:getobjectversion'];
const LIST_ACTIONS = ['s3:listbucket', 's3:listbucketversions', 's3:listbucketmultipartuploads'];

type PolicyStatement = {
  Effect?: unknown;
  Principal?: unknown;
  Action?: unknown;
  Condition?: unknown;
};

export function analysePublicPolicy(policyDocument: string): PublicBucketAccess {
  const empty: PublicBucketAccess = {
    read: false,
    write: false,
    list: false,
    conditionalStatements: 0,
  };

  let parsed: unknown;
  try {
    parsed = JSON.parse(policyDocument);
  } catch {
    return empty;
  }

  const statements = toArray((parsed as { Statement?: unknown })?.Statement);
  const result = { ...empty };

  for (const raw of statements) {
    const statement = raw as PolicyStatement;
    if (String(statement.Effect).toLowerCase() !== 'allow') continue;
    if (!isPublicPrincipal(statement.Principal)) continue;

    if (statement.Condition !== undefined) {
      result.conditionalStatements += 1;
      continue;
    }

    for (const action of toArray(statement.Action).map((a) => String(a).toLowerCase())) {
      if (matchesAny(action, READ_ACTIONS)) result.read = true;
      if (matchesAny(action, WRITE_ACTIONS)) result.write = true;
      if (matchesAny(action, LIST_ACTIONS)) result.list = true;
    }
  }

  return result;
}

// "*", { "AWS": "*" }, or { "AWS": ["*", ...] } all mean everyone. Anything
// naming a specific account or service principal is not public.
function isPublicPrincipal(principal: unknown): boolean {
  if (principal === '*') return true;
  if (typeof principal !== 'object' || principal === null) return false;
  const aws = (principal as Record<string, unknown>)['AWS'];
  return toArray(aws).some((entry) => entry === '*');
}

// Handles the wildcards IAM allows: "*", "s3:*", "s3:Get*", "s3:PutObject*".
function matchesAny(action: string, candidates: string[]): boolean {
  if (action === '*' || action === 's3:*') return true;
  if (!action.endsWith('*')) return candidates.includes(action);
  const prefix = action.slice(0, -1);
  return candidates.some((candidate) => candidate.startsWith(prefix));
}

function toArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}
