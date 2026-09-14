# aws-audit-scanner

Finds the common cost and security problems in an AWS account: forgotten spend,
and the defaults that actually cause incidents. **Read-only, runs locally,
covers every region.** Usable as a library, a CLI, or an
[MCP](https://modelcontextprotocol.io) server your agent can drive.

It answers the questions you'd check by hand if you had the afternoon: is
anything public that shouldn't be, does root have MFA, which access keys have
never been used, what's still billing that nobody is using.

**It cannot change anything.** Every call it makes is a `Describe*`, `List*` or
`Get*`. There is no code path that creates, modifies or deletes an AWS resource,
and no dependency that could add one — see [Read-only by construction](#read-only-by-construction).

Point it at your own account with your own credentials. Nothing is sent
anywhere, and nothing is stored.

---

## What it checks

| Tool | Finds |
|---|---|
| `scan_stopped_ec2` | Stopped instances still billing for their EBS volumes |
| `scan_unattached_ebs` | Volumes attached to nothing, billed at full rate |
| `scan_s3_public_access` | Buckets exposed by ACL or policy, and buckets missing Block Public Access |
| `scan_security_groups` | Sensitive ports open to `0.0.0.0/0` |
| `scan_iam` | Root access keys, root without MFA, users without MFA, keys never used or unused for 90+ days |
| `scan_cloudtrail` | Whether anything is actually being logged, and whether it covers all regions |
| `sweep_other_regions` | Forgotten EC2/EBS/RDS resources in regions you've stopped thinking about |

Every tool returns structured findings — severity, the specific resource id, why
it matters, and the console *and* CLI steps to fix it — so the output is usable
by a program, not just readable by a person.

## Install

```bash
npm install
npm run build
```

Requires Node 22+.

## Use it as an MCP server

Add it to any MCP client. For Claude Desktop, in
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aws-audit": {
      "command": "node",
      "args": ["/absolute/path/to/aws-audit-scanner/dist/index.js"],
      "env": { "AWS_PROFILE": "your-profile" }
    }
  }
}
```

Then ask your agent to audit the account. It calls the tools it needs and
reasons across the results.

## Use it as a library

```ts
import { scanIam } from 'aws-audit-scanner/dist/tools/scan-iam.js';

const result = await scanIam({ region: 'eu-west-1' });
if (result.ok) {
  for (const finding of result.findings) {
    console.log(`[${finding.severity}] ${finding.title}`);
  }
}
```

Every tool returns a `Result`-shaped value (`{ ok: true, findings }` or
`{ ok: false, error }`) rather than throwing, because a single denied permission
should degrade one check rather than fail the whole audit.

## Credentials

The tools use the ambient AWS credential chain — profile, environment,
instance role, whatever the SDK resolves. Nothing is read from a config file of
ours and nothing is stored.

To audit a *different* account, `assumeAuditRole` wraps STS with an external ID:

```ts
import { assumeAuditRole } from 'aws-audit-scanner/dist/assume-role.js';

const assumed = await assumeAuditRole({
  roleArn: 'arn:aws:iam::111122223333:role/YourAuditRole',
  externalId: 'the-id-the-role-requires',
  region: 'eu-west-1',
});
if (assumed.ok) await scanIam({ region: 'eu-west-1', credentials: assumed.credentials });
```

Sessions are short-lived by design.

---

## Read-only by construction

A promise in a README is worth very little, so this is enforced in three places:

1. **The code.** Only `Describe*`, `List*` and `Get*` commands are imported from
   the AWS SDK. Grep for it — there is no `Create`, `Put`, `Delete`, `Update`,
   `Terminate`, `Stop`, `Start`, `Modify`, `Attach` or `Detach` command in the
   source.
2. **The IAM policy.** The role the hosted service asks customers to deploy is
   published in full at
   [whatsinmycloud/readonly-role](https://github.com/whatsinmycloud/readonly-role) —
   the literal file, not a summary. `PERMISSIONS.md` in this repo explains why
   each permission is needed.
3. **The trust policy.** That role can only be assumed by one named role, in one
   named account, gated by a server-issued external ID. It is not assumable by
   anyone who merely learns its ARN.

If you're evaluating whether to point this at an account you care about: read
`src/tools/`. Each file is short, and the scan logic is the whole story.

## Coverage, honestly

- **Pagination is handled.** Every list call follows its continuation token.
  Worth stating because it wasn't always true here: IAM's `ListUsers` returns
  100 items when you don't pass `MaxItems`, so an unpaginated scan of a
  150-user account reported "2 users without MFA" with complete confidence
  while never looking at the other 50. A wrong number in a security report is
  worse than a missing one, because nothing signals that it's wrong. The EC2
  calls are paginated defensively rather than because a bug was demonstrated —
  `DescribeSecurityGroups` documents that omitting `MaxResults` returns
  everything. `src/paginate.ts` has the mechanics, and
  `src/tools/ugly-account.test.ts` fails the build if a first-page-only
  regression ever creeps back in.
- **Region discovery is a presence probe.** `discover.ts` checks every enabled
  region cheaply and deep-scans the ones with resources. `region-sweep.ts`
  deliberately reads only the first page — it answers "is there anything here?",
  not "what exactly is here?".
- **Costs are estimates.** EBS pricing is approximated from volume type and
  size. Treat the figures as an order of magnitude for prioritising, not a bill.
- **Not covered yet:** Lambda, ElastiCache, NAT Gateways, unattached Elastic
  IPs, old snapshots. All are real sources of forgotten spend; none are
  implemented.

## Development

```bash
npm test           # unit tests, no AWS calls — the SDK is mocked
npm run typecheck
npm run build
```

Tests use [`aws-sdk-client-mock`](https://github.com/m-radzikowski/aws-sdk-client-mock),
so the suite runs offline and never touches an account. New checks want a test
covering the interesting shape, not just the happy path — the bugs worth having
tests for here have all been about accounts that were bigger or messier than the
one the author was looking at.

## Contributing

Issues and pull requests welcome. A new scan tool needs: a `ScanResult`-returning
function in `src/tools/`, a registration in `src/index.ts`, and tests. Keep the
read-only guarantee absolute — a pull request that introduces a mutating AWS
call will be declined regardless of how useful it is.

## Who uses it

[WhatsInMyCloud](https://whatsinmycloud.com) runs this scanner and adds
prioritised plain-English reports and weekly monitoring on top. That layer is
not open source; everything that touches an AWS account is in this repo.

If you'd rather not run anything yourself, that's the hosted version. If you'd
rather read the code and run it locally, that's this.

## Licence

MIT — see [LICENSE](LICENSE).
