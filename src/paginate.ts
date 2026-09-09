// AWS list calls return one page. Nothing here originally asked for the next
// one, which is the quietest failure this scanner can have: an account with
// 150 IAM users returned the first 100, and the report said "2 users without
// MFA" with complete confidence. A crash would have been better — a wrong
// number in a security report is worse than a missing one, because the reader
// has no way to know it's wrong.
//
// Two token conventions are in play. EC2 and CloudTrail use NextToken; IAM and
// RDS use Marker with an IsTruncated flag. Both collapse to "give me the token
// for the next page, or undefined when there isn't one".

// A page is never unbounded in practice — IAM caps at 1000 per page, EC2 at
// 1000 — so this many pages is far past any real account while still ending a
// loop that would otherwise run forever on a malformed or looping token.
const MAX_PAGES = 200;

export type PaginateOptions<TPage, TItem> = {
  // Fetch one page. Called with undefined first, then with each page's token.
  fetchPage: (token: string | undefined) => Promise<TPage>;
  // Pull the items out of a page. Missing arrays are normal, not an error.
  itemsOf: (page: TPage) => TItem[] | undefined;
  // The token for the next page, or undefined at the end.
  tokenOf: (page: TPage) => string | undefined;
};

export async function collectPages<TPage, TItem>({
  fetchPage,
  itemsOf,
  tokenOf,
}: PaginateOptions<TPage, TItem>): Promise<TItem[]> {
  const collected: TItem[] = [];
  let token: string | undefined = undefined;

  for (let page = 0; page < MAX_PAGES; page += 1) {
    const response: TPage = await fetchPage(token);
    collected.push(...(itemsOf(response) ?? []));

    const next = tokenOf(response);
    // An API that echoes the same token back would otherwise loop forever.
    if (next === undefined || next === '' || next === token) return collected;
    token = next;
  }

  return collected;
}

// IAM and RDS signal "more pages" with IsTruncated alongside Marker. Trusting
// Marker alone is wrong: these APIs can return a Marker on the final page.
export function markerToken(page: {
  IsTruncated?: boolean | undefined;
  Marker?: string | undefined;
}): string | undefined {
  return page.IsTruncated === true ? page.Marker : undefined;
}
