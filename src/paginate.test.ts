import { describe, it, expect, vi } from 'vitest';
import { collectPages, markerToken, PaginationError } from './paginate.js';

type Page = { items?: string[]; next?: string };

describe('collectPages', () => {
  it('returns everything across pages, in order', async () => {
    const pages: Record<string, Page> = {
      first: { items: ['a', 'b'], next: 'p2' },
      p2: { items: ['c', 'd'], next: 'p3' },
      p3: { items: ['e'] },
    };
    const fetchPage = vi.fn(async (token: string | undefined) => pages[token ?? 'first']!);

    const items = await collectPages<Page, string>({
      fetchPage,
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });

    expect(items).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(fetchPage).toHaveBeenCalledTimes(3);
    // The first call must not invent a token — some APIs reject an empty one.
    expect(fetchPage).toHaveBeenNthCalledWith(1, undefined);
  });

  it('asks for one page when there is no next token', async () => {
    const fetchPage = vi.fn(async () => ({ items: ['only'] }) as Page);
    const items = await collectPages<Page, string>({
      fetchPage,
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });
    expect(items).toEqual(['only']);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('treats a page with no items as empty rather than failing', async () => {
    const items = await collectPages<Page, string>({
      fetchPage: async () => ({}),
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });
    expect(items).toEqual([]);
  });

  // Both of these used to return whatever had been collected so far, which is
  // a partial list wearing the clothes of a complete one — the defect this
  // module exists to prevent, reproduced inside it. They throw now.
  it('throws rather than returning partial results when a token repeats', async () => {
    const fetchPage = vi.fn(async () => ({ items: ['x'], next: 'same' }) as Page);

    await expect(
      collectPages<Page, string>({
        fetchPage,
        itemsOf: (p) => p.items,
        tokenOf: (p) => p.next,
      })
    ).rejects.toThrow(PaginationError);
  });

  it('throws rather than returning partial results when the page cap is hit', async () => {
    let n = 0;
    const fetchPage = vi.fn(async () => ({ items: ['x'], next: `page-${n++}` }) as Page);

    await expect(
      collectPages<Page, string>({
        fetchPage,
        itemsOf: (p) => p.items,
        tokenOf: (p) => p.next,
      })
    ).rejects.toThrow(/refusing to return partial results/);
    expect(fetchPage).toHaveBeenCalledTimes(200);
  });

  it('treats an empty-string token as the end', async () => {
    const fetchPage = vi.fn(async () => ({ items: ['x'], next: '' }) as Page);
    await collectPages<Page, string>({
      fetchPage,
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });
});

describe('markerToken', () => {
  // The documented contract is that Marker is meaningful when IsTruncated is
  // true. Branching on the flag follows it; branching on the Marker's presence
  // assumes something the docs don't promise in either direction.
  it('only follows the Marker when IsTruncated says there is more', () => {
    expect(markerToken({ IsTruncated: true, Marker: 'next' })).toBe('next');
    expect(markerToken({ IsTruncated: false, Marker: 'stale' })).toBeUndefined();
    expect(markerToken({ Marker: 'stale' })).toBeUndefined();
    expect(markerToken({})).toBeUndefined();
  });

  it('throws when a response says it is truncated but gives nowhere to continue', () => {
    expect(() => markerToken({ IsTruncated: true })).toThrow(PaginationError);
  });
});
