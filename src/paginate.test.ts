import { describe, it, expect, vi } from 'vitest';
import { collectPages, markerToken } from './paginate.js';

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

  it('stops when an API echoes the same token back, instead of looping forever', async () => {
    const fetchPage = vi.fn(async () => ({ items: ['x'], next: 'same' }) as Page);
    const items = await collectPages<Page, string>({
      fetchPage,
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });
    // Two calls: the first returns "same", the second is asked with it and
    // returns it again, which is where the guard trips.
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(items).toEqual(['x', 'x']);
  });

  it('caps the number of pages so a never-ending token cannot hang a scan', async () => {
    let n = 0;
    const fetchPage = vi.fn(async () => ({ items: ['x'], next: `page-${n++}` }) as Page);
    const items = await collectPages<Page, string>({
      fetchPage,
      itemsOf: (p) => p.items,
      tokenOf: (p) => p.next,
    });
    expect(fetchPage).toHaveBeenCalledTimes(200);
    expect(items).toHaveLength(200);
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
  // IAM and RDS can return a Marker on the final page. Following it costs an
  // extra call at best, and re-reads page one at worst.
  it('only follows the Marker when IsTruncated says there is more', () => {
    expect(markerToken({ IsTruncated: true, Marker: 'next' })).toBe('next');
    expect(markerToken({ IsTruncated: false, Marker: 'stale' })).toBeUndefined();
    expect(markerToken({ Marker: 'stale' })).toBeUndefined();
    expect(markerToken({})).toBeUndefined();
  });
});
