import { describe, it, expect } from 'vitest';
import {
  classifyLink,
  dedupeLinks,
  buildCsv,
  type ExtractedLink,
} from '@/lib/scanners/links-engine';

describe('links-engine: classifyLink', () => {
  it('同域 internal', () => {
    expect(classifyLink('https://example.com/page', 'https://example.com')).toBe('internal');
  });

  it('不同域 external', () => {
    expect(classifyLink('https://evil.com/attack', 'https://example.com')).toBe('external');
  });

  it('相对路径 /path', () => {
    expect(classifyLink('/about', 'https://example.com')).toBe('relative');
    expect(classifyLink('contact', 'https://example.com')).toBe('relative');
  });

  it('mailto', () => {
    expect(classifyLink('mailto:test@example.com', 'https://example.com')).toBe('mailto');
  });

  it('tel', () => {
    expect(classifyLink('tel:+86-138-0000-0000', 'https://example.com')).toBe('tel');
  });

  it('anchor #', () => {
    expect(classifyLink('#section', 'https://example.com')).toBe('anchor');
    expect(classifyLink('#', 'https://example.com')).toBe('anchor');
  });

  it('空字符串 anchor', () => {
    expect(classifyLink('', 'https://example.com')).toBe('anchor');
  });

  it('protocol-relative // 为 external', () => {
    expect(classifyLink('//evil.com/script.js', 'https://example.com')).toBe('external');
  });
});

describe('links-engine: dedupeLinks', () => {
  it('去除重复链接', () => {
    const links: ExtractedLink[] = [
      { href: 'https://example.com/', type: 'internal' },
      { href: 'https://example.com/', type: 'internal' },
      { href: 'https://example.com/about', type: 'internal' },
    ];
    const deduped = dedupeLinks(links);
    expect(deduped.length).toBe(2);
  });

  it('保留不同 href', () => {
    const links: ExtractedLink[] = [
      { href: '/a', type: 'relative' },
      { href: '/b', type: 'relative' },
      { href: '/c', type: 'relative' },
    ];
    expect(dedupeLinks(links).length).toBe(3);
  });

  it('空数组返回空', () => {
    expect(dedupeLinks([])).toEqual([]);
  });
});

describe('links-engine: buildCsv', () => {
  it('生成包含标题行的 CSV', () => {
    const links: ExtractedLink[] = [
      { href: 'https://example.com/', type: 'internal', tag: 'a', domain: 'example.com', text: 'Home' },
      { href: 'https://evil.com/', type: 'external', tag: 'a', domain: 'evil.com', text: 'Evil' },
    ];
    const csv = buildCsv(links);
    expect(csv).toContain('URL');
    expect(csv).toContain('Type');
    expect(csv).toContain('https://example.com/');
    expect(csv).toContain('external');
  });

  it('空数组仍有标题行', () => {
    const csv = buildCsv([]);
    expect(csv).toContain('URL');
    expect(csv).toContain('Type');
  });
});
