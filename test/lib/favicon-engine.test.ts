import { describe, it, expect } from 'vitest';
import {
  mmh3_32,
  computeFaviconHash,
  buildShodanQuery,
  buildFofaQuery,
  KNOWN_FAVICONS,
} from '@/lib/scanners/favicon-engine';

describe('favicon-engine: mmh3_32', () => {
  it('返回值为 32 位有符号整数', () => {
    const result = mmh3_32('test');
    expect(Number.isInteger(result)).toBe(true);
    // 32-bit signed integer range: -2^31 to 2^31 - 1
    expect(result).toBeGreaterThanOrEqual(-2147483648);
    expect(result).toBeLessThanOrEqual(2147483647);
  });

  it('确定性: 相同输入返回相同结果', () => {
    const a = mmh3_32('hello world');
    const b = mmh3_32('hello world');
    expect(a).toBe(b);
  });

  it('不同输入大概率返回不同结果', () => {
    const a = mmh3_32('foo');
    const b = mmh3_32('bar');
    expect(a).not.toBe(b);
  });

  it('空字符串也能计算', () => {
    const result = mmh3_32('');
    expect(Number.isInteger(result)).toBe(true);
    expect(result).toBeGreaterThanOrEqual(-2147483648);
    expect(result).toBeLessThanOrEqual(2147483647);
  });

  it('多次调用结果一致', () => {
    const inputs = ['', 'a', 'ab', 'abc', 'favicon.ico', 'data:image/png;base64,'];
    for (const input of inputs) {
      const first = mmh3_32(input);
      const second = mmh3_32(input);
      expect(first).toBe(second);
    }
  });
});

describe('favicon-engine: computeFaviconHash', () => {
  it('确定性: 相同 base64 输入返回相同 hash', () => {
    const b64 = 'AAABAAEAMDAAAAEIAAAAAAAAQAABAAAAAQAAAAA';
    const a = computeFaviconHash(b64);
    const b = computeFaviconHash(b64);
    expect(a).toBe(b);
  });

  it('返回 32 位有符号整数', () => {
    const hash = computeFaviconHash('AAABAAEAMDAAAAEIAAAAAAAAQAABAAAAAQAAAAA');
    expect(Number.isInteger(hash)).toBe(true);
    expect(hash).toBeGreaterThanOrEqual(-2147483648);
    expect(hash).toBeLessThanOrEqual(2147483647);
  });

  it('带 data URI 前缀也能正确计算', () => {
    const plain = computeFaviconHash('AAABAAEA');
    const withPrefix = computeFaviconHash('data:image/x-icon;base64,AAABAAEA');
    // 两者应该相同 — 前缀会被剥离
    expect(plain).toBe(withPrefix);
  });

  it('不同 base64 输入产生不同 hash', () => {
    const a = computeFaviconHash('AAABAAEA');
    const b = computeFaviconHash('ZZZZYYYY');
    expect(a).not.toBe(b);
  });
});

describe('favicon-engine: buildShodanQuery', () => {
  it('返回正确格式的 Shodan 查询', () => {
    const query = buildShodanQuery(-1555604066);
    expect(query).toBe('http.favicon.hash:-1555604066');
  });

  it('正数 hash 也能正确拼接', () => {
    const query = buildShodanQuery(1611882159);
    expect(query).toBe('http.favicon.hash:1611882159');
  });

  it('零值 hash', () => {
    const query = buildShodanQuery(0);
    expect(query).toBe('http.favicon.hash:0');
  });
});

describe('favicon-engine: buildFofaQuery', () => {
  it('返回正确格式的 FOFA 查询', () => {
    const query = buildFofaQuery(-1555604066);
    expect(query).toBe('icon_hash="-1555604066"');
  });

  it('正数 hash 也能正确拼接', () => {
    const query = buildFofaQuery(1611882159);
    expect(query).toBe('icon_hash="1611882159"');
  });

  it('零值 hash', () => {
    const query = buildFofaQuery(0);
    expect(query).toBe('icon_hash="0"');
  });
});

describe('favicon-engine: KNOWN_FAVICONS', () => {
  it('为非空 Record', () => {
    expect(typeof KNOWN_FAVICONS).toBe('object');
    expect(Object.keys(KNOWN_FAVICONS).length).toBeGreaterThan(0);
  });

  it('键为数字，值为字符串', () => {
    for (const [key, value] of Object.entries(KNOWN_FAVICONS)) {
      expect(Number.isInteger(Number(key))).toBe(true);
      expect(typeof value).toBe('string');
    }
  });

  it('包含常见产品', () => {
    const values = Object.values(KNOWN_FAVICONS);
    expect(values).toContain('Apache');
    expect(values).toContain('Nginx');
    expect(values).toContain('WordPress');
  });

  it('包含 IIS', () => {
    expect(Object.values(KNOWN_FAVICONS)).toContain('IIS');
  });

  it('包含 Cloudflare', () => {
    expect(Object.values(KNOWN_FAVICONS)).toContain('Cloudflare');
  });
});
