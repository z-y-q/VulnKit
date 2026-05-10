import { describe, it, expect } from '@jest/globals';
import {
  highlightJson,
  base64UrlDecode,
  detectAlgorithmConfusion,
  analyzeJwtClaims,
  getClaimIcon,
} from '../src/popup/vk-jwt.js';

// ---------------------------------------------------------------------------
// base64UrlDecode
// ---------------------------------------------------------------------------
describe('base64UrlDecode', () => {
  it('decodes standard base64url without padding to valid JSON', () => {
    // eyJhbGciOiJIUzI1NiJ9 decodes to {"alg":"HS256"}
    const decoded = base64UrlDecode('eyJhbGciOiJIUzI1NiJ9');
    const parsed = JSON.parse(decoded);
    expect(parsed).toEqual({ alg: 'HS256' });
  });

  it('decodes base64url string with correct padding', () => {
    // eyJhbGciOiJIUzI1NiJ9 (24 chars, already divisible by 4 — no padding needed)
    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 (36 chars, needs 0 padding)
    const decoded = base64UrlDecode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    const parsed = JSON.parse(decoded);
    expect(parsed.alg).toBe('HS256');
    expect(parsed.typ).toBe('JWT');
  });

  it('throws on invalid input', () => {
    // atob throws InvalidCharacterError for non-base64 characters
    expect(() => base64UrlDecode('!!!invalid!!!')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// highlightJson
// ---------------------------------------------------------------------------
describe('highlightJson', () => {
  it('highlights object keys with color:#9b59b6', () => {
    const html = highlightJson({ a: 1, b: 'hello' });
    expect(html).toContain('color:#9b59b6');
  });

  it('highlights string values with color:#27ae60', () => {
    const html = highlightJson({ name: 'hello' });
    expect(html).toContain('color:#27ae60');
  });

  it('highlights numbers with color:#e67e22', () => {
    const html = highlightJson({ count: 42 });
    expect(html).toContain('color:#e67e22');
  });

  it('highlights booleans and null with color:#3498db', () => {
    const html = highlightJson({ active: true, disabled: false, nothing: null });
    expect(html).toContain('color:#3498db');
  });

  it('handles nested objects', () => {
    const html = highlightJson({ outer: { inner: 'value' } });
    expect(html).toContain('color:#9b59b6');
    expect(html).toContain('color:#27ae60');
  });
});

// ---------------------------------------------------------------------------
// detectAlgorithmConfusion
// ---------------------------------------------------------------------------
describe('detectAlgorithmConfusion', () => {
  it('header {alg: "none"} returns critical severity item with "none" in title', () => {
    const results = detectAlgorithmConfusion({ alg: 'none' }, {});
    const found = results.find(r => r.severity === 'critical');
    expect(found).toBeDefined();
    expect(found.title.toLowerCase()).toContain('none');
  });

  it('header {alg: "none"} returns at least 1 finding', () => {
    const results = detectAlgorithmConfusion({ alg: 'none' }, {});
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it('header with jku returns high severity item', () => {
    const results = detectAlgorithmConfusion({ jku: 'https://evil.com/keys' }, {});
    const found = results.find(r => r.severity === 'high' && r.title.includes('jku'));
    expect(found).toBeDefined();
  });

  it('header with kid containing SQL injection chars returns high severity', () => {
    const results = detectAlgorithmConfusion({ kid: "1'; DROP TABLE--" }, {});
    const found = results.find(r => r.severity === 'high' && r.title.includes('SQL'));
    expect(found).toBeDefined();
  });

  it('header with kid containing path traversal returns high severity', () => {
    const results = detectAlgorithmConfusion({ kid: '../../../etc/passwd' }, {});
    const found = results.find(r => r.severity === 'high' && r.title.includes('路径遍历'));
    expect(found).toBeDefined();
  });

  it('header without alg returns medium severity', () => {
    const results = detectAlgorithmConfusion({}, {});
    const found = results.find(r => r.severity === 'medium' && r.title.includes('缺少'));
    expect(found).toBeDefined();
  });

  it('expired payload (exp in the past) returns medium "Token 已过期"', () => {
    const pastTimestamp = Math.floor(Date.now() / 1000) - 3600;
    const results = detectAlgorithmConfusion({ alg: 'HS256' }, { exp: pastTimestamp });
    const found = results.find(r => r.title.includes('Token 已过期'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('medium');
  });

  it('nbf in the future returns medium "Token 尚未生效"', () => {
    const futureTimestamp = Math.floor(Date.now() / 1000) + 3600;
    const results = detectAlgorithmConfusion({ alg: 'HS256' }, { nbf: futureTimestamp });
    const found = results.find(r => r.title.includes('Token 尚未生效'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('medium');
  });

  it('long validity (>365 days) returns low severity', () => {
    const now = Math.floor(Date.now() / 1000);
    const results = detectAlgorithmConfusion(
      { alg: 'HS256' },
      { nbf: now - 86400 * 400, exp: now + 86400 * 400 }
    );
    const found = results.find(r => r.title.includes('有效期过长'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('low');
  });

  it('no exp and no iat returns low severity', () => {
    const results = detectAlgorithmConfusion({ alg: 'HS256' }, {});
    const found = results.find(r => r.title.includes('缺少时间控制'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('low');
  });
});

// ---------------------------------------------------------------------------
// analyzeJwtClaims
// ---------------------------------------------------------------------------
describe('analyzeJwtClaims', () => {
  it('payload with password returns high severity finding', () => {
    const results = analyzeJwtClaims({}, { password: 's3cret' });
    const found = results.find(r => r.title.includes('password'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('high');
  });

  it('payload with email returns medium severity finding', () => {
    const results = analyzeJwtClaims({}, { email: 'user@example.com' });
    const found = results.find(r => r.title.includes('email'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('medium');
  });

  it('payload with many (>15) private claims returns low "过多私有 Claim"', () => {
    const payload = {};
    for (let i = 0; i < 20; i++) {
      payload[`custom_field_${i}`] = `value_${i}`;
    }
    const results = analyzeJwtClaims({}, payload);
    const found = results.find(r => r.title.includes('过多私有 Claim'));
    expect(found).toBeDefined();
    expect(found.severity).toBe('low');
  });

  it('empty payload returns empty array', () => {
    const results = analyzeJwtClaims({}, {});
    expect(results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getClaimIcon
// ---------------------------------------------------------------------------
describe('getClaimIcon', () => {
  it('getClaimIcon("exp") returns clock SVG string', () => {
    const icon = getClaimIcon('exp');
    expect(icon).toContain('<svg');
    // Clock icon is identified by circle + polyline (clock face + hands)
    expect(icon).toContain('<polyline');
    expect(icon).toContain('<circle');
  });

  it('getClaimIcon("sub") returns key SVG string', () => {
    const icon = getClaimIcon('sub');
    expect(icon).toContain('<svg');
    expect(icon).toContain('path');
  });

  it('getClaimIcon("aud") returns user SVG string', () => {
    const icon = getClaimIcon('aud');
    expect(icon).toContain('<svg');
    expect(icon).toContain('circle');
  });

  it('getClaimIcon("unknown") returns empty string', () => {
    expect(getClaimIcon('unknown')).toBe('');
  });
});
