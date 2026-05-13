import { describe, it, expect } from '@jest/globals';
import { analyzeResults } from '../src/popup/vk-cors.js';

// ---------------------------------------------------------------------------
// analyzeResults
// ---------------------------------------------------------------------------
describe('analyzeResults', () => {
  function makeResult(overrides) {
    return Object.assign(
      {
        endpoint: '/api/test',
        url: 'https://example.com/api/test',
        origin: { value: 'https://evil.com' },
        method: 'GET',
        response: { type: 'basic', status: 200, headers: {} },
      },
      overrides
    );
  }

  it('returns safe for opaque (no-cors) response', () => {
    var results = [makeResult({ response: { type: 'opaque', status: 0, headers: {} } })];
    var out = analyzeResults(results);
    expect(out.total).toBe(1);
    expect(out.safeCount).toBe(1);
    expect(out.errors).toEqual([]);
    expect(out.issues[0].severity).toBe('safe');
    expect(out.issues[0].findings).toContain('服务器未返回 CORS 头 (安全)');
  });

  it('returns safe when no ACAO header', () => {
    var results = [makeResult()];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('safe');
    expect(out.issues[0].findings).toContain('未设置 Access-Control-Allow-Origin');
  });

  it('returns warning for ACAO wildcard', () => {
    var results = [makeResult({ response: { type: 'basic', status: 200, headers: { 'access-control-allow-origin': '*' } } })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('warning');
    expect(out.issues[0].findings).toContain('ACAO: * (任意来源可访问)');
  });

  it('returns critical for ACAO wildcard + credentials true', () => {
    var results = [makeResult({
      response: {
        type: 'basic', status: 200,
        headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('critical');
    expect(out.issues[0].findings.some(function (f) { return f.indexOf('Allow-Credentials: true + Origin: *') !== -1; })).toBe(true);
  });

  it('returns danger for reflected origin', () => {
    var results = [makeResult({
      response: {
        type: 'basic', status: 200,
        headers: { 'access-control-allow-origin': 'https://evil.com' },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('danger');
    expect(out.issues[0].findings).toContain('Origin 被反射: https://evil.com');
  });

  it('returns critical for reflected origin + credentials true', () => {
    var results = [makeResult({
      response: {
        type: 'basic', status: 200,
        headers: {
          'access-control-allow-origin': 'https://evil.com',
          'access-control-allow-credentials': 'true',
        },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('critical');
    expect(out.issues[0].findings.some(function (f) { return f.indexOf('Allow-Credentials: true + Origin 反射') !== -1; })).toBe(true);
  });

  it('includes null origin warning when origin is null', () => {
    var results = [makeResult({
      origin: { value: 'null' },
      response: {
        type: 'basic', status: 200,
        headers: { 'access-control-allow-origin': 'null' },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('danger');
    expect(out.issues[0].findings).toContain('Null Origin 被信任 — sandbox/iframe 可利用');
  });

  it('returns warning for non-reflected ACAO', () => {
    var results = [makeResult({
      response: {
        type: 'basic', status: 200,
        headers: { 'access-control-allow-origin': 'https://other.com' },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].severity).toBe('warning');
    expect(out.issues[0].findings[0]).toContain('ACAO: https://other.com');
  });

  it('includes preflight findings for OPTIONS request', () => {
    var results = [makeResult({
      method: 'OPTIONS',
      response: {
        type: 'basic', status: 204,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST',
          'access-control-allow-headers': 'Content-Type, Authorization',
        },
      },
    })];
    var out = analyzeResults(results);
    var findings = out.issues[0].findings;
    expect(findings.some(function (f) { return f.indexOf('预检允许方法: GET, POST') !== -1; })).toBe(true);
    expect(findings.some(function (f) { return f.indexOf('预检允许头:') !== -1; })).toBe(true);
  });

  it('warns when OPTIONS has ACAO but no Allow-Methods', () => {
    var results = [makeResult({
      method: 'OPTIONS',
      response: {
        type: 'basic', status: 204,
        headers: { 'access-control-allow-origin': '*' },
      },
    })];
    var out = analyzeResults(results);
    expect(out.issues[0].findings).toContain('预检响应缺少 Allow-Methods');
  });

  it('includes expose-headers and max-age findings', () => {
    var results = [makeResult({
      response: {
        type: 'basic', status: 200,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-expose-headers': 'X-Custom-Header',
          'access-control-max-age': '3600',
        },
      },
    })];
    var findings = analyzeResults(results).issues[0].findings;
    expect(findings).toContain('暴露头: X-Custom-Header');
    expect(findings).toContain('预检缓存: 3600s');
  });

  it('correctly counts mixed results', () => {
    var results = [
      makeResult({ response: { type: 'opaque', status: 0, headers: {} } }),
      makeResult(),
      makeResult({
        response: { type: 'basic', status: 200, headers: { 'access-control-allow-origin': '*' } },
      }),
    ];
    var out = analyzeResults(results);
    expect(out.total).toBe(3);
    expect(out.safeCount).toBe(2);
    expect(out.issues).toHaveLength(3);
    expect(out.issues[0].severity).toBe('safe');
    expect(out.issues[1].severity).toBe('safe');
    expect(out.issues[2].severity).toBe('warning');
  });

  it('returns empty issues for empty input', () => {
    var out = analyzeResults([]);
    expect(out.total).toBe(0);
    expect(out.safeCount).toBe(0);
    expect(out.issues).toEqual([]);
  });
});
