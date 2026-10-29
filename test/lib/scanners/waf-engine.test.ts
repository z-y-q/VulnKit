import { describe, it, expect } from 'vitest';
import {
  analyzeResponse,
  detectWafInResponse,
  looksLikeWafBlock,
  getCompiledWafSignatures,
  WAF_SIGNATURES,
} from '@/lib/scanners/waf-engine';

describe('waf-engine: 预编译', () => {
  it('签名库非空且编译产物与签名一一对应', () => {
    expect(WAF_SIGNATURES.length).toBeGreaterThan(40);
    expect(getCompiledWafSignatures().length).toBe(WAF_SIGNATURES.length);
  });

  it('非法正则编译期剔除，不抛错', () => {
    // 签名库本身应全部合法（有正则就编译成功）
    for (const c of getCompiledWafSignatures()) {
      expect(c.header.length + c.body.length + c.cookie.length).toBeGreaterThan(0);
    }
  });
});

describe('waf-engine: analyzeResponse', () => {
  it('Cloudflare 响应头命中', () => {
    const d = analyzeResponse(
      { 'cf-ray': 'abc123', server: 'cloudflare', 'content-type': 'text/html' },
      '<html>ok</html>',
    );
    const cf = d.find((x) => x.name === 'Cloudflare');
    expect(cf).toBeDefined();
    expect(cf!.evidence.some((e) => e.type === 'header')).toBe(true);
  });

  it('SafeLine 拦截页命中（雷池/长亭合并签名）', () => {
    const d = analyzeResponse(
      { 'content-type': 'text/html' },
      '<html><body>Your request was blocked by SafeLine WAF</body></html>',
    );
    const sl = d.find((x) => x.name.includes('SafeLine'));
    expect(sl).toBeDefined();
  });

  it('加速乐 Cookie 命中', () => {
    const d = analyzeResponse(
      { 'set-cookie': '__jsluid_h=abc; path=/' },
      '<html>ok</html>',
    );
    const jsl = d.find((x) => x.name.includes('加速乐'));
    expect(jsl).toBeDefined();
    expect(jsl!.evidence.some((e) => e.type === 'cookie')).toBe(true);
  });

  it('普通响应零命中', () => {
    const d = analyzeResponse(
      { server: 'nginx', 'content-type': 'text/html' },
      '<html><body>正常页面</body></html>',
    );
    expect(d).toHaveLength(0);
  });

  it('证据数决定置信度（≥3 high）', () => {
    const d = analyzeResponse(
      { 'cf-ray': 'x', server: 'cloudflare', 'cf-cache-status': 'HIT' },
      'checking your browser',
    );
    const cf = d.find((x) => x.name === 'Cloudflare');
    expect(cf!.confidence).toBe('high');
  });
});

describe('waf-engine: detectWafInResponse / looksLikeWafBlock', () => {
  it('detectWafInResponse 只返回名称与证据文本', () => {
    const r = detectWafInResponse({ 'cf-ray': 'x' }, '');
    expect(r[0].name).toBe('Cloudflare');
    expect(typeof r[0].evidence[0]).toBe('string');
  });

  it.each([403, 406, 418, 429, 501])('状态码 %i 判定为疑似阻断', (status) => {
    expect(looksLikeWafBlock(status, '')).toBe(true);
  });

  it('200 + 拦截话术短响应 → 疑似阻断', () => {
    expect(looksLikeWafBlock(200, '<html>您的请求被拦截</html>')).toBe(true);
  });

  it('200 + 长正文提到 waf 字样不误报', () => {
    const longBody = 'a'.repeat(30000) + 'request blocked';
    expect(looksLikeWafBlock(200, longBody)).toBe(false);
  });

  it('200 + 正常响应 → 非阻断', () => {
    expect(looksLikeWafBlock(200, '<html>hello</html>')).toBe(false);
  });
});
