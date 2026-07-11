import { describe, it, expect } from 'vitest';
import {
  buildTestUrls,
  extractLocation,
  isRedirectVulnerable,
  REDIRECT_PAYLOADS,
  PROTOCOL_VARIANTS,
} from '@/lib/scanners/redirect-engine';

describe('redirect-engine: buildTestUrls', () => {
  it('生成 参数数 × 变体数 个测试 URL', () => {
    const tests = buildTestUrls('https://target.com/page');
    expect(tests.length).toBe(REDIRECT_PAYLOADS.length * PROTOCOL_VARIANTS.length);
  });

  it('清理基础 URL 的 query/hash', () => {
    const tests = buildTestUrls('https://target.com/page?x=1#frag');
    expect(tests[0].url).not.toContain('#frag');
  });

  it('每个 URL 包含参数和变体信息', () => {
    const tests = buildTestUrls('https://target.com/');
    expect(tests[0].param).toBeDefined();
    expect(tests[0].variant).toBeDefined();
    expect(tests[0].url).toContain('target.com');
  });

  it('变体被 URL 编码', () => {
    const tests = buildTestUrls('https://target.com/');
    const jsVariant = tests.find(t => t.variant === 'javascript:alert(1)');
    expect(jsVariant).toBeDefined();
    expect(jsVariant!.url).toContain(encodeURIComponent('javascript:alert(1)'));
  });
});

describe('redirect-engine: extractLocation', () => {
  it('从对象头提取 location', () => {
    expect(extractLocation({ location: 'https://evil.com' })).toBe('https://evil.com');
  });

  it('从数组头提取 location', () => {
    const headers = [
      { name: 'Content-Type', value: 'text/html' },
      { name: 'Location', value: 'https://evil.com' },
    ];
    expect(extractLocation(headers)).toBe('https://evil.com');
  });

  it('无 location 返回空字符串', () => {
    expect(extractLocation({ 'content-type': 'text/html' })).toBe('');
    expect(extractLocation(undefined)).toBe('');
  });
});

describe('redirect-engine: isRedirectVulnerable', () => {
  it('3xx 重定向指向 evil.com = 漏洞', () => {
    const resp = {
      status: 302,
      headers: { location: 'https://evil.com/phish' },
    };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(true);
  });

  it('3xx 重定向指向 example.com = 漏洞', () => {
    const resp = {
      status: 301,
      headers: { location: 'https://example.com' },
    };
    expect(isRedirectVulnerable(resp, 'https://example.com')).toBe(true);
  });

  it('3xx 重定向指向同源 = 安全', () => {
    const resp = {
      status: 302,
      headers: { location: 'https://target.com/login' },
    };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(false);
  });

  it('redirected 标志 + evil.com 最终 URL = 漏洞', () => {
    const resp = { status: 200, redirected: true, url: 'https://evil.com/landing' };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(true);
  });

  it('meta refresh 跳转 evil.com = 漏洞', () => {
    const resp = {
      status: 200,
      body: '<html><head><meta http-equiv="refresh" content="0;url=https://evil.com"></head></html>',
    };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(true);
  });

  it('JS location.href 跳转 = 漏洞', () => {
    const resp = {
      status: 200,
      body: '<script>location.href = "https://evil.com";</script>',
    };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(true);
  });

  it('无响应返回 false', () => {
    expect(isRedirectVulnerable(null as any, 'https://evil.com')).toBe(false);
  });

  it('普通 200 响应无恶意内容 = 安全', () => {
    const resp = { status: 200, body: '<html><body>welcome</body></html>' };
    expect(isRedirectVulnerable(resp, 'https://evil.com')).toBe(false);
  });
});

describe('redirect-engine: 数据完整性', () => {
  it('REDIRECT_PAYLOADS 包含常见参数', () => {
    const params = REDIRECT_PAYLOADS.map(p => p.param);
    expect(params).toContain('url');
    expect(params).toContain('redirect');
    expect(params).toContain('redirect_uri');
    expect(params).toContain('returnUrl');
  });

  it('PROTOCOL_VARIANTS 包含绕过技巧', () => {
    expect(PROTOCOL_VARIANTS).toContain('//evil.com');
    expect(PROTOCOL_VARIANTS.some(v => v.includes('javascript:'))).toBe(true);
    expect(PROTOCOL_VARIANTS.some(v => v.includes('\\'))).toBe(true); // 反斜杠绕过
  });
});
