import { describe, it, expect } from 'vitest';
import {
  analyzeHeaders,
  deepAnalyzeCSP,
  severityLabel,
  SEVERITY_COLOR,
  STATUS_COLOR,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
} from '@/lib/scanners/headers-engine';

// ====== 辅助构造 ======

/** 完美安全头集合 — 所有检查器应 pass */
const SECURE_HEADERS: Record<string, string> = {
  'content-security-policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=(), camera=(), microphone=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cache-control': 'no-store',
  'pragma': 'no-cache',
  'content-security-policy-report-only': "default-src 'self'",
  'clear-site-data': '"cache","cookies","storage"',
  'x-robots-tag': 'noindex',
  'x-permitted-cross-domain-policies': 'none',
  'x-xss-protection': '0',
  'x-download-options': 'noopen',
  'report-to': '{"group":"default","max_age":10886400}',
  'nel': '{"report_to":"default","max_age":10886400}',
  'reporting-endpoints': 'default="https://example.com/report"',
  'content-digest': 'sha-256=:abc=:',
  'accept-ch': 'Sec-CH-DPR, Sec-CH-Width',
  'origin-agent-cluster': '?1',
};

/** 空头 — 所有安全头缺失 */
const EMPTY_HEADERS: Record<string, string> = {};

/** 有误配置的头 */
const MISCONFIGURED_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src *; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'",
  'strict-transport-security': 'max-age=300',
  'x-frame-options': 'ALLOW-FROM https://evil.com',
  'x-content-type-options': 'something-wrong',
  'server': 'Apache/2.4.51',
  'x-powered-by': 'Express',
  'set-cookie': 'session=abc123; Path=/',
};

// ====== 测试 ======

describe('headers-engine: 完全安全头', () => {
  it('满分或接近满分 (>=90)，评分为 A', () => {
    const result = analyzeHeaders(SECURE_HEADERS);
    expect(result.score).toBeGreaterThanOrEqual(90);
    expect(result.grade).toBe('A');
    expect(result.passed).toBeGreaterThan(0);
    expect(result.missing).toBe(0);
  });

  it('安全头全部 pass，无 miss', () => {
    const result = analyzeHeaders(SECURE_HEADERS);
    const securityResults = result.results.filter(
      r =>
        r.category === 'security' &&
        r.name !== 'X-Download-Options' &&
        r.name !== 'Content-Security-Policy-Report-Only', // report-only 为建议性，固定 warn
    );
    for (const r of securityResults) {
      expect(r.status).toBe('pass');
    }
  });

  it('CSP 检查结果为 pass', () => {
    const result = analyzeHeaders(SECURE_HEADERS);
    const csp = result.results.find(r => r.name === 'Content-Security-Policy');
    expect(csp).toBeDefined();
    expect(csp!.status).toBe('pass');
  });

  it('HSTS 检查结果为 pass', () => {
    const result = analyzeHeaders(SECURE_HEADERS);
    const hsts = result.results.find(r => r.name === 'Strict-Transport-Security');
    expect(hsts).toBeDefined();
    expect(hsts!.status).toBe('pass');
  });

  it('XFO 检查结果为 pass', () => {
    const result = analyzeHeaders(SECURE_HEADERS);
    const xfo = result.results.find(r => r.name === 'X-Frame-Options');
    expect(xfo).toBeDefined();
    expect(xfo!.status).toBe('pass');
  });
});

describe('headers-engine: 空头 / 全缺失', () => {
  it('低分 (<40)，评级为 F', () => {
    const result = analyzeHeaders(EMPTY_HEADERS);
    expect(result.score).toBeLessThan(40);
    expect(result.grade).toBe('F');
    expect(result.missing).toBeGreaterThan(10);
    // 部分可选头（Clear-Site-Data/X-Robots-Tag 等）未设置时也算 pass，故 passed 不强制为 0
    expect(result.passed).toBeLessThanOrEqual(7);
  });

  it('issues 中包含大量 high/medium 级别', () => {
    const result = analyzeHeaders(EMPTY_HEADERS);
    const highIssues = result.issues.filter(i => i.severity === 'high' || i.severity === 'medium');
    expect(highIssues.length).toBeGreaterThan(5);
  });

  it('CSP 和 HSTS 均缺失', () => {
    const result = analyzeHeaders(EMPTY_HEADERS);
    const csp = result.results.find(r => r.name === 'Content-Security-Policy');
    const hsts = result.results.find(r => r.name === 'Strict-Transport-Security');
    expect(csp!.status).toBe('miss');
    expect(hsts!.status).toBe('miss');
  });

  it('无信息泄露', () => {
    const result = analyzeHeaders(EMPTY_HEADERS);
    expect(result.infoLeaks.length).toBe(0);
    expect(result.serverSignatures.length).toBe(0);
    expect(result.frameworkSignatures.length).toBe(0);
  });
});

describe('headers-engine: 误配置头', () => {
  it('CSP 含 unsafe-inline 和通配符，应为 warn', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    const csp = result.results.find(r => r.name === 'Content-Security-Policy');
    expect(csp!.status).toBe('warn');
    expect(csp!.recommendation).toContain('unsafe-inline');
  });

  it('HSTS max-age 不足 30 天，应为 warn', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    const hsts = result.results.find(r => r.name === 'Strict-Transport-Security');
    expect(hsts!.status).toBe('warn');
    expect(hsts!.recommendation).toContain('max-age');
  });

  it('XFO ALLOW-FROM 为 warn', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    const xfo = result.results.find(r => r.name === 'X-Frame-Options');
    expect(xfo!.status).toBe('warn');
  });

  it('检测到 Server 信息泄露 — Apache', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    expect(result.infoLeaks.length).toBeGreaterThan(0);
    expect(result.infoLeaks.some(l => l.name === 'Server')).toBe(true);
    expect(result.serverSignatures).toContain('apache');
  });

  it('检测到 X-Powered-By 技术栈泄露', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    expect(result.infoLeaks.some(l => l.name === 'X-Powered-By')).toBe(true);
  });

  it('Cookie 不安全 — 缺少 Secure 和 HttpOnly', () => {
    const result = analyzeHeaders(MISCONFIGURED_HEADERS);
    expect(result.cookieFindings.length).toBeGreaterThan(0);
    expect(result.cookieFindings[0].issues).toContain('缺少 Secure');
    expect(result.cookieFindings[0].issues).toContain('缺少 HttpOnly');
  });

  it('分数低于安全头但高于空头', () => {
    const secureResult = analyzeHeaders(SECURE_HEADERS);
    const misResult = analyzeHeaders(MISCONFIGURED_HEADERS);
    const emptyResult = analyzeHeaders(EMPTY_HEADERS);
    expect(secureResult.score).toBeGreaterThan(misResult.score);
    expect(misResult.score).toBeGreaterThan(emptyResult.score);
  });
});

describe('headers-engine: 服务器/框架签名检测', () => {
  it('检测 nginx 服务器签名', () => {
    const result = analyzeHeaders({ server: 'nginx/1.24.0' });
    expect(result.serverSignatures).toContain('nginx');
  });

  it('检测 Express 服务器签名', () => {
    const result = analyzeHeaders({ server: 'Express' });
    expect(result.serverSignatures).toContain('express');
  });

  it('检测 Laravel 框架签名 (来自任意头值)', () => {
    const result = analyzeHeaders({ 'x-powered-by': 'Laravel v10' });
    expect(result.frameworkSignatures).toContain('laravel');
  });

  it('无 Server 头不报签名', () => {
    const result = analyzeHeaders({ 'content-type': 'text/html' });
    expect(result.serverSignatures.length).toBe(0);
  });
});

describe('headers-engine: deepAnalyzeCSP', () => {
  it('null 返回 CSP 完全缺失', () => {
    const result = deepAnalyzeCSP(null);
    expect(result.missingCritical.length).toBeGreaterThan(0);
    expect(result.missingCritical[0].directive).toBe('Content-Security-Policy');
    expect(result.summary).toContain('未设置');
  });

  it('空字符串等同 null', () => {
    const result = deepAnalyzeCSP('');
    expect(result.missingCritical.length).toBeGreaterThan(0);
    expect(result.summary).toContain('未设置');
  });

  it('含 unsafe-inline 产生高危绕过', () => {
    const result = deepAnalyzeCSP("script-src 'unsafe-inline'");
    const hasBypass = result.bypasses.some(b => b.type === 'xss-inline');
    expect(hasBypass).toBe(true);
    expect(result.directives['script-src'].issues).toContain('允许内联脚本执行（unsafe-inline）');
  });

  it('含 unsafe-eval 产生高危绕过', () => {
    const result = deepAnalyzeCSP("script-src 'unsafe-eval'");
    const hasBypass = result.bypasses.some(b => b.type === 'eval-injection');
    expect(hasBypass).toBe(true);
  });

  it('default-src * 产生高危绕过', () => {
    const result = deepAnalyzeCSP('default-src *');
    const hasBypass = result.bypasses.some(b => b.type === 'wildcard-default');
    expect(hasBypass).toBe(true);
  });

  it('connect-src * 产生高危绕过', () => {
    const result = deepAnalyzeCSP('connect-src *');
    const hasBypass = result.bypasses.some(b => b.type === 'data-exfil');
    expect(hasBypass).toBe(true);
  });

  it('缺失 frame-ancestors 记录为 missingCritical', () => {
    const result = deepAnalyzeCSP("default-src 'self'");
    const missing = result.missingCritical.find(m => m.directive === 'frame-ancestors');
    expect(missing).toBeDefined();
  });

  it('缺失 base-uri 记录为 missingCritical', () => {
    const result = deepAnalyzeCSP("default-src 'self'");
    const missing = result.missingCritical.find(m => m.directive === 'base-uri');
    expect(missing).toBeDefined();
  });

  it('完整 CSP 无高危绕过，配置良好', () => {
    const result = deepAnalyzeCSP(
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; style-src 'self'; img-src 'self'; connect-src 'self'; upgrade-insecure-requests",
    );
    const highBypasses = result.bypasses.filter(b => b.severity === 'high');
    expect(highBypasses.length).toBe(0);
    expect(result.summary).toContain('CSP 配置良好');
  });

  it('允许外部域名脚本标记为 medium risk', () => {
    const result = deepAnalyzeCSP("script-src 'self' https://cdn.example.com");
    expect(result.directives['script-src'].issues.some(i => i.includes('外部域名脚本'))).toBe(true);
    expect(result.bypasses.some(b => b.type === 'domain-takeover')).toBe(true);
  });
});

describe('headers-engine: severityLabel', () => {
  it('中文映射正确', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('high')).toBe('高危');
    expect(severityLabel('medium')).toBe('中危');
    expect(severityLabel('low')).toBe('低危');
    expect(severityLabel('info')).toBe('信息');
  });
});

describe('headers-engine: 常量', () => {
  it('SEVERITY_COLOR 包含所有严重级别', () => {
    expect(SEVERITY_COLOR).toHaveProperty('critical');
    expect(SEVERITY_COLOR).toHaveProperty('high');
    expect(SEVERITY_COLOR).toHaveProperty('medium');
    expect(SEVERITY_COLOR).toHaveProperty('low');
    expect(SEVERITY_COLOR).toHaveProperty('info');
  });

  it('STATUS_COLOR 包含 pass/warn/miss', () => {
    expect(STATUS_COLOR).toHaveProperty('pass');
    expect(STATUS_COLOR).toHaveProperty('warn');
    expect(STATUS_COLOR).toHaveProperty('miss');
  });

  it('CATEGORY_LABELS 包含安全防护', () => {
    expect(CATEGORY_LABELS['security']).toBe('安全防护');
    expect(CATEGORY_LABELS['privacy']).toBe('隐私保护');
    expect(CATEGORY_LABELS['cross-origin']).toBe('跨域隔离');
  });

  it('CATEGORY_ORDER 以 security 开头', () => {
    expect(CATEGORY_ORDER[0]).toBe('security');
  });
});

describe('headers-engine: Cookie 分析', () => {
  it('安全 Cookie 不产生发现', () => {
    const result = analyzeHeaders({
      'set-cookie': 'sid=abc; Secure; HttpOnly; SameSite=Strict',
    });
    expect(result.cookieFindings.length).toBe(0);
  });

  it('安全 Cookie（Secure+HttpOnly+SameSite）不产生发现', () => {
    const result = analyzeHeaders({
      'set-cookie': 'safe=1; Secure; HttpOnly; SameSite=Lax',
    });
    expect(result.cookieFindings.length).toBe(0);
  });
});

describe('headers-engine: 单个头检查器边界', () => {
  it('XCTO 非 nosniff 值为 warn', () => {
    const result = analyzeHeaders({ 'x-content-type-options': 'WRONG' });
    const xcto = result.results.find(r => r.name === 'X-Content-Type-Options');
    expect(xcto!.status).toBe('warn');
  });

  it('RP 不安全值 (unsafe-url) 为 warn', () => {
    const result = analyzeHeaders({ 'referrer-policy': 'unsafe-url' });
    const rp = result.results.find(r => r.name === 'Referrer-Policy');
    expect(rp!.status).toBe('warn');
  });

  it('COOP 不安全值 (unsafe-none) 为 warn', () => {
    const result = analyzeHeaders({ 'cross-origin-opener-policy': 'unsafe-none' });
    const coop = result.results.find(r => r.name === 'Cross-Origin-Opener-Policy');
    expect(coop!.status).toBe('warn');
  });

  it('CSP Report-Only 有值时为 warn', () => {
    const result = analyzeHeaders({ 'content-security-policy-report-only': "default-src 'self'" });
    const cspRo = result.results.find(r => r.name === 'Content-Security-Policy-Report-Only');
    expect(cspRo!.status).toBe('warn');
  });

  it('X-XSS-Protection: 0 为 warn', () => {
    const result = analyzeHeaders({ 'x-xss-protection': '0' });
    const xxp = result.results.find(r => r.name === 'X-XSS-Protection');
    expect(xxp!.status).toBe('warn');
  });

  it('Cache-Control max-age=3600 为 warn（非 no-store）', () => {
    const result = analyzeHeaders({ 'cache-control': 'max-age=3600' });
    const cc = result.results.find(r => r.name === 'Cache-Control');
    expect(cc!.status).toBe('warn');
  });
});
