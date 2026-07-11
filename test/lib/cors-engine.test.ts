import { describe, it, expect } from 'vitest';
import {
  analyzeResults,
  buildDynamicOrigins,
  severityLabel,
  CORS_SORT_FNS,
  ORIGIN_VARIANTS,
  DEFAULT_CORS_ENDPOINTS,
  type CorsProbeResult,
} from '@/lib/scanners/cors-engine';

describe('cors-engine: buildDynamicOrigins', () => {
  it('为标准域名构建混淆 origin', () => {
    const origins = buildDynamicOrigins('www.example.com');
    expect(origins.length).toBe(4);
    expect(origins.some(o => o.value.includes('evil.example.com'))).toBe(true);
    expect(origins.some(o => o.value.includes('example.com.evil.com'))).toBe(true);
  });

  it('处理短域名不抛错', () => {
    const origins = buildDynamicOrigins('localhost');
    expect(origins).toBeDefined();
  });
});

describe('cors-engine: analyzeResults', () => {
  const makeResult = (
    headers: Record<string, string>,
    origin: string,
    status = 200,
    method = 'GET'
  ): CorsProbeResult => ({
    endpoint: { path: '/api/', label: '/api/' },
    url: 'https://target.com/api/',
    origin: { value: origin, label: origin },
    method,
    response: { status, headers },
  });

  it('ACAO 反射 + 凭证 = critical', () => {
    const results = [
      makeResult(
        { 'access-control-allow-origin': 'https://evil.com', 'access-control-allow-credentials': 'true' },
        'https://evil.com'
      ),
    ];
    const { issues } = analyzeResults(results);
    expect(issues[0].severity).toBe('critical');
    expect(issues[0].findings.some(f => f.includes('Origin 反射'))).toBe(true);
  });

  it('ACAO: * = warning', () => {
    const results = [makeResult({ 'access-control-allow-origin': '*' }, 'https://evil.com')];
    const { issues } = analyzeResults(results);
    expect(issues[0].severity).toBe('warning');
  });

  it('ACAO: * + 凭证 = critical（浏览器拒绝配置）', () => {
    const results = [
      makeResult(
        { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' },
        'null'
      ),
    ];
    const { issues } = analyzeResults(results);
    expect(issues[0].severity).toBe('critical');
  });

  it('无 ACAO = safe', () => {
    const results = [makeResult({}, 'https://evil.com')];
    const { issues, safeCount } = analyzeResults(results);
    expect(issues[0].severity).toBe('safe');
    expect(safeCount).toBe(1);
  });

  it('Null Origin 反射标记为可利用', () => {
    const results = [makeResult({ 'access-control-allow-origin': 'null' }, 'null')];
    const { issues } = analyzeResults(results);
    expect(issues[0].severity).toBe('danger');
    expect(issues[0].findings.some(f => f.includes('Null Origin'))).toBe(true);
  });

  it('opaque 响应无头 = safe', () => {
    const results: CorsProbeResult[] = [
      {
        endpoint: { path: '/', label: '/' },
        url: 'https://target.com/',
        origin: { value: 'https://evil.com', label: 'evil' },
        method: 'GET',
        response: { status: 0, type: 'opaque', headers: {} },
      },
    ];
    const { issues, safeCount } = analyzeResults(results);
    expect(issues[0].severity).toBe('safe');
    expect(safeCount).toBe(1);
  });

  it('OPTIONS 预检响应记录允许方法', () => {
    const results = [
      makeResult(
        {
          'access-control-allow-origin': 'https://evil.com',
          'access-control-allow-methods': 'GET, POST, DELETE',
        },
        'https://evil.com',
        200,
        'OPTIONS'
      ),
    ];
    const { issues } = analyzeResults(results);
    expect(issues[0].findings.some(f => f.includes('GET, POST, DELETE'))).toBe(true);
  });
});

describe('cors-engine: 辅助函数', () => {
  it('severityLabel 中文映射', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('safe')).toBe('安全');
    expect(severityLabel('danger')).toBe('危险');
  });

  it('CORS_SORT_FNS.risk 按严重度排序', () => {
    const issues = [
      { severity: 'safe', url: 'a' },
      { severity: 'critical', url: 'b' },
      { severity: 'warning', url: 'c' },
    ] as any;
    const sorted = [...issues].sort(CORS_SORT_FNS.risk);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[2].severity).toBe('safe');
  });

  it('ORIGIN_VARIANTS 包含 null origin', () => {
    expect(ORIGIN_VARIANTS.some(o => o.value === 'null')).toBe(true);
  });

  it('DEFAULT_CORS_ENDPOINTS 包含 graphql', () => {
    expect(DEFAULT_CORS_ENDPOINTS.some(e => e.path === '/graphql')).toBe(true);
  });
});
