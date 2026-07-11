/**
 * CORS 检测引擎 — 灵眸 v6.0
 * 从 vk-cors.js 提取的纯分析逻辑（不含网络请求与 UI）
 * 网络探测由调用方提供 probeFn，引擎只负责策略与分析
 */

export type CorsSeverity = 'critical' | 'danger' | 'warning' | 'safe' | 'info';

export interface OriginVariant {
  value: string;
  label: string;
}

export interface CorsEndpoint {
  path: string;
  label: string;
}

export interface CorsProbeResponse {
  status?: number;
  type?: string;
  headers?: Record<string, string>;
}

export interface CorsProbeResult {
  endpoint: CorsEndpoint;
  url: string;
  origin: OriginVariant;
  method: string;
  response: CorsProbeResponse;
}

export interface CorsIssue {
  endpoint: CorsEndpoint;
  url: string;
  origin: OriginVariant;
  method: string;
  acao: string;
  acac: string;
  acam: string;
  acah: string;
  acae: string;
  acma: string;
  severity: CorsSeverity;
  findings: string[];
  statusCode: number;
}

export interface CorsAnalysisResult {
  issues: CorsIssue[];
  safeCount: number;
  total: number;
}

/** 默认探测端点 */
export const DEFAULT_CORS_ENDPOINTS: CorsEndpoint[] = [
  { path: '/', label: '根路径' },
  { path: '/api/', label: '/api/' },
  { path: '/api/v1/', label: '/api/v1/' },
  { path: '/graphql', label: '/graphql' },
  { path: '/api/user', label: '/api/user' },
  { path: '/api/config', label: '/api/config' },
];

/** 标准恶意 Origin 变体 */
export const ORIGIN_VARIANTS: OriginVariant[] = [
  { value: 'https://evil.example.com', label: '恶意子域' },
  { value: 'null', label: 'Null Origin' },
  { value: 'https://evil.com', label: '跨域恶意' },
];

/** 基于当前域名构建动态混淆 Origin */
export function buildDynamicOrigins(hostname: string): OriginVariant[] {
  try {
    const parts = hostname.split('.');
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';
    const baseHost = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
    return [
      { value: `https://evil.${baseHost}`, label: `子域名混淆 (evil.${baseHost})` },
      { value: `https://${baseHost}.evil.com`, label: `后缀混淆 (${baseHost}.evil.com)` },
      { value: `https://${hostname.replace(/^www\./, '')}.attacker.com`, label: '去 www 后缀' },
      { value: `https://${tld}.evil.com`, label: `TLD 混淆 (${tld}.evil.com)` },
    ];
  } catch {
    return [];
  }
}

/** 排序函数 */
export const CORS_SORT_FNS: Record<string, (a: CorsIssue, b: CorsIssue) => number> = {
  risk: (a, b) => {
    const order: Record<string, number> = { critical: 0, danger: 1, warning: 2, info: 3, safe: 4 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  },
  url: (a, b) => (a.url || '').localeCompare(b.url || ''),
};

/**
 * 分析 CORS 探测结果 — 核心漏洞判定逻辑
 * 输入是一组探测响应，输出是带严重级别的 issues
 */
export function analyzeResults(results: CorsProbeResult[]): CorsAnalysisResult {
  const issues: CorsIssue[] = [];
  let safeCount = 0;

  for (const r of results) {
    const headers = r.response.headers || {};
    const acao = headers['access-control-allow-origin'] || '';
    const acac = headers['access-control-allow-credentials'] || '';
    const acam = headers['access-control-allow-methods'] || '';
    const acah = headers['access-control-allow-headers'] || '';
    const acae = headers['access-control-expose-headers'] || '';
    const acma = headers['access-control-max-age'] || '';

    let severity: CorsSeverity = 'safe';
    const findings: string[] = [];
    const isOptions = r.method === 'OPTIONS';

    // Opaque response — 服务器未反射 Origin
    if (r.response.type === 'opaque' && !acao) {
      findings.push('服务器未返回 CORS 头 (安全)');
      safeCount++;
      issues.push(buildIssue(r, '', '', '', '', '', '', 'safe', findings));
      continue;
    }

    if (!acao) {
      severity = 'safe';
      findings.push('未设置 Access-Control-Allow-Origin');
      safeCount++;
    } else if (acao === '*') {
      severity = 'warning';
      findings.push('ACAO: * (任意来源可访问)');
      if (acac && acac.toLowerCase() === 'true') {
        severity = 'critical';
        findings.push('Allow-Credentials: true + Origin: * — 浏览器会拒绝此配置');
      }
    } else if (acao === r.origin.value) {
      severity = 'danger';
      findings.push(`Origin 被反射: ${acao}`);
      if (acac && acac.toLowerCase() === 'true') {
        severity = 'critical';
        findings.push('Allow-Credentials: true + Origin 反射 — 可跨站窃取数据');
      }
      if (r.origin.value === 'null') {
        findings.push('Null Origin 被信任 — sandbox/iframe 可利用');
      }
      findings.push('恶意 Origin 被信任，可能导致 CSRF/数据泄露');
    } else {
      severity = 'warning';
      findings.push(`ACAO: ${acao} (非反射)`);
    }

    if (acam && isOptions) findings.push(`预检允许方法: ${acam}`);
    if (acah && isOptions) findings.push(`预检允许头: ${acah}`);
    if (acae) findings.push(`暴露头: ${acae}`);
    if (acma) findings.push(`预检缓存: ${acma}s`);
    if (isOptions && !acam && acao) findings.push('预检响应缺少 Allow-Methods');

    issues.push(buildIssue(r, acao, acac, acam, acah, acae, acma, severity, findings));
  }

  return { issues, safeCount, total: results.length };
}

function buildIssue(
  r: CorsProbeResult,
  acao: string,
  acac: string,
  acam: string,
  acah: string,
  acae: string,
  acma: string,
  severity: CorsSeverity,
  findings: string[]
): CorsIssue {
  return {
    endpoint: r.endpoint,
    url: r.url,
    origin: r.origin,
    method: r.method,
    acao,
    acac,
    acam,
    acah,
    acae,
    acma,
    severity,
    findings,
    statusCode: r.response.status || 0,
  };
}

/** 严重级别 → 中文标签 */
export function severityLabel(sev: CorsSeverity): string {
  const map: Record<CorsSeverity, string> = {
    critical: '严重',
    danger: '危险',
    warning: '警告',
    safe: '安全',
    info: '信息',
  };
  return map[sev] || sev;
}

/** 严重级别 → 统一报告级别 */
export const CORS_SEV_MAP: Record<CorsSeverity, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  critical: 'critical',
  danger: 'high',
  warning: 'medium',
  safe: 'info',
  info: 'info',
};
