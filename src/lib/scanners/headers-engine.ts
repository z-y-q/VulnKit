/**
 * HTTP Security Headers 检测引擎 — 灵眸 v6.0
 * 从 vk-headers.js / vk-headers-checkers.js / vk-headers-render.js 提取的纯分析逻辑
 * 纯函数：不含 browser、fetch、DOM、UI
 */

import data from '../data/headers-data.json';

// ====== 类型 ======

export type HeaderSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HeaderIssue {
  header: string;
  severity: HeaderSeverity;
  message: string;
  recommendation?: string;
}

export interface HeaderCheckResult {
  name: string;
  category: string;
  weight: number;
  status: 'pass' | 'warn' | 'miss';
  value: string | null;
  detail: string;
  recommendation: string;
}

export interface InfoLeak {
  name: string;
  detail: string;
  message: string;
}

export interface CookieFinding {
  name: string;
  issues: string[];
  flags: Record<string, string | boolean>;
}

export interface CspBypass {
  type: string;
  description: string;
  severity: HeaderSeverity;
}

export interface CspDeepAnalysis {
  directives: Record<string, {
    values: string[];
    risk: string;
    issues: string[];
  }>;
  bypasses: CspBypass[];
  missingCritical: {
    directive: string;
    impact: string;
    severity: HeaderSeverity;
  }[];
  summary: string;
}

export interface HeaderAnalysisResult {
  score: number;          // 0-100
  grade: string;          // A-F
  passed: number;
  warning: number;
  missing: number;
  results: HeaderCheckResult[];
  issues: HeaderIssue[];
  infoLeaks: InfoLeak[];
  cookieFindings: CookieFinding[];
  cspDeep: CspDeepAnalysis;
  serverSignatures: string[];
  frameworkSignatures: string[];
}

// ====== CSP 解析与深度分析 ======

function parseCSP(value: string): { directives: Record<string, string[]>; raw: string } {
  if (!value) return { directives: {}, raw: '' };
  const directives: Record<string, string[]> = {};
  const parts = value.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = (tokens[0] || '').toLowerCase();
    const values = tokens.slice(1);
    directives[name] = values;
  }
  return { directives, raw: value };
}

const RISK_ORDER: Record<string, number> = { safe: 0, low: 1, medium: 2, high: 3 };

function analyzeDirectiveValues(
  directives: Record<string, { values: string[]; risk: string; issues: string[] }>,
  name: string,
  values: string[],
  riskIssues: Array<{ check: (v: string[]) => boolean; risk: string; issue: string; bypass?: CspBypass }>,
  addBypass: (type: string, desc: string, severity: HeaderSeverity) => void,
): void {
  const result = { values, risk: 'safe', issues: [] as string[] };
  // Join values into a string for simple checks (some checkers expect string)
  const joined = values.join(' ');
  for (const item of riskIssues) {
    if (item.check(values)) {
      result.issues.push(item.issue);
      if ((RISK_ORDER[item.risk] || 0) > (RISK_ORDER[result.risk] || 0)) {
        result.risk = item.risk;
      }
      if (item.bypass) addBypass(item.bypass.type, item.bypass.description, item.bypass.severity);
    }
  }
  directives[name] = result;
}

function checkScriptDomainSources(
  scriptSrc: string[],
  directives: Record<string, { values: string[]; risk: string; issues: string[] }>,
  addBypass: (type: string, desc: string, severity: HeaderSeverity) => void,
): void {
  const domainValues = scriptSrc.filter(
    v => !v.startsWith("'") && v !== 'data:' && v !== '*' && !v.startsWith('blob:'),
  );
  if (domainValues.length === 0) return;
  if (directives['script-src'].risk === 'safe') directives['script-src'].risk = 'medium';
  directives['script-src'].issues.push('允许加载外部域名脚本: ' + domainValues.join(', '));
  addBypass(
    'domain-takeover',
    `攻陷 ${domainValues[0]} 后可注入恶意脚本到该域名，CSP 自动放行`,
    'medium',
  );
}

function checkMissingDirectives(
  d: Record<string, string[]>,
  addBypass: (type: string, desc: string, severity: HeaderSeverity) => void,
): CspDeepAnalysis['missingCritical'] {
  const missingCritical: CspDeepAnalysis['missingCritical'] = [];
  const checks: Array<{
    directive: string;
    impact: string;
    severity: HeaderSeverity;
    bypassType?: string;
    bypassDesc?: string;
  }> = [
    {
      directive: 'base-uri',
      impact: '缺失 base-uri 允许攻击者注入 <base href="https://evil.com"> 劫持相对路径资源加载',
      severity: 'medium',
      bypassType: 'base-hijack',
      bypassDesc: '注入 <base href="https://evil.com"> 劫持所有相对路径资源',
    },
    {
      directive: 'object-src',
      impact: "缺失 object-src（默认非 'none'）允许加载 Flash/Java applet 等插件",
      severity: 'medium',
    },
    {
      directive: 'form-action',
      impact: '缺失 form-action 允许表单提交到任意 URL（钓鱼攻击）',
      severity: 'medium',
      bypassType: 'form-phish',
      bypassDesc: '表单数据可被引导提交到钓鱼站点',
    },
    {
      directive: 'frame-ancestors',
      impact: '缺失 frame-ancestors 允许页面被 iframe 嵌套（点击劫持）',
      severity: 'medium',
      bypassType: 'clickjack',
      bypassDesc: '页面可被嵌入恶意 iframe 进行点击劫持攻击',
    },
    {
      directive: 'upgrade-insecure-requests',
      impact: '缺失 upgrade-insecure-requests 存在混合内容风险',
      severity: 'low',
    },
  ];
  for (const item of checks) {
    if (!d[item.directive]) {
      missingCritical.push({ directive: item.directive, impact: item.impact, severity: item.severity });
      if (item.bypassType && item.bypassDesc) addBypass(item.bypassType, item.bypassDesc, item.severity);
    }
  }
  return missingCritical;
}

function buildScriptSrcChecks(
  addBypass: (type: string, desc: string, severity: HeaderSeverity) => void,
): Array<{ check: (v: string[]) => boolean; risk: string; issue: string; bypass: CspBypass }> {
  return [
    {
      check: v => v.indexOf("'unsafe-inline'") !== -1,
      risk: 'high',
      issue: '允许内联脚本执行（unsafe-inline）',
      bypass: {
        type: 'xss-inline',
        description: '直接注入 <script>alert(1)</script> 即可执行 XSS',
        severity: 'high',
      },
    },
    {
      check: v => v.indexOf("'unsafe-eval'") !== -1,
      risk: 'high',
      issue: '允许 eval() 执行（unsafe-eval）',
      bypass: {
        type: 'eval-injection',
        description: '通过 eval() / Function() 动态执行任意代码',
        severity: 'high',
      },
    },
    {
      check: v => v.indexOf('data:') !== -1,
      risk: 'medium',
      issue: '允许 data: URI 加载脚本',
      bypass: {
        type: 'data-uri-script',
        description: '通过 <script src="data:text/javascript,..."> 注入脚本',
        severity: 'medium',
      },
    },
  ];
}

function buildOtherDirectiveChecks(): Record<
  string,
  Array<{ check: (v: string[]) => boolean; risk: string; issue: string; bypass: CspBypass }>
> {
  return {
    'default-src': [
      {
        check: v => v.indexOf('*') !== -1,
        risk: 'high',
        issue: '通配符 * 允许任意来源',
        bypass: {
          type: 'wildcard-default',
          description: 'default-src * 几乎使所有 CSP 保护失效',
          severity: 'high',
        },
      },
    ],
    'style-src': [
      {
        check: v => v.indexOf("'unsafe-inline'") !== -1,
        risk: 'low',
        issue: '允许内联样式（CSS 注入可窃取数据）',
        bypass: {
          type: 'css-exfil',
          description: '通过 CSS 注入窃取 CSRF token 等敏感属性值',
          severity: 'low',
        },
      },
    ],
    'img-src': [
      {
        check: v => v.indexOf('*') !== -1 || v.indexOf('data:') !== -1,
        risk: 'low',
        issue: 'img-src 限制宽松（可探测内网）',
        bypass: {
          type: 'ssrf-img',
          description: '通过 <img src="http://192.168.x.x/"> 探测内网服务',
          severity: 'low',
        },
      },
    ],
    'connect-src': [
      {
        check: v => v.indexOf('*') !== -1,
        risk: 'high',
        issue: 'connect-src 允许任意目标（数据外泄）',
        bypass: {
          type: 'data-exfil',
          description: '通过 fetch/WebSocket 将数据发送到任意域名',
          severity: 'high',
        },
      },
    ],
  };
}

export function deepAnalyzeCSP(cspValue: string | null): CspDeepAnalysis {
  if (!cspValue) {
    return {
      directives: {},
      bypasses: [],
      missingCritical: [
        {
          directive: 'Content-Security-Policy',
          impact: '未设置 CSP，页面完全不受内容安全策略保护',
          severity: 'high',
        },
      ],
      summary: '未设置 Content-Security-Policy',
    };
  }

  const parsed = parseCSP(cspValue);
  const d = parsed.directives;
  const fallbackSrc = d['default-src'] ?? [];
  const scriptSrc = d['script-src'] ?? fallbackSrc;
  const styleSrc = d['style-src'] ?? fallbackSrc;
  const imgSrc = d['img-src'] ?? fallbackSrc;
  const connectSrc = d['connect-src'] ?? fallbackSrc;

  const directives: Record<string, { values: string[]; risk: string; issues: string[] }> = {};
  const bypasses: CspBypass[] = [];
  const bypassTypes: Record<string, boolean> = {};

  function addBypass(type: string, description: string, severity: HeaderSeverity) {
    if (!bypassTypes[type]) {
      bypassTypes[type] = true;
      bypasses.push({ type, description, severity });
    }
  }

  analyzeDirectiveValues(directives, 'script-src', scriptSrc, buildScriptSrcChecks(addBypass), addBypass);
  checkScriptDomainSources(scriptSrc, directives, addBypass);

  const otherChecks = buildOtherDirectiveChecks();
  const otherMap: Record<string, string[]> = {
    'default-src': fallbackSrc,
    'style-src': styleSrc,
    'img-src': imgSrc,
    'connect-src': connectSrc,
  };
  for (const name of ['default-src', 'style-src', 'img-src', 'connect-src']) {
    analyzeDirectiveValues(directives, name, otherMap[name], otherChecks[name], addBypass);
  }

  const missingCritical = checkMissingDirectives(d, addBypass);

  // Build summary
  const parts: string[] = [];
  let highCount = 0;
  let medCount = 0;
  for (const bp of bypasses) {
    if (bp.severity === 'high') highCount++;
    else if (bp.severity === 'medium') medCount++;
  }
  if (highCount > 0) parts.push(`高危绕过 ${highCount} 项`);
  if (medCount > 0) parts.push(`中危绕过 ${medCount} 项`);
  if (missingCritical.length > 0) parts.push(`缺失指令 ${missingCritical.length} 项`);
  if (parts.length === 0) parts.push('CSP 配置良好');

  return { directives, bypasses, missingCritical, summary: parts.join('，') };
}

// ====== 各安全头检查器 ======

type CheckerFn = (value: string | null) => { status: 'pass' | 'warn' | 'miss'; detail: string; recommendation: string };

function checkCSP(value: string | null) {
  if (!value)
    return {
      status: 'miss' as const,
      detail: '未设置',
      recommendation: '添加 Content-Security-Policy 头，限制资源加载来源',
    };
  const issues: string[] = [];
  const csp = parseCSP(value);
  const d = csp.directives;

  if (!d['default-src'] && !d['script-src']) issues.push('缺少 default-src 和 script-src');

  const defaultSrc = d['default-src'] || [];
  if (defaultSrc.indexOf('*') !== -1) issues.push('default-src 使用通配符 *');
  if (defaultSrc.indexOf("'none'") === -1 && defaultSrc.length === 0 && !d['script-src'])
    issues.push('default-src 未限制');

  const scriptSrc = d['script-src'] || [];
  if (scriptSrc.indexOf("'unsafe-inline'") !== -1) issues.push('script-src 包含 unsafe-inline（允许内联脚本）');
  if (scriptSrc.indexOf("'unsafe-eval'") !== -1) issues.push('script-src 包含 unsafe-eval（允许 eval）');
  if (scriptSrc.indexOf('data:') !== -1) issues.push('script-src 允许 data: URI');

  const styleSrc = d['style-src'] || defaultSrc;
  if (styleSrc.indexOf("'unsafe-inline'") !== -1) issues.push('style-src 包含 unsafe-inline');

  const imgSrc = d['img-src'] || defaultSrc;
  if (imgSrc.indexOf('data:') !== -1) issues.push('img-src 允许 data: URI');

  const connectSrc = d['connect-src'] || [];
  if (connectSrc.indexOf('*') !== -1) issues.push('connect-src 使用通配符');

  if (!d['frame-ancestors']) issues.push('缺少 frame-ancestors（防止点击劫持）');
  if (!d['form-action']) issues.push('缺少 form-action（防止表单劫持）');

  if (issues.length > 0)
    return { status: 'warn' as const, detail: value.substring(0, 200), recommendation: '移除或修复: ' + issues.join('；') };
  return { status: 'pass' as const, detail: value.substring(0, 200), recommendation: '' };
}

function checkHSTS(value: string | null) {
  if (!value)
    return {
      status: 'miss' as const,
      detail: '未设置',
      recommendation: '添加 Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    };
  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const issues: string[] = [];
  if (maxAge < 2592000) issues.push(`max-age 不足 30 天（当前 ${maxAge}s）`);
  if (value.indexOf('includeSubDomains') === -1) issues.push('缺少 includeSubDomains');
  if (value.indexOf('preload') === -1) issues.push('未加入 HSTS Preload');
  if (issues.length > 0)
    return { status: 'warn' as const, detail: value.substring(0, 200), recommendation: issues.join('；') };
  return { status: 'pass' as const, detail: value.substring(0, 200), recommendation: '' };
}

function checkXFO(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 X-Frame-Options: DENY 或 SAMEORIGIN 防止点击劫持' };
  const upper = value.toUpperCase().trim();
  if (upper === 'DENY' || upper === 'SAMEORIGIN')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议使用 DENY 或 SAMEORIGIN' };
}

function checkXCTO(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 X-Content-Type-Options: nosniff 防止 MIME 嗅探' };
  if (value.toLowerCase().trim() === 'nosniff')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '应为 nosniff' };
}

function checkXXP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置（现代浏览器已弃用，建议用 CSP 替代）', recommendation: 'X-XSS-Protection 已被现代浏览器弃用，请使用 CSP 替代' };
  if (value.indexOf('0') === 0)
    return { status: 'warn' as const, detail: value, recommendation: '已禁用 XSS 过滤器，请确保有 CSP 保护' };
  return { status: 'pass' as const, detail: value, recommendation: '注意：该头已被现代浏览器弃用' };
}

function checkRP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Referrer-Policy: strict-origin-when-cross-origin' };
  const lower = value.toLowerCase().trim();
  const safeValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
  if (safeValues.indexOf(lower) !== -1)
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议使用 strict-origin-when-cross-origin 或 no-referrer' };
}

function checkPP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Permissions-Policy 限制浏览器功能（geolocation, camera, microphone 等）' };
  return { status: 'pass' as const, detail: value.substring(0, 200), recommendation: '' };
}

function checkCOOP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Cross-Origin-Opener-Policy: same-origin 防止 window.opener 泄露' };
  const lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-origin-allow-popups')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议使用 same-origin' };
}

function checkCORP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Cross-Origin-Resource-Policy: same-origin 防止跨域资源泄露' };
  const lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-site')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议使用 same-origin' };
}

function checkCOEP(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Cross-Origin-Embedder-Policy: require-corp 防止跨域嵌入攻击' };
  const lower = value.toLowerCase().trim();
  if (lower === 'require-corp' || lower === 'credentialless')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议使用 require-corp' };
}

function checkCC(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置', recommendation: '添加 Cache-Control: no-store 或 no-cache 防止敏感页面缓存' };
  const lower = value.toLowerCase();
  if (lower.indexOf('no-store') !== -1) return { status: 'pass' as const, detail: value, recommendation: '' };
  if (lower.indexOf('no-cache') !== -1 || lower.indexOf('private') !== -1) return { status: 'pass' as const, detail: value, recommendation: '' };
  if (lower.indexOf('max-age=0') !== -1) return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '建议添加 no-store 或 no-cache' };
}

function checkPragma(value: string | null) {
  if (!value)
    return { status: 'miss' as const, detail: '未设置（HTTP/1.0 兼容头）', recommendation: '添加 Pragma: no-cache 以兼容 HTTP/1.0 缓存控制' };
  if (value.toLowerCase().trim() === 'no-cache')
    return { status: 'pass' as const, detail: value, recommendation: '' };
  return { status: 'warn' as const, detail: value, recommendation: '应为 no-cache' };
}

function checkCSPReportOnly(value: string | null) {
  if (!value) return { status: 'pass' as const, detail: '未设置', recommendation: '' };
  return {
    status: 'warn' as const,
    detail: value.substring(0, 200),
    recommendation: '检测到 CSP Report-Only 模式 — 策略违规不会被阻止，仅上报。生产环境应使用 Content-Security-Policy',
  };
}

function checkClearSiteData(value: string | null) {
  if (!value)
    return { status: 'pass' as const, detail: '未设置', recommendation: '敏感应用可考虑添加 Clear-Site-Data 控制客户端数据清除' };
  return { status: 'pass' as const, detail: value, recommendation: '' };
}

function checkXRobots(value: string | null) {
  if (!value) return { status: 'pass' as const, detail: '未设置', recommendation: '' };
  return { status: 'pass' as const, detail: value, recommendation: '' };
}

function checkXPCD(value: string | null) {
  if (!value) return { status: 'pass' as const, detail: '未设置', recommendation: '' };
  return { status: 'pass' as const, detail: value, recommendation: '' };
}

function checkReportTo(value: string | null) {
  if (!value) return { status: 'pass' as const, detail: '未设置', recommendation: '' };
  return { status: 'pass' as const, detail: value.substring(0, 100), recommendation: '' };
}

function checkNEL(value: string | null) {
  if (!value) return { status: 'pass' as const, detail: '未设置', recommendation: '' };
  return { status: 'pass' as const, detail: value.substring(0, 100), recommendation: '' };
}

// ====== 检查器映射表 ======

const HEADER_CHECKERS: Record<string, CheckerFn | undefined> = {
  'Content-Security-Policy': checkCSP,
  'Strict-Transport-Security': checkHSTS,
  'X-Frame-Options': checkXFO,
  'X-Content-Type-Options': checkXCTO,
  'X-XSS-Protection': checkXXP,
  'Referrer-Policy': checkRP,
  'Permissions-Policy': checkPP,
  'Cross-Origin-Opener-Policy': checkCOOP,
  'Cross-Origin-Resource-Policy': checkCORP,
  'Cross-Origin-Embedder-Policy': checkCOEP,
  'Cache-Control': checkCC,
  'Pragma': checkPragma,
  'Content-Security-Policy-Report-Only': checkCSPReportOnly,
  'Clear-Site-Data': checkClearSiteData,
  'X-Robots-Tag': checkXRobots,
  'X-Permitted-Cross-Domain-Policies': checkXPCD,
  'X-Download-Options': checkXPCD,
  'Report-To': checkReportTo,
  'NEL': checkNEL,
};

// ====== 信息泄露检测 ======

function detectInfoLeaks(headers: Record<string, string>): InfoLeak[] {
  const leaks: InfoLeak[] = [];
  const serverVal = headers['server'] || '';
  const signatures: string[] = data.SERVER_SIGNATURES;

  if (serverVal) {
    const serverLower = serverVal.toLowerCase();
    const detected = signatures.filter(s => serverLower.indexOf(s) !== -1);
    if (detected.length > 0) {
      leaks.push({ name: 'Server', detail: serverVal, message: '服务器信息泄露: ' + detected.join(', ') });
    }
  }

  const poweredBy = headers['x-powered-by'] || '';
  if (poweredBy) {
    leaks.push({ name: 'X-Powered-By', detail: poweredBy, message: '技术栈泄露: ' + poweredBy });
  }

  const xAspNet = headers['x-aspnet-version'] || '';
  if (xAspNet) {
    leaks.push({ name: 'X-AspNet-Version', detail: xAspNet, message: 'ASP.NET 版本泄露' });
  }

  const xGenerator = headers['x-generator'] || '';
  if (xGenerator) {
    leaks.push({ name: 'X-Generator', detail: xGenerator, message: 'CMS/框架信息泄露: ' + xGenerator });
  }

  return leaks;
}

// ====== 服务器/框架指纹识别 ======

function detectSignatures(headers: Record<string, string>): { server: string[]; framework: string[] } {
  const serverSignatures: string[] = [];
  const frameworkSignatures: string[] = [];

  const serverVal = (headers['server'] || '').toLowerCase();
  for (const sig of data.SERVER_SIGNATURES) {
    if (serverVal.indexOf(sig) !== -1) serverSignatures.push(sig);
  }

  // 检查多个可能暴露框架的头
  const headerValues = Object.values(headers).join(' ').toLowerCase();
  for (const sig of data.FRAMEWORK_SIGNATURES) {
    if (headerValues.indexOf(sig) !== -1) frameworkSignatures.push(sig);
  }

  return { server: serverSignatures, framework: frameworkSignatures };
}

// ====== Cookie 安全分析 ======

function parseSetCookies(headers: Record<string, string>): Array<{ name: string; flags: Record<string, string | boolean> }> {
  const raw = headers['set-cookie'];
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list.map(str => parseOneCookie(str));
}

function parseOneCookie(str: string) {
  const parts = str.split(';');
  const nameVal = (parts[0] || '').trim();
  const eqIdx = nameVal.indexOf('=');
  const name = eqIdx !== -1 ? nameVal.substring(0, eqIdx).trim() : nameVal;
  const flags: Record<string, string | boolean> = {};
  for (let i = 1; i < parts.length; i++) {
    const flag = parts[i].trim().toLowerCase();
    if (flag.indexOf('secure') === 0) flags.secure = true;
    else if (flag.indexOf('httponly') === 0) flags.httponly = true;
    else if (flag.indexOf('samesite=') === 0) flags.samesite = flag.substring(9).trim();
  }
  return { name, flags };
}

function analyzeCookieSecurity(
  setCookies: Array<{ name: string; flags: Record<string, string | boolean> }>,
): CookieFinding[] {
  if (setCookies.length === 0) return [];
  const findings: CookieFinding[] = [];
  for (const cookie of setCookies) {
    const name = cookie.name || '';
    const flags = cookie.flags;
    const issues: string[] = [];
    if (!flags.secure) issues.push('缺少 Secure');
    if (!flags.httponly) issues.push('缺少 HttpOnly');
    if (!flags.samesite || flags.samesite === 'none') {
      if (!flags.secure) issues.push('SameSite=None 但无 Secure');
      else issues.push('SameSite=None（跨站可访问）');
    }
    if (issues.length > 0) {
      findings.push({ name, issues, flags });
    }
  }
  return findings;
}

// ====== 严重级别工具 ======

export function severityLabel(sev: HeaderSeverity): string {
  const map: Record<HeaderSeverity, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  };
  return map[sev] || sev;
}

export const SEVERITY_COLOR: Record<HeaderSeverity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-red-500 text-white',
  medium: 'bg-yellow-500 text-white',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-400 text-white',
};

/** 状态 → CSS 颜色类 */
export const STATUS_COLOR: Record<string, string> = {
  pass: 'text-green-600 dark:text-green-400',
  warn: 'text-yellow-600 dark:text-yellow-400',
  miss: 'text-red-500 dark:text-red-400',
};

/** 分类 → 中文标签 */
export const CATEGORY_LABELS: Record<string, string> = {
  security: '安全防护',
  privacy: '隐私保护',
  'cross-origin': '跨域隔离',
  caching: '缓存控制',
  legacy: '传统兼容',
  monitoring: '监控上报',
};

/** 分类显示排序 */
export const CATEGORY_ORDER = ['security', 'privacy', 'cross-origin', 'caching', 'legacy', 'monitoring'];

// ====== 核心分析函数 ======

/**
 * 分析 HTTP 安全响应头 — 主入口
 * 输入：headers 键值对（key 全小写）
 * 输出：带评分、缺失头、误配置、泄露、签名等的完整分析结果
 */
export function analyzeHeaders(headers: Record<string, string>): HeaderAnalysisResult {
  const SECURITY_HEADERS = data.SECURITY_HEADERS;
  let totalWeight = 0;
  let earnedWeight = 0;
  let passedCount = 0;
  let warnCount = 0;
  let missCount = 0;
  const results: HeaderCheckResult[] = [];

  for (const rule of SECURITY_HEADERS) {
    totalWeight += rule.weight;
    const headerValue = headers[rule.name.toLowerCase()] || null;
    const checker = HEADER_CHECKERS[rule.name];
    const checkResult = checker
      ? checker(headerValue)
      : headerValue !== null
        ? { status: 'pass' as const, detail: headerValue.substring(0, 200), recommendation: '' }
        : { status: 'miss' as const, detail: '未设置', recommendation: '' };

    if (checkResult.status === 'pass') {
      earnedWeight += rule.weight;
      passedCount++;
    } else if (checkResult.status === 'warn') {
      earnedWeight += rule.weight * 0.5;
      warnCount++;
    } else {
      missCount++;
    }

    results.push({
      name: rule.name,
      category: rule.category,
      weight: rule.weight,
      status: checkResult.status,
      value: headerValue,
      detail: checkResult.detail,
      recommendation: checkResult.recommendation,
    });
  }

  const score = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  let grade: string;
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  // 信息泄露
  const infoLeaks = detectInfoLeaks(headers);

  // 服务器/框架签名
  const sigs = detectSignatures(headers);

  // Cookie 安全
  const setCookies = parseSetCookies(headers);
  const cookieFindings = analyzeCookieSecurity(setCookies);

  // CSP 深度分析
  const cspDeep = deepAnalyzeCSP(headers['content-security-policy'] || null);

  // 汇总所有 issues
  const issues = buildIssues(results, infoLeaks, cookieFindings, cspDeep);

  return {
    score,
    grade,
    passed: passedCount,
    warning: warnCount,
    missing: missCount,
    results,
    issues,
    infoLeaks,
    cookieFindings,
    cspDeep,
    serverSignatures: sigs.server,
    frameworkSignatures: sigs.framework,
  };
}

// ====== 问题汇总 ======

function buildIssues(
  results: HeaderCheckResult[],
  infoLeaks: InfoLeak[],
  cookieFindings: CookieFinding[],
  cspDeep: CspDeepAnalysis,
): HeaderIssue[] {
  const issues: HeaderIssue[] = [];

  for (const r of results) {
    if (r.status === 'pass') continue;
    let severity: HeaderSeverity;
    if (r.status === 'miss') {
      severity = r.weight >= 7 ? 'high' : r.weight >= 4 ? 'medium' : 'low';
    } else {
      severity = 'low';
    }
    issues.push({
      header: r.name,
      severity,
      message: `安全头 ${r.status === 'miss' ? '缺失' : '警告'}: ${r.detail}`,
      recommendation: r.recommendation || undefined,
    });
  }

  for (const leak of infoLeaks) {
    issues.push({
      header: leak.name,
      severity: 'medium',
      message: `信息泄露: ${leak.message}`,
    });
  }

  for (const cf of cookieFindings) {
    issues.push({
      header: cf.name,
      severity: 'medium',
      message: `Cookie 不安全: ${cf.issues.join('；')}`,
    });
  }

  if (cspDeep.bypasses) {
    for (const bp of cspDeep.bypasses) {
      issues.push({
        header: 'Content-Security-Policy',
        severity: bp.severity,
        message: `CSP 绕过: ${bp.type}`,
        recommendation: bp.description,
      });
    }
  }

  if (cspDeep.missingCritical) {
    for (const mc of cspDeep.missingCritical) {
      issues.push({
        header: 'Content-Security-Policy',
        severity: mc.severity,
        message: `CSP 缺失指令: ${mc.directive}`,
        recommendation: mc.impact,
      });
    }
  }

  // 按严重程度排序
  const order: Record<HeaderSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  issues.sort((a, b) => (order[b.severity] ?? 0) - (order[a.severity] ?? 0));

  return issues;
}
