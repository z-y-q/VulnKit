/**
 * XSS 检测引擎 — 灵眸 v6.0
 * 从 vk-xss.js / vk-xss-verify.js / vk-xss-autofuzz.js 提取的纯分析逻辑
 * 不含 browser / fetch / DOM 操作；网络探测由调用方提供
 */

import data from '../data/xss-data.json';

// ====== 类型 ======

export type XssContext = 'html' | 'attr' | 'script' | 'url' | 'style';

export type XssSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface XssFinding {
  param: string;
  payload: string;
  context: XssContext;
  reflected: boolean;
  sanitized: boolean;
  severity: XssSeverity;
  evidence?: string;
}

// ====== 常量 ======

/** 唯一金丝雀字符串，用于检测反射 */
export const XSS_MARKERS: string[] = [
  'vkxssprobe1<>',
  'vkxssprobe2"\'>',
  'vkxssprobe3;/${',
];

/** 通用反射探针 */
export const REFLECTION_PROBE = "vkxss'\\\"><xyz";

/** 严重级别排序权重（越小越严重） */
export const SEVERITY_ORDER: Record<XssSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ====== JSON 数据访问 ======

type PayloadEntry = { name: string; value: string };
type RegexDef = { __regexp__: true; source: string; flags: string };

const XSS_SCAN_PAYLOADS = (data.XSS_SCAN_PAYLOADS ?? []) as PayloadEntry[];
const CONTEXT_PAYLOADS = (data.CONTEXT_PAYLOADS ?? {}) as Record<string, string[]>;
const SINK_PATTERNS = (data.SINK_PATTERNS ?? []) as Array<{
  context: string;
  regex: RegexDef;
  severity: string;
}>;
const SANITIZER_PATTERNS = (data.SANITIZER_PATTERNS ?? []) as Array<{
  name: string;
  regex: RegexDef;
  reduction: number;
}>;

// ====== 上下文检测 ======

/**
 * 从反射点周围的字符猜测注入上下文
 * 参考原 vk-xss-verify.js analyzeReflectionContext
 */
export function detectContext(surrounding: string): XssContext {
  const before = surrounding.slice(0, 60);
  const after = surrounding.slice(-60);

  // script 标签内
  if (/<script[^>]*>[\s\S]*$/i.test(before) && /^[\s\S]*<\/script>/i.test(after)) {
    return 'script';
  }

  // URL / href / src / action 属性值
  if (/\b(?:href|src|action|formaction)\s*=\s*(?:["'][^"']*)?$/i.test(before)) {
    return 'url';
  }

  // style 属性
  if (/\bstyle\s*=\s*(?:["'][^"']*)?$/i.test(before)) {
    return 'style';
  }

  // 属性值内（引号未闭合）
  if (/["'][^"'>]*$/i.test(before)) {
    return 'attr';
  }

  // HTML 标签内（属性区域）
  if (/<\w+[^>]*$/i.test(before)) {
    return 'attr';
  }

  // 默认 HTML 文本上下文
  return 'html';
}

// ====== Payload 选择 ======

/**
 * 根据上下文选择合适的 payload
 * 从 XSS_SCAN_PAYLOADS 和 CONTEXT_PAYLOADS 中挑选
 */
export function buildPayloadsForContext(ctx: XssContext): string[] {
  const payloads: string[] = [];

  // 从 SCAN_PAYLOADS 中挑选通用 payload
  for (const p of XSS_SCAN_PAYLOADS) {
    payloads.push(p.value);
  }

  // 根据上下文添加针对性 payload（来自 JSON CONTEXT_PAYLOADS）
  const ctxMap: Record<XssContext, string[]> = {
    html: [
      ...((CONTEXT_PAYLOADS['innerHTML'] ?? []) as string[]),
      ...((CONTEXT_PAYLOADS['outerHTML'] ?? []) as string[]),
      ...((CONTEXT_PAYLOADS['documentWrite'] ?? []) as string[]),
      ...((CONTEXT_PAYLOADS['insertAdjacentHTML'] ?? []) as string[]),
    ],
    attr: (CONTEXT_PAYLOADS['attribute'] ?? []) as string[],
    script: [
      ...((CONTEXT_PAYLOADS['eval'] ?? []) as string[]),
      ...((CONTEXT_PAYLOADS['script-src'] ?? []) as string[]),
    ],
    url: (CONTEXT_PAYLOADS['url'] ?? []) as string[],
    style: [],
  };

  const ctxPayloads = ctxMap[ctx] ?? [];
  for (const p of ctxPayloads) {
    if (!payloads.includes(p)) {
      payloads.push(p);
    }
  }

  return payloads;
}

// ====== 反射检测 ======

/** HTML 实体解码 */
function htmlDecode(str: string): string {
  if (!str) return '';
  return str
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/&#39;/g, "'")
    .replace(/&#47;/g, '/')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)));
}

/**
 * 判断 payload 是否在响应体中出现（含编码变体）
 * 参考原 vk-xss-verify.js isReflected
 */
export function findReflection(
  body: string,
  marker: string,
): { found: boolean; context: XssContext; surrounding?: string } {
  if (!body || !marker) {
    return { found: false, context: 'html' };
  }

  // 精确匹配
  let idx = body.indexOf(marker);
  if (idx !== -1) {
    const start = Math.max(0, idx - 60);
    const end = Math.min(body.length, idx + marker.length + 60);
    const surrounding = body.substring(start, end);
    return { found: true, context: detectContext(surrounding), surrounding };
  }

  // HTML 实体解码后匹配
  const decoded = htmlDecode(body);
  if (decoded !== body) {
    idx = decoded.indexOf(marker);
    if (idx !== -1) {
      const start = Math.max(0, idx - 60);
      const end = Math.min(decoded.length, idx + marker.length + 60);
      const surrounding = decoded.substring(start, end);
      return { found: true, context: detectContext(surrounding), surrounding };
    }
  }

  // URI 解码后匹配
  try {
    const uriDecoded = decodeURIComponent(body);
    if (uriDecoded !== body) {
      idx = uriDecoded.indexOf(marker);
      if (idx !== -1) {
        const start = Math.max(0, idx - 60);
        const end = Math.min(uriDecoded.length, idx + marker.length + 60);
        const surrounding = uriDecoded.substring(start, end);
        return { found: true, context: detectContext(surrounding), surrounding };
      }
    }
  } catch {
    // ignore URIError
  }

  // 去空白匹配
  const stripped = body.replace(/\s+/g, '');
  const markerStripped = marker.replace(/\s+/g, '');
  if (stripped.indexOf(markerStripped) !== -1) {
    return { found: true, context: 'html', surrounding: '' };
  }

  const decStripped = decoded.replace(/\s+/g, '');
  if (decStripped !== stripped && decStripped.indexOf(markerStripped) !== -1) {
    return { found: true, context: 'html', surrounding: '' };
  }

  return { found: false, context: 'html' };
}

// ====== 净化检测 ======

/**
 * 检查响应体中是否存在安全净化器模式
 * 如果存在，说明输入可能已被过滤/转义
 */
export function isSanitized(body: string, payload: string): boolean {
  if (!body) return false;

  for (const sp of SANITIZER_PATTERNS) {
    try {
      const re = new RegExp(sp.regex.source, sp.regex.flags);
      if (re.test(body)) {
        // 高 reduction 值的净化器意味着更强的保护
        if (sp.reduction >= 3) return true;
        // 低 reduction 净化器也检测，但不一定是完全安全
        if (sp.reduction >= 1) {
          // 检查 payload 是否仍被反射（如果净化器存在但 payload 仍反射，可能是绕过）
          if (!body.includes(payload) && !htmlDecode(body).includes(payload)) {
            return true;
          }
        }
      }
    } catch {
      // ignore invalid regex
    }
  }

  return false;
}

// ====== 严重性评估 ======

/**
 * 根据反射上下文评估严重性
 * 参考原 vk-xss-autofuzz.js scoreFinding
 */
export function assessSeverity(
  context: XssContext,
  reflected: boolean,
  sanitized: boolean,
): XssSeverity {
  if (!reflected) return 'info';
  if (sanitized) return 'low';

  switch (context) {
    case 'script':
      return 'critical';
    case 'html':
      return 'high';
    case 'attr':
      return 'high';
    case 'url':
      return 'medium';
    case 'style':
      return 'medium';
    default:
      return 'info';
  }
}

// ====== 严重性标签 ======

const SEVERITY_LABELS: Record<XssSeverity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

/**
 * 严重级别 → 中文标签
 */
export function severityLabel(sev: XssSeverity): string {
  return SEVERITY_LABELS[sev] ?? sev;
}

// ====== Sink 分析（DOM XSS 静态检测）======

export interface SinkMatch {
  code: string;
  source: string;
  contexts: string[];
  severity: XssSeverity;
  score: number;
  sanitizers: string[];
}

/**
 * 对单行代码执行 sink 模式匹配
 * 参考原 vk-xss-sinks.js analyzeSingleSink
 */
export function analyzeSinkLine(
  code: string,
  source = 'inline',
): SinkMatch | null {
  const matchedPatterns: Array<{ context: string; severity: string }> = [];

  for (const sp of SINK_PATTERNS) {
    try {
      const re = new RegExp(sp.regex.source, sp.regex.flags);
      const matches = code.match(re);
      if (matches && matches.length > 0) {
        matchedPatterns.push({ context: sp.context, severity: sp.severity });
      }
    } catch {
      // ignore invalid regex
    }
  }

  if (matchedPatterns.length === 0) return null;

  // 检测净化器
  const sanitizers: string[] = [];
  let totalReduction = 0;
  for (const sp of SANITIZER_PATTERNS) {
    try {
      const re = new RegExp(sp.regex.source, sp.regex.flags);
      if (re.test(code)) {
        sanitizers.push(sp.name);
        totalReduction += sp.reduction;
      }
    } catch {
      // ignore
    }
  }

  // 评分
  let baseScore = 8;
  const hasCritical = matchedPatterns.some(m => m.severity === 'critical');
  const hasHigh = matchedPatterns.some(m => m.severity === 'high');
  if (hasCritical) baseScore = 9;
  else if (hasHigh) baseScore = 7;
  else baseScore = 5;

  baseScore -= totalReduction;
  if (matchedPatterns.length > 2) baseScore += 1;
  if (source === 'event-attr') baseScore += 1;
  if (source === 'js-href') baseScore += 2;

  baseScore = Math.max(1, Math.min(10, baseScore));

  let severity: XssSeverity;
  if (baseScore >= 8) severity = 'critical';
  else if (baseScore >= 6) severity = 'high';
  else if (baseScore >= 4) severity = 'medium';
  else severity = 'low';

  const contexts = [...new Set(matchedPatterns.map(m => m.context))];

  return {
    code,
    source,
    contexts,
    severity,
    score: baseScore,
    sanitizers,
  };
}

// ====== 排序工具 ======

export const XSS_SORT_FNS: Record<string, (a: XssFinding, b: XssFinding) => number> = {
  severity: (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
  param: (a, b) => a.param.localeCompare(b.param),
  context: (a, b) => a.context.localeCompare(b.context),
};
