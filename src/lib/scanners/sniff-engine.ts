/**
 * 网站嗅探引擎 — 灵眸 v6.0
 * 技术指纹匹配纯分析逻辑（不含网络请求与 UI）
 * 从 vk-sniff-scanner.js 提取的核心引擎
 */

import TECH_SIGNATURES from '@/lib/data/sniff-tech-signatures.json';

// ====== 类型定义 ======

export interface SniffInput {
  html: string;
  headers: Record<string, string>;
  scriptSrcs: string[];
  cookies: Record<string, string>;
  meta: { name: string; content: string }[];
}

interface SerializedMatcher {
  source: 'headers' | 'meta' | 'body' | 'scriptSrc' | 'cookies' | 'globals' | 'classNames' | 'ids';
  type: 'regex' | 'string' | 'equals' | 'contains';
  value: string | { __regexp__: true; source: string; flags: string };
}

interface TechSignature {
  name: string;
  category: string;
  matchers: SerializedMatcher[];
}

export interface SniffMatch {
  name: string;
  category: string;
  evidences: SniffEvidence[];
  matchedCount: number;
}

export interface SniffEvidence {
  source: string;
  evidence: string;
}

// ====== 分类标签与排序 ======

export const CATEGORY_LABELS: Record<string, string> = {
  CMS: 'CMS',
  框架: '框架',
  'JS 框架': 'JS 框架',
  'UI 框架': 'UI 框架',
  'JS 库': 'JS 库',
  'Web 服务器': 'Web 服务器',
  CDN: 'CDN',
  云服务: '云服务',
  分析: '分析',
  社交SDK: '社交 SDK',
  移动框架: '移动框架',
  富文本编辑器: '富文本编辑器',
  图表库: '图表库',
  地图: '地图',
  加密库: '加密库',
  构建工具: '构建工具',
  监控: '监控',
  安全头: '安全头',
  其他: '其他',
};

/** 分类显示顺序 */
export const CATEGORY_ORDER: string[] = [
  'CMS',
  '框架',
  'JS 框架',
  'UI 框架',
  'JS 库',
  'Web 服务器',
  'CDN',
  '云服务',
  '分析',
  '社交SDK',
  '移动框架',
  '富文本编辑器',
  '图表库',
  '地图',
  '加密库',
  '构建工具',
  '监控',
  '安全头',
  '其他',
];

/** 信号来源中文标签 */
export const SOURCE_LABELS: Record<string, string> = {
  headers: 'HTTP 响应头',
  globals: 'JS 全局变量',
  meta: 'Meta 标签',
  body: '页面内容',
  cookies: 'Cookies',
  classNames: 'CSS 类名',
  ids: '元素 ID',
  scriptSrc: '脚本来源',
};

// ====== 核心：正则水合 ======

/**
 * 将 JSON 序列化的 matcher value 转为 RegExp 或保留 string。
 * JSON 中正则存储为 { __regexp__: true, source, flags }。
 */
export function hydrateMatcher(
  value: string | { __regexp__: true; source: string; flags: string },
): RegExp | string {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && '__regexp__' in value && value.__regexp__) {
    return new RegExp(value.source, value.flags);
  }
  return String(value);
}

// ====== 信号池构建 ======

function buildSignalPool(input: SniffInput) {
  const pool: Record<string, string> = {};

  // headers: 拼接为 "name: value" 小写行
  const headerLines: string[] = [];
  for (const [k, v] of Object.entries(input.headers)) {
    headerLines.push(`${k.toLowerCase()}: ${v.toLowerCase()}`);
  }
  pool.headers = headerLines.join('\n');

  // meta: 拼接为 "name=content" 小写行
  const metaLines: string[] = [];
  for (const m of input.meta) {
    metaLines.push(`${(m.name || '').toLowerCase()}=${(m.content || '').toLowerCase()}`);
  }
  pool.meta = metaLines.join('\n');

  // body: 整个 HTML 小写
  pool.body = (input.html || '').toLowerCase();

  // scriptSrc: 拼接为小写行
  pool.scriptSrc = (input.scriptSrcs || []).map(s => s.toLowerCase()).join('\n');

  // cookies: 拼接为小写行
  const cookieLines: string[] = [];
  for (const [k, v] of Object.entries(input.cookies)) {
    cookieLines.push(`${k.toLowerCase()}=${v.toLowerCase()}`);
  }
  pool.cookies = cookieLines.join('\n');

  return pool;
}

// ====== 单条匹配 ======

function evaluateMatcher(
  matcher: SerializedMatcher,
  pool: Record<string, string>,
): SniffEvidence | null {
  const source = matcher.source;
  const type = matcher.type;
  const raw = matcher.value;

  const haystack = pool[source];
  if (!haystack) return null;

  const pattern = hydrateMatcher(raw);

  if (type === 'regex' && pattern instanceof RegExp) {
    const match = pattern.exec(haystack);
    if (match) {
      const start = Math.max(0, match.index - 30);
      const end = Math.min(haystack.length, match.index + match[0].length + 30);
      return { source, evidence: haystack.substring(start, end) };
    }
    return null;
  }

  if ((type === 'string' || type === 'contains') && typeof pattern === 'string') {
    const lower = pattern.toLowerCase();
    const idx = haystack.indexOf(lower);
    if (idx !== -1) {
      const start = Math.max(0, idx - 20);
      const end = Math.min(haystack.length, idx + lower.length + 20);
      return { source, evidence: haystack.substring(start, end) };
    }
    return null;
  }

  return null;
}

// ====== 主扫描 ======

/**
 * 对给定输入执行全部技术指纹匹配，返回命中的技术列表。
 * 结果按匹配数量降序排列。
 */
export function scan(input: SniffInput): SniffMatch[] {
  const pool = buildSignalPool(input);
  const signatures = TECH_SIGNATURES as TechSignature[];
  const results: SniffMatch[] = [];

  for (const sig of signatures) {
    const evidences: SniffEvidence[] = [];

    for (const matcher of sig.matchers) {
      const evidence = evaluateMatcher(matcher, pool);
      if (evidence) evidences.push(evidence);
    }

    if (evidences.length === 0) continue;

    results.push({
      name: sig.name,
      category: sig.category,
      evidences,
      matchedCount: evidences.length,
    });
  }

  // 按匹配数量降序
  results.sort((a, b) => b.matchedCount - a.matchedCount);

  return results;
}
