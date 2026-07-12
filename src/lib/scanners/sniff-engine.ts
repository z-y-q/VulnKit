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
  /** JS 全局变量名列表（来自 page-inspect fingerprint） */
  globals?: string[];
  /** 页面 CSS 类名列表 */
  classNames?: string[];
  /** 元素 id 列表 */
  ids?: string[];
  /** 版本信息（如 { 'Vue.js': '3.4.0' }） */
  versions?: Record<string, string>;
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

/** 预编译后的 matcher：value 已水合为 RegExp 或 string，避免每次扫描重建正则 */
interface CompiledMatcher {
  source: SerializedMatcher['source'];
  type: SerializedMatcher['type'];
  pattern: RegExp | string;
}

interface CompiledSignature {
  name: string;
  category: string;
  matchers: CompiledMatcher[];
}

export interface SniffMatch {
  name: string;
  category: string;
  evidences: SniffEvidence[];
  matchedCount: number;
  /** 置信度评分 0-100 */
  confidence: number;
  /** 置信度级别：strong(强)/moderate(稳)/weak(弱) */
  confidenceLevel: 'strong' | 'moderate' | 'weak';
  /** 提取到的版本号（如 '3.4.0'），无则 undefined */
  version?: string;
}

export interface SniffEvidence {
  source: string;
  evidence: string;
}

// ====== 置信度评分（对齐 v5 sniff-state） ======

/** 各信号源的基础分 */
const CONFIDENCE_BASE_SCORES: Record<string, number> = {
  headers: 30,
  globals: 30,
  meta: 20,
  body: 20,
  cookies: 25,
  classNames: 15,
  ids: 15,
  scriptSrc: 18,
};

/** 置信度级别阈值 */
export function levelFromScore(score: number): SniffMatch['confidenceLevel'] {
  if (score >= 90) return 'strong';
  if (score >= 75) return 'moderate';
  return 'weak';
}

/**
 * 计算单条命中的置信度评分。
 * - 基础分：命中的各信号源 base 分之和
 * - 多源加成：每多一个来源 +4
 * - 多匹配加成：每多一个 matcher +20%
 * 上限 100。
 */
export function scoreConfidence(evidences: SniffEvidence[]): number {
  if (evidences.length === 0) return 0;
  const sources = new Set(evidences.map(e => e.source));
  let score = 0;
  for (const s of sources) score += CONFIDENCE_BASE_SCORES[s] ?? 15;
  score += (sources.size - 1) * 4; // 多源加成
  score *= 1 + 0.2 * (evidences.length - 1); // 多 matcher 加成
  return Math.min(100, Math.round(score));
}

export const CONFIDENCE_LABELS: Record<SniffMatch['confidenceLevel'], string> = {
  strong: '强',
  moderate: '稳',
  weak: '弱',
};

/** 置信度级别 → UI 颜色类 */
export const CONFIDENCE_COLORS: Record<SniffMatch['confidenceLevel'], string> = {
  strong: 'bg-green-500 text-white',
  moderate: 'bg-amber-500 text-white',
  weak: 'bg-gray-400 text-white',
};

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

/**
 * 签名预编译缓存 — 模块加载时一次性把所有 matcher 的 value 水合为
 * RegExp/string，避免每次 scan 重复 new RegExp（134 签名 × 多 matcher）。
 */
const COMPILED_SIGNATURES: CompiledSignature[] = (TECH_SIGNATURES as TechSignature[]).map(sig => ({
  name: sig.name,
  category: sig.category,
  matchers: sig.matchers.map(m => ({
    source: m.source,
    type: m.type,
    pattern: hydrateMatcher(m.value),
  })),
}));

/** 暴露编译缓存（供测试验证预编译单例性） */
export function getCompiledSignatures(): CompiledSignature[] {
  return COMPILED_SIGNATURES;
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

  // globals: JS 全局变量名（每行一个，小写）
  pool.globals = (input.globals || []).map(g => g.toLowerCase()).join('\n');

  // classNames: CSS 类名（每行一个，小写）
  pool.classNames = (input.classNames || []).map(c => c.toLowerCase()).join('\n');

  // ids: 元素 id（每行一个，小写）
  pool.ids = (input.ids || []).map(i => i.toLowerCase()).join('\n');

  // versions: 拼接到 globals 池（如 "vue.js 3.4.0"），使版本签名也能命中
  if (input.versions) {
    const vLines = Object.entries(input.versions).map(([k, v]) => `${k.toLowerCase()} ${v.toLowerCase()}`);
    pool.globals = (pool.globals ? pool.globals + '\n' : '') + vLines.join('\n');
  }

  return pool;
}

// ====== 单条匹配 ======

function evaluateMatcher(
  matcher: CompiledMatcher,
  pool: Record<string, string>,
): SniffEvidence | null {
  const source = matcher.source;
  const type = matcher.type;
  const pattern = matcher.pattern;

  const haystack = pool[source];
  if (!haystack) return null;

  // equals：精确整行匹配（globals/classNames/ids 池为换行分隔）。
  // 关键修复：原先 equals 直接 return null，导致 92 个 globals 精确匹配器
  // （Vue/React/Angular/jQuery/Webpack/Vite 等 29 项技术）完全失效。
  if (type === 'equals' && typeof pattern === 'string') {
    const lower = pattern.toLowerCase();
    for (const line of haystack.split('\n')) {
      if (line === lower) return { source, evidence: pattern };
    }
    return null;
  }

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
  const signatures = COMPILED_SIGNATURES;
  const versions = input.versions || {};
  const results: SniffMatch[] = [];

  for (const sig of signatures) {
    const evidences: SniffEvidence[] = [];

    for (const matcher of sig.matchers) {
      const evidence = evaluateMatcher(matcher, pool);
      if (evidence) evidences.push(evidence);
    }

    if (evidences.length === 0) continue;

    const confidence = scoreConfidence(evidences);
    // 版本提取：优先精确匹配 versions[name]，其次按 name 前缀模糊匹配
    let version: string | undefined = versions[sig.name];
    if (!version) {
      const lowerName = sig.name.toLowerCase();
      for (const [k, v] of Object.entries(versions)) {
        if (lowerName.startsWith(k.toLowerCase()) || k.toLowerCase().startsWith(lowerName)) {
          version = v;
          break;
        }
      }
    }

    results.push({
      name: sig.name,
      category: sig.category,
      evidences,
      matchedCount: evidences.length,
      confidence,
      confidenceLevel: levelFromScore(confidence),
      version,
    });
  }

  // 按置信度降序，同级再按匹配数降序
  results.sort((a, b) => b.confidence - a.confidence || b.matchedCount - a.matchedCount);

  return results;
}
