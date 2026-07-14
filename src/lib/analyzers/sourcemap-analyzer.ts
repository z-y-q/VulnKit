/**
 * Source Map 分析引擎
 * 纯分析逻辑（不含网络请求与 UI）
 * 从 vk-sourcemap-*.js 提取的 source map 解析、敏感路径分类
 */

import { scanLeaks, toSimpleSeverity } from '@/lib/scanners/leak-scanner';

// ====== Types ======

/** 解析后的 Source Map 结构 */
export interface SourceMapInfo {
  file: string;
  version: number;
  sources: string[];
  sourcesContent: string[] | null;
  sourceRoot?: string;
  mappings?: string;
}

/** 分类后的源文件列表 */
export interface ClassifiedSources {
  all: string[];
  sensitive: string[];
}

/** 单个 Bundle 的 Source Map 扫描结果 */
export interface SourceMapResult {
  bundleUrl: string;
  mapUrl: string | null;
  info: SourceMapInfo | null;
  sourceCount: number;
  sensitiveFiles: string[];
  hasContentLeak: boolean;
  error?: string;
}

/** Build Tool 检测结果（与 inject/sourcemap-detect.ts 返回值对齐） */
export interface DetectResult {
  tool: string | null;
  version: string | null;
  hints: string[];
  features: string[];
}

/** Source Map 风险等级 */
export type SourceMapSeverity = 'critical' | 'high' | 'medium' | 'info';

// ====== Regex ======

/** 匹配 //# sourceMappingURL=URL 或 //@ sourceMappingURL=URL */
const SOURCEMAP_URL_RE = /\/\/[@#]\s*sourceMappingURL\s*=\s*(\S+)/i;

// ====== Pure Functions ======

/** 解析相对 URL 为绝对 URL */
function resolveUrl(relative: string, base: string): string {
  try {
    return new URL(relative, base).href;
  } catch {
    return relative;
  }
}

/** 解析 HTML 中的 <base href="...">，返回解析后的有效 base URL（无 base 则返回原 baseUrl）。
 *  浏览器加载相对 script src 时会先查 <base>，未处理 <base> 会把 /user/login 页面下的
 *  lib/x.js 错误解析成 /user/lib/x.js（站点根在 / 时会 404）。
 */
function effectiveBase(html: string, baseUrl: string): string {
  const m = html.match(/<base\b[^>]*\bhref\s*=\s*["']([^"']+)["']/i);
  if (!m) return baseUrl;
  return resolveUrl(m[1], baseUrl);
}

/** 从 HTML 中提取 <script src="..."> 与 <link rel="preload" as="script"> 的 URL 列表 */
export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const base = effectiveBase(html, baseUrl);
  const urls: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string) => {
    const url = resolveUrl(raw, base);
    if (!seen.has(url)) {
      seen.add(url);
      urls.push(url);
    }
  };
  // <script src="...">
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) push(match[1]);
  // <link rel="preload" ... as="script" href="...">（webpack/vite 常用于预加载 chunk）
  const preloadRe = /<link\b[^>]*\brel\s*=\s*["']preload["'][^>]*\bas\s*=\s*["']script["'][^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
  while ((match = preloadRe.exec(html)) !== null) push(match[1]);
  const preloadRe2 = /<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\bas\s*=\s*["']script["'][^>]*\brel\s*=\s*["']preload["']/gi;
  while ((match = preloadRe2.exec(html)) !== null) push(match[1]);
  return urls;
}

/** 从 HTML 内联 <script> 中提取 sourceMappingURL 提示 */
export function extractInlineSourceMapHints(html: string, baseUrl: string): string[] {
  const base = effectiveBase(html, baseUrl);
  const urls: string[] = [];
  const seen = new Set<string>();
  const scriptRe = /<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = scriptRe.exec(html)) !== null) {
    const content = scriptMatch[1];
    const mapRe = /\/\/[@#]\s*sourceMappingURL\s*=\s*(\S+)/gi;
    let mapMatch: RegExpExecArray | null;
    while ((mapMatch = mapRe.exec(content)) !== null) {
      const rawUrl = mapMatch[1];
      if (rawUrl.startsWith('data:')) continue;
      const url = resolveUrl(rawUrl, base);
      if (!seen.has(url)) {
        seen.add(url);
        urls.push(url);
      }
    }
  }
  return urls;
}

/**
 * 从 JS 代码体中提取 sourceMappingURL，解析为绝对 URL。
 * 优化：优先检查文件尾部（标准位置），找不到再扫描全文。
 */
export function extractSourceMapUrl(jsBody: string, baseUrl: string): string | null {
  // 优化：只检查最后一行（标准 sourceMappingURL 位置）
  const lastNewline = jsBody.lastIndexOf('\n');
  const tail = lastNewline >= 0
    ? jsBody.substring(lastNewline)
    : jsBody.substring(jsBody.length - 500);

  const tailMatch = SOURCEMAP_URL_RE.exec(tail);
  if (tailMatch) {
    const rawUrl = tailMatch[1];
    if (rawUrl.startsWith('data:')) return null;
    return resolveUrl(rawUrl, baseUrl);
  }

  // 回退：扫描全文
  const bodyRe = new RegExp(SOURCEMAP_URL_RE.source, 'gi');
  let match: RegExpExecArray | null;
  while ((match = bodyRe.exec(jsBody)) !== null) {
    const rawUrl = match[1];
    if (rawUrl.startsWith('data:')) continue;
    return resolveUrl(rawUrl, baseUrl);
  }
  return null;
}

/**
 * 提取并解析内联 base64 source map（注释形如 sourceMappingURL=data:application/json;base64,...）。
 * 直接返回 SourceMapInfo，无需网络请求。找不到返回 null。
 */
export function extractInlineSourceMap(jsBody: string): SourceMapInfo | null {
  const bodyRe = new RegExp(SOURCEMAP_URL_RE.source, 'gi');
  let match: RegExpExecArray | null;
  while ((match = bodyRe.exec(jsBody)) !== null) {
    const rawUrl = match[1];
    if (!rawUrl.startsWith('data:')) continue;
    const commaIdx = rawUrl.indexOf(',');
    if (commaIdx < 0) return null;
    const meta = rawUrl.slice(0, commaIdx);
    const payload = rawUrl.slice(commaIdx + 1);
    let jsonStr: string;
    try {
      if (meta.includes('base64')) {
        jsonStr = atob(payload);
      } else {
        jsonStr = decodeURIComponent(payload);
      }
    } catch {
      return null;
    }
    return parseSourceMap(jsonStr);
  }
  return null;
}
export function parseSourceMap(mapJson: string): SourceMapInfo | null {
  try {
    const parsed = JSON.parse(mapJson);
    if (!parsed || typeof parsed.version !== 'number') return null;
    return {
      file: parsed.file || '',
      version: parsed.version,
      sources: Array.isArray(parsed.sources) ? parsed.sources : [],
      sourcesContent: Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : null,
      sourceRoot: parsed.sourceRoot || undefined,
      mappings: parsed.mappings || undefined,
    };
  } catch {
    return null;
  }
}

/** 检查 Source Map 是否包含完整源码内容（sourcesContent 泄露） */
export function hasSourceContent(map: SourceMapInfo): boolean {
  if (!map.sourcesContent || map.sourcesContent.length === 0) return false;
  return map.sourcesContent.some(c => c != null && c.length > 0);
}

/** 敏感文件路径匹配规则 */
const SENSITIVE_PATTERNS: RegExp[] = [
  /\.env/i,
  /\.env\./i,
  /\/config\//i,
  /\.config\.\w+$/i,
  /secret/i,
  /credential/i,
  /private[-_]?key/i,
  /auth/i,
  /password/i,
  /token/i,
  /\.key$/i,
  /\.pem$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\/api\//i,
  /\/routes?\//i,
  /\/internal\//i,
  /\/admin\//i,
  /database/i,
  /\/db\//i,
  /\/models?\//i,
  /\/schema/i,
  /\.sql$/i,
  /\/middleware/i,
  /\/debug/i,
  /\/test\//i,
  /\/\.aws\//i,
  /\/\.github\//i,
  /\/credentials/i,
];

/** 对源文件路径进行分类：标记敏感文件 */
export function classifySources(sources: string[]): ClassifiedSources {
  const cleaned = sources.map(s => s.replace(/^webpack:\/\//, ''));
  const all = [...new Set(cleaned)].sort();
  const sensitive = all.filter(s => SENSITIVE_PATTERNS.some(p => p.test(s)));
  return { all, sensitive };
}

/** 评估 Source Map 泄露的风险等级 */
export function assessRisk(result: SourceMapResult): SourceMapSeverity {
  if (!result.info) return 'info';
  if (result.hasContentLeak && result.sensitiveFiles.length > 0) return 'critical';
  if (result.hasContentLeak) return 'high';
  if (result.sensitiveFiles.length > 0) return 'medium';
  if (result.sourceCount > 0) return 'info';
  return 'info';
}

/** 风险等级中文标签 */
export function severityLabel(sev: SourceMapSeverity): string {
  const map: Record<SourceMapSeverity, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    info: '信息',
  };
  return map[sev];
}

/** 风险等级对应颜色 class */
export const SEV_COLOR: Record<SourceMapSeverity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-red-500 text-white',
  medium: 'bg-yellow-500 text-white',
  info: 'bg-blue-500 text-white',
};

// ====== Source Map 路径猜测（v5 Phase 2.5 移植） ======

/**
 * 根据构建工具和 bundle URL 猜测可能的 .map 文件地址。
 * 用于发现 bundle 尾部未声明 sourceMappingURL、但实际存在的 map。
 */
export function guessMapUrls(bundleUrl: string, tool: string | null): string[] {
  const candidates: string[] = [];
  const pushUnique = (u: string) => {
    try {
      const abs = new URL(u, bundleUrl).href;
      if (!candidates.includes(abs)) candidates.push(abs);
    } catch { /* ignore */ }
  };

  // 通用：直接追加 .map
  if (!bundleUrl.endsWith('.map')) pushUnique(bundleUrl + '.map');

  const path = (() => { try { return new URL(bundleUrl).pathname; } catch { return ''; } })();

  // 构建工具特定策略
  switch (tool) {
    case 'vite':
    case 'rollup':
    case 'esbuild':
      // Vite 等：对 /assets/、dist/ 等同源 JS 一律追加 .map（通用规则只追加原 bundle，
      // 这里对 hashless 变体也会探测）。已被通用 + hashless 规则覆盖，补一个 assets 下的探测。
      if (path.indexOf('/assets/') >= 0) pushUnique(bundleUrl + '.map');
      break;
    case 'turbopack':
    case 'next':
      // 仅对 /_next/static/ 下的 JS 探测 .map（其他路径通常无 map）
      if (path.indexOf('/_next/static/') >= 0) pushUnique(bundleUrl + '.map');
      break;
    case 'nuxt':
      // 仅对 /_nuxt/ 下的 JS 探测 .map
      if (path.indexOf('/_nuxt/') >= 0) pushUnique(bundleUrl + '.map');
      break;
  }

  // 去掉 hash 后缀再试：xxx.[hash].js → xxx.js.map
  const hashless = path.replace(/\.[a-f0-9]{6,}\.(js|mjs|cjs)$/i, '.$1');
  if (hashless && hashless !== path) {
    const base = bundleUrl.replace(/[^/]+$/, '');
    pushUnique(base + hashless.split('/').pop() + '.map');
  }

  return candidates;
}

// ====== 源码内容安全扫描（端点 + 密钥） ======

export interface EndpointFinding {
  type: 'api' | 'graphql' | 'websocket';
  value: string;
}

export interface SecretFinding {
  rule: string;
  severity: 'high' | 'medium' | 'low';
  value: string;
}

const ENDPOINT_PATTERNS: { type: EndpointFinding['type']; re: RegExp }[] = [
  // API 路径
  { type: 'api', re: /["'`](\/(?:api|v1|v2|v3|rest|graphql|gql)\/[a-zA-Z0-9_\-\/{}.:]+)["'`]/g },
  // fetch / axios 调用
  { type: 'api', re: /(?:fetch|axios|request|http|api)\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/g },
  // fetch('url')
  { type: 'api', re: /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g },
  // GraphQL 查询
  { type: 'graphql', re: /(?:gql|graphql)\s*`([\s\S]{0,200}?(?:query|mutation|subscription)\s+\w+)/g },
  { type: 'graphql', re: /\b(query|mutation|subscription)\s+(\w+)\s*[\({]/g },
  // WebSocket
  { type: 'websocket', re: /new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]/g },
  { type: 'websocket', re: /["'`](wss?:\/\/[^"'`]+)["'`]/g },
];

const SECRET_PATTERNS: { rule: string; severity: SecretFinding['severity']; re: RegExp }[] = [
  // 保留少量兜底模式（leak-scanner 未覆盖的通用场景），主力扫描由 scanLeaks 90 条规则承担
  { rule: 'JWT', severity: 'medium', re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
];

const MAX_FINDINGS_PER_TYPE = 100;

/** 从源码内容提取 API/GraphQL/WebSocket 端点 */
export function extractEndpoints(source: string): EndpointFinding[] {
  const found = new Map<string, EndpointFinding>();
  for (const { type, re } of ENDPOINT_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null && found.size < MAX_FINDINGS_PER_TYPE) {
      const val = (m[1] || m[0] || '').trim().slice(0, 200);
      if (!val || val.length < 3) continue;
      const key = `${type}::${val}`;
      if (!found.has(key)) found.set(key, { type, value: val });
    }
  }
  return [...found.values()];
}

/**
 * 从源码内容扫描密钥/敏感凭证。
 * 主力由 leak-scanner 的 90 条规则承担（含 validate 回调降误报），
 * SECRET_PATTERNS 仅作少量兜底。
 */
export function scanSecrets(source: string): SecretFinding[] {
  const found = new Map<string, SecretFinding>();

  // 1) 主力：90 条规则引擎
  for (const lf of scanLeaks(source, 20)) {
    const key = `${lf.ruleId}::${lf.value}`;
    if (!found.has(key) && found.size < MAX_FINDINGS_PER_TYPE) {
      found.set(key, {
        rule: `${lf.rule}${lf.exploit ? '（' + lf.exploit.slice(0, 40) + '）' : ''}`,
        severity: toSimpleSeverity(lf.severity),
        value: lf.value,
      });
    }
  }

  // 2) 兜底：少量补充模式
  for (const { rule, severity, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = re.exec(source)) !== null && count < 20 && found.size < MAX_FINDINGS_PER_TYPE) {
      const val = (m[1] || m[0] || '').slice(0, 120);
      if (!val) continue;
      const key = `${rule}::${val}`;
      if (!found.has(key)) {
        found.set(key, { rule, severity, value: val });
        count++;
      }
    }
  }
  return [...found.values()];
}

/** 合并多个模块的源码为一个字符串（用于批量扫描） */
export function concatSources(sources: string[], contents: (string | null)[]): string {
  let out = '';
  for (let i = 0; i < sources.length && i < contents.length; i++) {
    if (contents[i]) out += '\n' + contents[i];
  }
  return out.slice(0, 2_000_000); // 上限 2MB，避免正则爆炸
}

/** 从 bundle 源码中正则提取 webpack chunk 文件名引用（v5 discoverChunksDeepParse 移植）。
 *  匹配字面量 "name.hash.js" / './name.hash.js' / "path/name.hash.css"，
 *  返回去重的文件名（相对 bundle base）。能发现命名 chunk（certification.7db0e790.js）
 *  与数字 chunk（4363.99d4d99a.js），不依赖 webpack 运行时是否暴露。
 */
export function extractChunkFilenames(source: string): string[] {
  const re = /["']\.?\/?([\w./-]+\.[a-f0-9]{6,}\.(?:js|mjs|css))["']/g;
  const out: string[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const f = m[1];
    // 过滤明显非 chunk 的（如带 http 的、过长的）
    if (f.length > 200 || f.indexOf('://') !== -1) continue;
    if (!seen.has(f)) { seen.add(f); out.push(f); }
  }
  return out;
}

/** 从 bundle 源码解析 webpack chunk 哈希表并重建 chunk URL（v5 smRegisterChunkUrls 移植）。
 *  webpack5 的 u() 用 `"prefix"+e+"."+{4363:"99d4d99a",certification:"7db0e790"}[e]+".js"` 动态拼接，
 *  源码里没有完整文件名字面量，必须解析 {key:hash} 表 + 重建 `base+key+"."+hash+".js"`。
 *  key 支持命名 chunk 与数字 chunk；只接受含 ≥3 对 hash 的对象（chunk 清单特征）以降误报。
 */
export function discoverChunksByHashmap(source: string, bundleBase: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const objRe = /\{([^{}]{20,})\}/g;
  let obj: RegExpExecArray | null;
  while ((obj = objRe.exec(source)) !== null) {
    const inner = obj[1];
    const pairRe = /["']?([\w-]+)["']?\s*:\s*["']([a-f0-9]{6,})["']/g;
    const pairs: { k: string; h: string }[] = [];
    let p: RegExpExecArray | null;
    while ((p = pairRe.exec(inner)) !== null) pairs.push({ k: p[1], h: p[2] });
    if (pairs.length < 3) continue; // chunk 清单通常几十上百项，过滤零散哈希对象
    for (const { k, h } of pairs) {
      if (k.length > 60) continue;
      const file = k + '.' + h + '.js';
      try {
        const url = new URL(file, bundleBase).href;
        if (!seen.has(url)) { seen.add(url); out.push(url); }
      } catch { /* ignore */ }
    }
  }
  return out;
}

// ====== Webpack 运行时快照（Phase 1 MAIN world 注入返回值） ======

export interface WebpackSnapshot {
  modules: { id: string; path?: string }[];
  hasWebpack: boolean;
  chunkInfo: { chunkFilenames: Record<string, string>; publicPath?: string } | null;
  monitoredScripts: string[];
  wpPublicPath: string;
}

/**
 * 将 webpack 快照的 chunkFilenames（id→相对文件名）解析为绝对 URL。
 * 对齐 v5 discoverChunksFromManifest：先用已知 bundle URL 反推 base（匹配文件名），
 * 回退到 wpPublicPath / 页面 base。
 */
export function resolveWebpackChunkUrls(
  snap: WebpackSnapshot | null,
  pageUrl: string,
  knownBundles: string[] = [],
): string[] {
  if (!snap?.chunkInfo?.chunkFilenames) return [];
  const manifest = snap.chunkInfo.chunkFilenames;
  const files = Object.values(manifest).filter(Boolean);

  // 1) 用已知 bundle 反推 base（找到某个 chunk 文件名与已知 URL 末段匹配的）
  let base = '';
  for (const sUrl of knownBundles) {
    const sUrlClean = sUrl.split('?')[0];
    const sBare = sUrlClean.substring(sUrlClean.lastIndexOf('/') + 1);
    for (const f of files) {
      const cBare = f.substring(f.lastIndexOf('/') + 1);
      if (cBare === sBare) {
        base = sUrlClean.substring(0, sUrlClean.length - f.length);
        break;
      }
    }
    if (base) break;
  }
  // 2) 回退：publicPath / 页面目录
  if (!base) {
    const pp = snap.chunkInfo.publicPath || snap.wpPublicPath || '';
    if (pp) {
      try { base = new URL(pp, pageUrl).href; } catch { base = pp; }
    } else {
      base = pageUrl.substring(0, pageUrl.lastIndexOf('/') + 1);
    }
  }

  const out: string[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    try {
      const abs = new URL(f, base).href;
      if (!seen.has(abs)) { seen.add(abs); out.push(abs); }
    } catch { /* ignore */ }
  }
  return out;
}
