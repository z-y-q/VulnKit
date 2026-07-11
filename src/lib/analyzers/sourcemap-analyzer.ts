/**
 * Source Map 分析引擎 — 灵眸 v6.0
 * 纯分析逻辑（不含网络请求与 UI）
 * 从 vk-sourcemap-*.js 提取的 source map 解析、敏感路径分类
 */

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

/** 从 HTML 中提取 <script src="..."> 的 URL 列表 */
export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const url = resolveUrl(match[1], baseUrl);
    if (!seen.has(url)) {
      seen.add(url);
      urls.push(url);
    }
  }
  return urls;
}

/** 从 HTML 内联 <script> 中提取 sourceMappingURL 提示 */
export function extractInlineSourceMapHints(html: string, baseUrl: string): string[] {
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
      const url = resolveUrl(rawUrl, baseUrl);
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

/** 解析 Source Map JSON 字符串为结构化信息 */
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
