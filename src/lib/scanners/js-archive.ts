/**
 * JS 归档引擎 — 灵眸 v7.2
 * 把当前页面所有 JS 按「原始 URL 路径」组织进 zip，供本地安全审计。
 * 纯逻辑：URL → zip 内路径映射、清单生成、文件名去重。无网络 / 无 DOM。
 */

export interface ArchiveEntry {
  /** 原始绝对 URL（inline 脚本为空） */
  url: string;
  /** zip 内相对路径，如 cdn.example.com/static/js/app.js */
  path: string;
  /** 字节大小 */
  size: number;
  /** 抓取状态 */
  status: 'ok' | 'fail' | 'skip';
  /** 失败/跳过原因 */
  note?: string;
  /** http/inline/data 来源标记 */
  kind: 'http' | 'inline' | 'data';
  /** 来源置信度：DOM script[src] / preload link / performance 资源 / 内联 */
  source?: 'dom' | 'preload' | 'performance' | 'inline';
}

/**
 * 将一个 http(s) URL 映射为 zip 内路径：host + pathname（去掉 query/hash）。
 * 例：https://cdn.x.com/a/b/app.js?v=1 → cdn.x.com/a/b/app.js
 * 末尾无文件名时补 index.js。
 */
export function urlToZipPath(rawUrl: string): string | null {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  let path = u.pathname;
  // 末尾是目录 → 补 index.js
  if (path.endsWith('/') || path === '') path += 'index.js';
  // 无扩展名的兜底（罕见）→ 补 .js
  const seg = path.slice(path.lastIndexOf('/') + 1);
  if (seg && !/\.[a-zA-Z0-9]+$/.test(seg)) path += '.js';
  // 去掉开头的斜杠，拼上 host
  return (u.host + path).replace(/^\/+/, '');
}

/**
 * 对路径列表去重：相同路径追加 __2、__3。
 * 返回 Map<原始URL(or inline key), zipPath>，调用方据此落盘。
 */
export function dedupePaths(inputs: { key: string; path: string }[]): Map<string, string> {
  const used = new Set<string>();
  const out = new Map<string, string>();
  for (const { key, path } of inputs) {
    let p = path;
    if (used.has(p)) {
      const dot = p.lastIndexOf('.');
      const ext = dot > p.lastIndexOf('/') ? p.slice(dot) : '';
      const base = ext ? p.slice(0, dot) : p;
      let n = 2;
      while (used.has(`${base}__${n}${ext}`)) n++;
      p = `${base}__${n}${ext}`;
    }
    used.add(p);
    out.set(key, p);
  }
  return out;
}

// 明确的非 JS 资源后缀：图片/字体/CSS/媒体/文档/数据。用于过滤 performance 资源。
const NON_JS_EXT = /\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|css|woff2?|ttf|otf|eot|mp[34]|webm|ogg|wav|flac|pdf|zip|rar|7z|wasm|map|json|html?|xml)(\?|#|$)/i;

/** 是否为明确的非 JS 资源（按后缀判定，含 query/hash）。 */
export function isExplicitlyNonJs(url: string): boolean {
  return NON_JS_EXT.test(url);
}

/** 严格 JS 后缀（.js/.mjs，含 query/hash）—— 用于低置信来源的强校验。 */
export function isJsLike(url: string): boolean {
  return /^https?:\/\//i.test(url) && /\.m?js(\?|#|$)/i.test(url);
}

/**
 * 是否值得归档为脚本（来源置信度放宽版）：
 * 接受 .js/.mjs，也接受 extensionless、query-only 的 bundler chunk（如 /_next/static/chunk?id=…），
 * 仅排除图片/字体/CSS/JSON/HTML 等明确非 JS 资源。
 *
 * 用于 DOM script[src] / preload link / performance resource —— 这些来源本身已带有
 * 「这是脚本」的语义信号（script 标签、as=script、script/link initiatorType）。
 */
export function isArchiveableScript(url: string): boolean {
  return /^https?:\/\//i.test(url) && !isExplicitlyNonJs(url);
}

/** 生成 MANIFEST.txt 内容：每行 [状态] size\tpath\t-> url */
export function buildManifest(entries: ArchiveEntry[], pageUrl: string, fetchedAt: number): string {
  const lines: string[] = [];
  lines.push('# 灵眸 JS 归档清单 / Lingmou JS Archive');
  lines.push(`# 页面: ${pageUrl}`);
  lines.push(`# 生成时间: ${new Date(fetchedAt).toISOString()}`);
  const ok = entries.filter(e => e.status === 'ok');
  const fail = entries.filter(e => e.status === 'fail');
  const skip = entries.filter(e => e.status === 'skip');
  const totalSize = ok.reduce((s, e) => s + e.size, 0);
  lines.push(`# 成功 ${ok.length} / 失败 ${fail.length} / 跳过 ${skip.length} / 合计 ${entries.length}，解压后约 ${(totalSize / 1024).toFixed(1)} KB`);
  lines.push('');
  lines.push('[status]\tsize\tsource\tpath\t->\turl');
  for (const e of entries) {
    const st = e.status === 'ok' ? 'OK' : e.status === 'fail' ? 'FAIL' : 'SKIP';
    const src = e.source || (e.kind === 'inline' ? 'inline' : '?');
    lines.push(`${st}\t${e.size}\t${src}\t${e.path}\t->\t${e.url || '(inline)'}`);
  }
  return lines.join('\n');
}
