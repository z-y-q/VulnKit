/**
 * 源码解析工具
 * 从 HTML 源码中提取外部脚本和样式链接
 */

/** 从 HTML 源码中提取所有 <script src="..."> 的 URL */
export function extractScriptSrcs(html: string): string[] {
  const srcs: string[] = [];
  // 使用正则匹配，避免 DOMParser 对不完整 HTML 的依赖
  const re = /<script[^>]*\ssrc\s*=\s*(?:"([^"]+)"|'([^']+)'|(\S+))[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const url = m[1] || m[2] || m[3];
    if (url) srcs.push(url);
  }
  return srcs;
}

/** 从 HTML 源码中提取所有 <link href="..."> (stylesheet) 的 URL */
export function extractLinkHrefs(html: string): string[] {
  const hrefs: string[] = [];
  const re = /<link[^>]*\shref\s*=\s*(?:"([^"]+)"|'([^']+)'|(\S+))[^>]*rel\s*=\s*(?:"[^"]*stylesheet[^"]*"|'[^']*stylesheet[^']*'|\S*stylesheet\S*)[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const url = m[1] || m[2] || m[3];
    if (url) hrefs.push(url);
  }
  // 也匹配 href 在 rel 之前的情况
  const re2 = /<link[^>]*\srel\s*=\s*(?:"[^"]*stylesheet[^"]*"|'[^']*stylesheet[^']*'|\S*stylesheet\S*)[^>]*\shref\s*=\s*(?:"([^"]+)"|'([^']+)'|(\S+))[^>]*>/gi;
  while ((m = re2.exec(html)) !== null) {
    const url = m[1] || m[2] || m[3];
    if (url) hrefs.push(url);
  }
  return [...new Set(hrefs)];
}

/** 格式化文件大小 */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
