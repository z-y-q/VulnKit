// 链接提取引擎（纯函数，无 DOM/网络依赖）

/** 提取到的链接 */
export interface ExtractedLink {
  href: string;
  text?: string;
  /** 来源标签: a / img / script / link / iframe / form */
  tag?: string;
  domain?: string;
  type: 'internal' | 'external' | 'relative' | 'mailto' | 'tel' | 'anchor';
  protocol?: string;
}

/** 根据 href 和页面 origin 分类链接 */
export function classifyLink(href: string, baseOrigin: string): ExtractedLink['type'] {
  if (!href) return 'anchor';
  if (href.startsWith('mailto:')) return 'mailto';
  if (href.startsWith('tel:')) return 'tel';
  if (href.startsWith('#') || href === '#' || /^\s*#\w*$/.test(href)) return 'anchor';
  if (href.startsWith('//')) return 'external'; // protocol-relative, likely cross-origin
  if (/^\w+:\/\//.test(href)) {
    try {
      const u = new URL(href);
      if (u.origin === baseOrigin) return 'internal';
      return 'external';
    } catch {
      return 'relative';
    }
  }
  // relative path
  if (/^\.\.?\/?/.test(href) || /^\//.test(href)) return 'relative';
  return 'relative';
}

/** 去重（基于 href） */
export function dedupeLinks(links: ExtractedLink[]): ExtractedLink[] {
  const seen = new Set<string>();
  return links.filter(l => {
    const key = l.href;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** 构建 CSV 字符串 */
export function buildCsv(links: ExtractedLink[]): string {
  const header = ['URL', 'Type', 'Tag', 'Domain', 'Text'];
  const rows = links.map(l => [
    l.href,
    l.type,
    l.tag || '',
    l.domain || '',
    l.text || '',
  ]);
  const lines = [header, ...rows].map(r =>
    r.map(c => `"${c.replace(/"/g, '""')}"`).join(','),
  );
  return lines.join('\n');
}
