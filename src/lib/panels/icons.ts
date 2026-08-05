/**
 * 面板图标映射 —— 统一用 Lucide 单线图标集替代彩色 emoji（Apple Design §16 Craft）。
 *
 * 彩色 emoji 在不同平台渲染不一、尺寸难统一、观感「卡通」，是廉价感的主要来源。
 * Lucide 是克制、一致的 monoline 集，经 UnoCSS presetIcons 以 CSS mask 内联（无运行时网络，
 * 符合扩展 CSP）。颜色继承 currentColor，随上下文 text 色变化。
 *
 * 经 @/components/ui/PanelIcon.svelte 渲染；未命中时回退到 registry 的 emoji。
 * 用到的 i-lucide-* 类名同时在 uno.config.ts 的 safelist 中显式声明（动态拼接需保证生成）。
 */
export const PANEL_ICONS: Record<string, string> = {
  // 侦察 Recon
  favicon: 'image',
  gather: 'radar',
  subdomain: 'network',
  asset: 'crosshair',
  // 扫描 Scan
  xssscan: 'bug',
  sqliscan: 'database',
  cors: 'share-2',
  headers: 'shield-check',
  waf: 'flame',
  redirect: 'move-up-right',
  fuzz: 'folder-search',
  graphql: 'hexagon',
  'cookie-audit': 'cookie',
  sniff: 'scan-eye',
  leakscan: 'key-round',
  hae: 'regex',
  // 利用 Exploit
  encoding: 'binary',
  payload: 'package',
  spoof: 'venetian-mask',
  jsctrl: 'settings-2',
  // 框架 Framework
  vue: 'leaf',
  react: 'atom',
  angular: 'boxes',
  svelte: 'diamond',
  ruoyi: 'route',
  sourcemap: 'map',
  // 工具 Tools
  links: 'link',
  multiurl: 'external-link',
  history: 'file-clock',
  'history-archive': 'archive',
  tabsave: 'bookmark',
  exif: 'camera',
  'storage-check': 'hard-drive',
  'source-loader': 'file-code-2',
  jsarchive: 'file-archive',
  // 报告 Report
  report: 'file-text',
};

/** 面板 id → 完整 UnoCSS 图标类名（如 'i-lucide-shield-check'）；未映射返回 undefined */
export function panelIconClass(id: string): string | undefined {
  const name = PANEL_ICONS[id];
  return name ? `i-lucide-${name}` : undefined;
}

/** safelist 用：所有用到的完整类名（供 uno.config.ts 引用，保证动态拼接时也生成） */
export const PANEL_ICON_CLASSES: string[] = Object.values(PANEL_ICONS).map((n) => `i-lucide-${n}`);
