/**
 * 面板元数据注册表 — Popup / 快捷入口专用
 * 只包含 id、label、icon、category 等元信息，不导入组件本体。
 * 避免 Popup 加载 30 个面板组件的完整 JS。
 */

export interface PanelMeta {
  id: string;
  label: string;
  icon: string;
  category: string;
  categoryLabel: string;
  catColor: string;
}

export const panelMeta: PanelMeta[] = [
  // ===== 侦察 (Recon) =====
  { id: 'favicon', label: '图标识别', icon: '🖼️', category: 'recon', categoryLabel: '侦察', catColor: '#4A90E2' },
  { id: 'gather', label: '信息收集', icon: '🔍', category: 'recon', categoryLabel: '侦察', catColor: '#4A90E2' },
  { id: 'subdomain', label: '子域名', icon: '🌐', category: 'recon', categoryLabel: '侦察', catColor: '#4A90E2' },
  { id: 'asset', label: '资产测绘', icon: '📍', category: 'recon', categoryLabel: '侦察', catColor: '#4A90E2' },

  // ===== 扫描 (Scan) =====
  { id: 'xssscan', label: 'XSS扫描', icon: '⚡', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'cors', label: 'CORS检测', icon: '🔗', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'headers', label: '安全头', icon: '🛡️', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'waf', label: 'WAF指纹', icon: '🔥', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'redirect', label: '重定向', icon: '↗️', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'fuzz', label: '目录扫描', icon: '📂', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'graphql', label: 'GraphQL', icon: '◈', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'cookie-audit', label: 'Cookie审计', icon: '🍪', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'sniff', label: '网站嗅探', icon: '👃', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'leakscan', label: '泄露扫描', icon: '🔓', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },
  { id: 'hae', label: 'HAE规则', icon: '🎨', category: 'scan', categoryLabel: '扫描', catColor: '#e74c3c' },

  // ===== 利用 (Exploit) =====
  { id: 'encoding', label: '编码工具', icon: '🔤', category: 'exploit', categoryLabel: '利用', catColor: '#e67e22' },
  { id: 'payload', label: 'Payload', icon: '💊', category: 'exploit', categoryLabel: '利用', catColor: '#e67e22' },
  { id: 'spoof', label: '请求伪造', icon: '🎭', category: 'exploit', categoryLabel: '利用', catColor: '#e67e22' },
  { id: 'jsctrl', label: 'JS控制', icon: '⚙️', category: 'exploit', categoryLabel: '利用', catColor: '#e67e22' },

  // ===== 框架 (Framework) =====
  { id: 'vue', label: 'Vue分析', icon: '🟢', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },
  { id: 'react', label: 'React分析', icon: '⚛️', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },
  { id: 'angular', label: 'Angular分析', icon: '🅰️', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },
  { id: 'svelte', label: 'Svelte分析', icon: '🔶', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },
  { id: 'ruoyi', label: 'RuoYi路由', icon: '📁', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },
  { id: 'sourcemap', label: 'Source Map', icon: '🗺️', category: 'framework', categoryLabel: '框架', catColor: '#27ae60' },

  // ===== 工具 (Tools) =====
  { id: 'links', label: '链接提取', icon: '🔗', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'multiurl', label: 'URL多开', icon: '📑', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'history', label: '历史档案', icon: '📜', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'history-archive', label: 'Wayback', icon: '🗂️', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'tabsave', label: '标签保存', icon: '📑', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'exif', label: 'EXIF查看', icon: '📷', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'storage-check', label: '存储检查', icon: '🗄️', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'source-loader', label: '源码加载', icon: '📦', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },
  { id: 'jsarchive', label: 'JS归档', icon: '🗜️', category: 'tools', categoryLabel: '工具', catColor: '#9b59b6' },

  // ===== 报告 (Report) =====
  { id: 'report', label: '统一报告', icon: '📊', category: 'report', categoryLabel: '报告', catColor: '#999' },
];
