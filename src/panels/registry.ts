/**
 * 面板元数据注册表 — Popup / 快捷入口专用
 * 只包含 id、label、icon、category 等元信息，不导入组件本体。
 * 避免 Popup 加载 30 个面板组件的完整 JS。
 *
 * aliases/keywords 驱动 Sidebar/Popup 搜索（panelMatches）：用户搜「跨域」命中 CORS、
 * 搜「cookie」命中 Cookie 审计、搜英文别名也能命中。capabilities/supportsAutoRun 为
 * 后续快捷入口与自动运行校验预留，本轮只标注已知面板，不全量补齐。
 */

export type PanelCapability =
  | 'target-url' // 接收目标 URL（UrlInput）
  | 'task' // 接入 TaskController（可暂停/取消/多阶段）
  | 'filter' // 结果可筛选/搜索（ResultToolbar）
  | 'detail' // 有详情视图
  | 'copy' // 结果可复制
  | 'export' // 结果可导出（ExportMenu）
  | 'history' // 写入 scan-history
  | 'handoff'; // 跨面板 handoff 写方或读方（analysisContextStore）

export interface PanelMeta {
  id: string;
  label: string;
  icon: string;
  category: string;
  categoryLabel: string;
  catColor: string;
  /** 中文别名/同义词/英文名，参与搜索匹配 */
  aliases?: string[];
  /** 搜索关键词（技术术语、相关概念） */
  keywords?: string[];
  /** 面板能力标签，驱动快捷入口/工具栏/自动运行校验 */
  capabilities?: PanelCapability[];
  /** Popup 是否支持「当前页域名一键跑」（预留，本轮不接逻辑） */
  supportsAutoRun?: boolean;
}

/**
 * 判断面板是否匹配搜索词 q。内部自行 trim + toLowerCase，调用方传原始 query 即可。
 * 空/纯空白 query 一律返回 true。匹配维度：label / categoryLabel / id / category / aliases / keywords。
 */
export function panelMatches(meta: PanelMeta, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const hay = [
    meta.label,
    meta.categoryLabel,
    meta.id,
    meta.category,
    ...(meta.aliases ?? []),
    ...(meta.keywords ?? []),
  ];
  return hay.some((s) => s.toLowerCase().includes(needle));
}

export const panelMeta: PanelMeta[] = [
  // ===== 侦察 (Recon) =====
  {
    id: 'favicon',
    label: '图标识别',
    icon: '🖼️',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    aliases: ['favicon', '站点图标', '网站图标', 'icon'],
    keywords: ['图标', 'favicon', 'ico', 'hash', '指纹'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'gather',
    label: '信息收集',
    icon: '🔍',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    aliases: ['收集', '信息探测', 'recon'],
    keywords: ['信息', '收集', '探测', '侦察', '指纹', 'handoff'],
    capabilities: ['target-url', 'copy', 'export', 'history', 'handoff'],
    supportsAutoRun: true,
  },
  {
    id: 'subdomain',
    label: '子域名',
    icon: '🌐',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    aliases: ['子域', '二级域名', 'subdomain'],
    keywords: ['子域名', '域名', 'subdomain', 'dns', '枚举'],
    capabilities: ['target-url', 'copy', 'export', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'asset',
    label: '资产测绘',
    icon: '📍',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    aliases: ['资产', '测绘', 'asset'],
    keywords: ['资产', '测绘', 'fofa', 'zoomeye', 'quake', '测绘平台'],
    capabilities: ['copy', 'export', 'detail'],
  },

  // ===== 扫描 (Scan) =====
  {
    id: 'xssscan',
    label: 'XSS扫描',
    icon: '⚡',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['xss', '跨站脚本', '跨站'],
    keywords: ['xss', '跨站', '脚本', '注入', '反射', 'payload'],
    capabilities: ['target-url', 'copy', 'export', 'detail', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'cors',
    label: 'CORS检测',
    icon: '🔗',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['cors', '跨域'],
    keywords: ['cors', '跨域', '跨域资源共享', '同源', 'origin'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'headers',
    label: '安全头',
    icon: '🛡️',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['响应头', 'http头', 'security headers', '响应头部'],
    keywords: ['安全头', '响应头', 'header', 'csp', 'hsts', 'x-frame'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'waf',
    label: 'WAF指纹',
    icon: '🔥',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['waf', '防火墙', 'web应用防火墙'],
    keywords: ['waf', '防火墙', '指纹', '防护', '识别'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'redirect',
    label: '重定向',
    icon: '↗️',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['跳转', '302', '301', 'open redirect'],
    keywords: ['重定向', '跳转', 'redirect', '302', '301', '开放重定向'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'fuzz',
    label: '目录扫描',
    icon: '📂',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['目录爆破', '路径扫描', 'dir brute', '爆破'],
    keywords: ['目录', '扫描', '爆破', 'fuzz', '路径', '字典'],
    capabilities: ['target-url', 'task', 'filter', 'copy', 'export', 'history', 'handoff'],
    supportsAutoRun: true,
  },
  {
    id: 'graphql',
    label: 'GraphQL',
    icon: '◈',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['gql'],
    keywords: ['graphql', 'gql', 'introspection', '内省', 'api'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'cookie-audit',
    label: 'Cookie审计',
    icon: '🍪',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['cookie', 'cookies'],
    keywords: ['cookie', 'cookies', '审计', '会话', 'secure', 'httponly', 'samesite'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'sniff',
    label: '网站嗅探',
    icon: '👃',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['嗅探', '指纹识别', 'whatweb', '识别'],
    keywords: ['嗅探', '指纹', 'cms', '识别', '技术栈'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'leakscan',
    label: '泄露扫描',
    icon: '🔓',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['泄露', '敏感信息泄露', 'leak'],
    keywords: ['泄露', '敏感', '信息', '暴露', '邮箱', '密钥', 'token'],
    capabilities: ['target-url', 'copy', 'history'],
    supportsAutoRun: true,
  },
  {
    id: 'hae',
    label: 'HAE规则',
    icon: '🎨',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    aliases: ['hae'],
    keywords: ['hae', '规则', '正则', '提取', '信息提取'],
    capabilities: ['copy', 'detail'],
  },

  // ===== 利用 (Exploit) =====
  {
    id: 'encoding',
    label: '编码工具',
    icon: '🔤',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    aliases: ['编码', '解码', 'encode', 'decode'],
    keywords: ['编码', '解码', 'base64', 'url', 'hex', 'html', 'jwt', '哈希', '加密'],
    capabilities: ['copy'],
  },
  {
    id: 'payload',
    label: 'Payload',
    icon: '💊',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    aliases: ['payloads', '攻击载荷', '载荷'],
    keywords: ['payload', '载荷', '攻击', 'sqli', 'xss', 'shell', '反弹'],
    capabilities: ['copy'],
  },
  {
    id: 'spoof',
    label: '请求伪造',
    icon: '🎭',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    aliases: ['伪造', '伪造头', 'headers spoof', 'header 伪造'],
    keywords: ['伪造', 'user-agent', 'ua', 'xff', 'referer', '请求头', 'dnr'],
    capabilities: ['copy'],
  },
  {
    id: 'jsctrl',
    label: 'JS控制',
    icon: '⚙️',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    aliases: ['js控制', 'javascript控制', '脚本控制'],
    keywords: ['js', 'javascript', '控制', 'hook', '拦截', '注入'],
    capabilities: ['copy'],
  },

  // ===== 框架 (Framework) =====
  {
    id: 'vue',
    label: 'Vue分析',
    icon: '🟢',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['vue', 'vuejs', 'vue.js'],
    keywords: ['vue', 'vuex', 'pinia', 'store', '状态'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'react',
    label: 'React分析',
    icon: '⚛️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['react', 'reactjs'],
    keywords: ['react', 'redux', 'hooks', 'store', 'zustand'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'angular',
    label: 'Angular分析',
    icon: '🅰️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['angular', 'ng'],
    keywords: ['angular', 'ngrx', 'service', '依赖注入'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'svelte',
    label: 'Svelte分析',
    icon: '🔶',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['svelte', 'sveltekit'],
    keywords: ['svelte', 'store', 'rune', '状态'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'ruoyi',
    label: 'RuoYi路由',
    icon: '📁',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['ruoyi', '若依', '若依框架'],
    keywords: ['ruoyi', '若依', '路由', '权限', '越权', '后台'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'sourcemap',
    label: 'Source Map',
    icon: '🗺️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    aliases: ['source map', 'sourcemap', '源码映射', 'sourceMap'],
    keywords: ['sourcemap', 'source map', '源码', '映射', '还原', 'map'],
    capabilities: ['copy', 'export', 'detail'],
  },

  // ===== 工具 (Tools) =====
  {
    id: 'links',
    label: '链接提取',
    icon: '🔗',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['链接', '提取链接', 'extract links'],
    keywords: ['链接', '提取', 'url', 'href', 'handoff'],
    capabilities: ['target-url', 'copy', 'export', 'handoff'],
    supportsAutoRun: true,
  },
  {
    id: 'multiurl',
    label: 'URL多开',
    icon: '📑',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['url多开', '批量打开', 'multi url'],
    keywords: ['多开', '批量', 'url', '打开', 'handoff'],
    capabilities: ['task', 'copy', 'export', 'handoff'],
  },
  {
    id: 'history',
    label: '历史档案',
    icon: '📜',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['历史', '扫描历史', 'scan history'],
    keywords: ['历史', '档案', '记录', '扫描', '回跳'],
    capabilities: ['history', 'handoff'],
  },
  {
    id: 'history-archive',
    label: 'Wayback',
    icon: '🗂️',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['wayback', '网页档案馆', '历史存档'],
    keywords: ['wayback', '存档', '历史', 'archive', 'handoff'],
    capabilities: ['target-url', 'copy', 'export', 'handoff'],
    supportsAutoRun: true,
  },
  {
    id: 'tabsave',
    label: '标签保存',
    icon: '📑',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['标签', '保存标签', '会话保存'],
    keywords: ['标签', '保存', 'tab', '会话', '恢复'],
    capabilities: ['export'],
  },
  {
    id: 'exif',
    label: 'EXIF查看',
    icon: '📷',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['exif', '照片信息'],
    keywords: ['exif', '照片', '元数据', 'gps', '图片'],
    capabilities: ['copy', 'detail'],
  },
  {
    id: 'storage-check',
    label: '存储检查',
    icon: '🗄️',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['存储', 'localstorage', '存储审计'],
    keywords: ['存储', 'storage', 'localstorage', 'sessionstorage', 'indexeddb', 'cookie'],
    capabilities: ['target-url', 'copy', 'detail'],
    supportsAutoRun: true,
  },
  {
    id: 'source-loader',
    label: '源码加载',
    icon: '📦',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['源码', '加载源码', 'source loader'],
    keywords: ['源码', '加载', 'source', 'fetch', 'handoff'],
    capabilities: ['copy', 'export', 'handoff'],
  },
  {
    id: 'jsarchive',
    label: 'JS归档',
    icon: '🗜️',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    aliases: ['js归档', 'javascript归档', 'js打包'],
    keywords: ['js', 'javascript', '归档', '打包', '下载', 'zip'],
    capabilities: ['target-url', 'task', 'copy', 'export'],
    supportsAutoRun: true,
  },

  // ===== 报告 (Report) =====
  {
    id: 'report',
    label: '统一报告',
    icon: '📊',
    category: 'report',
    categoryLabel: '报告',
    catColor: '#999',
    aliases: ['报告', '漏洞报告', 'report'],
    keywords: ['报告', '导出', '统计', '漏洞', '汇总'],
    capabilities: ['filter', 'export', 'history'],
  },
];
