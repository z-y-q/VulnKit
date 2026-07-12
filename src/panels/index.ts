import type { Component } from 'svelte';
import EncodingPanel from './encoding/EncodingPanel.svelte';
import JsCtrlPanel from './jsctrl/JsCtrlPanel.svelte';
import PayloadPanel from './payload/PayloadPanel.svelte';
import GatherPanel from './gather/GatherPanel.svelte';
import SpoofPanel from './spoof/SpoofPanel.svelte';
import WafPanel from './waf/WafPanel.svelte';
import CookieAuditPanel from './cookie-audit/CookieAuditPanel.svelte';
import CorsPanel from './cors/CorsPanel.svelte';
import RedirectPanel from './redirect/RedirectPanel.svelte';
import FuzzPanel from './fuzz/FuzzPanel.svelte';
import HeadersPanel from './headers/HeadersPanel.svelte';
import GraphqlPanel from './graphql/GraphqlPanel.svelte';
import SubdomainPanel from './subdomain/SubdomainPanel.svelte';
import XssPanel from './xss/XssPanel.svelte';
import VuePanel from './vue/VuePanel.svelte';
import ReactPanel from './react/ReactPanel.svelte';
import AngularPanel from './angular/AngularPanel.svelte';
import SveltePanel from './svelte/SveltePanel.svelte';
import RuoYiPanel from './ruoyi/RuoYiPanel.svelte';
import SourcemapPanel from './sourcemap/SourcemapPanel.svelte';
import SniffPanel from './sniff/SniffPanel.svelte';
import LeakscanPanel from './leakscan/LeakscanPanel.svelte';
import HaePanel from './hae/HaePanel.svelte';
import ReportPanel from './report/ReportPanel.svelte';
import FaviconPanel from './favicon/FaviconPanel.svelte';
import AssetPanel from './asset/AssetPanel.svelte';
import LinksPanel from './links/LinksPanel.svelte';
import ExifPanel from './exif/ExifPanel.svelte';
import StorageCheckPanel from './storage-check/StorageCheckPanel.svelte';
import MultiurlPanel from './multiurl/MultiurlPanel.svelte';
import HistoryPanel from './history/HistoryPanel.svelte';
import HistoryArchivePanel from './history-archive/HistoryArchivePanel.svelte';
import TabsavePanel from './tabsave/TabsavePanel.svelte';
import SourceLoaderPanel from './source-loader/SourceLoaderPanel.svelte';

export interface PanelConfig {
  id: string;
  label: string;
  icon: string;
  category: string;
  categoryLabel: string;
  catColor: string;
  component: Component;
}

// 面板注册表 — 30 个功能面板
// Phase 4 中逐步替换占位符为真实面板组件
export const panels: PanelConfig[] = [
  // ===== 侦察 (Recon) =====
  {
    id: 'favicon',
    label: '图标识别',
    icon: '🖼️',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    component: FaviconPanel,
  },
  {
    id: 'gather',
    label: '信息收集',
    icon: '🔍',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    component: GatherPanel,
  },
  {
    id: 'subdomain',
    label: '子域名',
    icon: '🌐',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    component: SubdomainPanel,
  },
  {
    id: 'asset',
    label: '资产测绘',
    icon: '📍',
    category: 'recon',
    categoryLabel: '侦察',
    catColor: '#4A90E2',
    component: AssetPanel,
  },

  // ===== 扫描 (Scan) =====
  {
    id: 'xssscan',
    label: 'XSS扫描',
    icon: '⚡',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: XssPanel,
  },
  {
    id: 'cors',
    label: 'CORS检测',
    icon: '🔗',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: CorsPanel,
  },
  {
    id: 'headers',
    label: '安全头',
    icon: '🛡️',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: HeadersPanel,
  },
  {
    id: 'waf',
    label: 'WAF指纹',
    icon: '🔥',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: WafPanel,
  },
  {
    id: 'redirect',
    label: '重定向',
    icon: '↗️',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: RedirectPanel,
  },
  {
    id: 'fuzz',
    label: '目录扫描',
    icon: '📂',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: FuzzPanel,
  },
  {
    id: 'graphql',
    label: 'GraphQL',
    icon: '◈',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: GraphqlPanel,
  },
  {
    id: 'cookie-audit',
    label: 'Cookie审计',
    icon: '🍪',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: CookieAuditPanel,
  },
  {
    id: 'sniff',
    label: '网站嗅探',
    icon: '👃',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: SniffPanel,
  },
  {
    id: 'leakscan',
    label: '泄露扫描',
    icon: '🔓',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: LeakscanPanel,
  },
  {
    id: 'hae',
    label: 'HAE规则',
    icon: '🎨',
    category: 'scan',
    categoryLabel: '扫描',
    catColor: '#e74c3c',
    component: HaePanel,
  },

  // ===== 利用 (Exploit) =====
  {
    id: 'encoding',
    label: '编码工具',
    icon: '🔤',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    component: EncodingPanel,
  },
  {
    id: 'payload',
    label: 'Payload',
    icon: '💊',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    component: PayloadPanel,
  },
  {
    id: 'spoof',
    label: '请求伪造',
    icon: '🎭',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    component: SpoofPanel,
  },
  {
    id: 'jsctrl',
    label: 'JS控制',
    icon: '⚙️',
    category: 'exploit',
    categoryLabel: '利用',
    catColor: '#e67e22',
    component: JsCtrlPanel,
  },

  // ===== 框架 (Framework) =====
  {
    id: 'vue',
    label: 'Vue分析',
    icon: '🟢',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: VuePanel,
  },
  {
    id: 'react',
    label: 'React分析',
    icon: '⚛️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: ReactPanel,
  },
  {
    id: 'angular',
    label: 'Angular分析',
    icon: '🅰️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: AngularPanel,
  },
  {
    id: 'svelte',
    label: 'Svelte分析',
    icon: '🔶',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: SveltePanel,
  },
  {
    id: 'ruoyi',
    label: 'RuoYi路由',
    icon: '📁',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: RuoYiPanel,
  },
  {
    id: 'sourcemap',
    label: 'Source Map',
    icon: '🗺️',
    category: 'framework',
    categoryLabel: '框架',
    catColor: '#27ae60',
    component: SourcemapPanel,
  },

  // ===== 工具 (Tools) =====
  {
    id: 'links',
    label: '链接提取',
    icon: '🔗',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: LinksPanel,
  },
  {
    id: 'multiurl',
    label: 'URL多开',
    icon: '📑',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: MultiurlPanel,
  },
  {
    id: 'history',
    label: '历史档案',
    icon: '📜',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: HistoryPanel,
  },
  {
    id: 'history-archive',
    label: 'Wayback',
    icon: '🗂️',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: HistoryArchivePanel,
  },
  {
    id: 'tabsave',
    label: '标签保存',
    icon: '📑',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: TabsavePanel,
  },
  {
    id: 'exif',
    label: 'EXIF查看',
    icon: '📷',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: ExifPanel,
  },
  {
    id: 'storage-check',
    label: '存储检查',
    icon: '🗄️',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: StorageCheckPanel,
  },
  {
    id: 'source-loader',
    label: '源码加载',
    icon: '📦',
    category: 'tools',
    categoryLabel: '工具',
    catColor: '#9b59b6',
    component: SourceLoaderPanel,
  },

  // ===== 报告 (Report) =====
  {
    id: 'report',
    label: '统一报告',
    icon: '📊',
    category: 'report',
    categoryLabel: '报告',
    catColor: '#999',
    component: ReportPanel,
  },
];
