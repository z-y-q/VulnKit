/**
 * 面板动态加载器 — 灵眸 v6.0
 * 每个面板按需 import()，side-panel 切换时才拉取对应 chunk，
 * 避免首屏一次性加载全部 35 个面板组件。
 *
 * key 必须与 registry.ts 中 panelMeta 的 id 一一对应；
 * index.ts 会在启动时校验每个 meta.id 都有对应 loader，缺失即抛错。
 */
import type { Component } from 'svelte';

type PanelLoader = () => Promise<{ default: Component }>;

export const panelLoaders: Record<string, PanelLoader> = {
  // ===== 侦察 (Recon) =====
  favicon: () => import('./favicon/FaviconPanel.svelte'),
  gather: () => import('./gather/GatherPanel.svelte'),
  subdomain: () => import('./subdomain/SubdomainPanel.svelte'),
  asset: () => import('./asset/AssetPanel.svelte'),

  // ===== 扫描 (Scan) =====
  xssscan: () => import('./xss/XssPanel.svelte'),
  cors: () => import('./cors/CorsPanel.svelte'),
  headers: () => import('./headers/HeadersPanel.svelte'),
  waf: () => import('./waf/WafPanel.svelte'),
  redirect: () => import('./redirect/RedirectPanel.svelte'),
  fuzz: () => import('./fuzz/FuzzPanel.svelte'),
  graphql: () => import('./graphql/GraphqlPanel.svelte'),
  'cookie-audit': () => import('./cookie-audit/CookieAuditPanel.svelte'),
  sniff: () => import('./sniff/SniffPanel.svelte'),
  leakscan: () => import('./leakscan/LeakscanPanel.svelte'),
  hae: () => import('./hae/HaePanel.svelte'),

  // ===== 利用 (Exploit) =====
  encoding: () => import('./encoding/EncodingPanel.svelte'),
  payload: () => import('./payload/PayloadPanel.svelte'),
  spoof: () => import('./spoof/SpoofPanel.svelte'),
  jsctrl: () => import('./jsctrl/JsCtrlPanel.svelte'),

  // ===== 框架 (Framework) =====
  vue: () => import('./vue/VuePanel.svelte'),
  react: () => import('./react/ReactPanel.svelte'),
  angular: () => import('./angular/AngularPanel.svelte'),
  svelte: () => import('./svelte/SveltePanel.svelte'),
  ruoyi: () => import('./ruoyi/RuoYiPanel.svelte'),
  sourcemap: () => import('./sourcemap/SourcemapPanel.svelte'),

  // ===== 工具 (Tools) =====
  links: () => import('./links/LinksPanel.svelte'),
  multiurl: () => import('./multiurl/MultiurlPanel.svelte'),
  history: () => import('./history/HistoryPanel.svelte'),
  'history-archive': () => import('./history-archive/HistoryArchivePanel.svelte'),
  tabsave: () => import('./tabsave/TabsavePanel.svelte'),
  exif: () => import('./exif/ExifPanel.svelte'),
  'storage-check': () => import('./storage-check/StorageCheckPanel.svelte'),
  'source-loader': () => import('./source-loader/SourceLoaderPanel.svelte'),
  jsarchive: () => import('./jsarchive/JsArchivePanel.svelte'),

  // ===== 报告 (Report) =====
  report: () => import('./report/ReportPanel.svelte'),
};
