/**
 * 面板动态加载器
 * 每个面板按需 import()，side-panel 切换时才拉取对应 chunk，
 * 避免首屏一次性加载全部 36 个面板组件。
 *
 * key 必须与 registry.ts 中 panelMeta 的 id 一一对应；
 * index.ts 会在启动时校验每个 meta.id 都有对应 loader，缺失即抛错。
 *
 * §7.1：Promise 缓存避免重复 import；失败时删除 cache 允许重试；
 * 可选预加载入口供 Sidebar hover/idle 时预热。
 */
import type { Component } from 'svelte';

type PanelLoader = () => Promise<{ default: Component }>;

// Promise 缓存：成功则复用，失败则删除允许重试
const loaderCache = new Map<string, Promise<{ default: Component }>>();

/**
 * 加载面板组件（带缓存）
 * @param id 面板 id（registry.ts 中的 meta.id）
 * @returns 组件模块 Promise
 */
export function loadPanel(id: string): Promise<{ default: Component }> {
  const cached = loaderCache.get(id);
  if (cached) return cached;

  const loader = panelLoaders[id];
  if (!loader) {
    const err = new Error(`Panel loader not found: ${id}`);
    return Promise.reject(err);
  }

  const promise = loader().catch((err) => {
    // 失败时删除缓存，允许下次重试（网络恢复/chunk 重新部署等场景）
    loaderCache.delete(id);
    throw err;
  });

  loaderCache.set(id, promise);
  return promise;
}

/**
 * 预加载面板（可选，供 Sidebar hover/idle 时预热）
 * @param ids 要预加载的面板 id 列表
 */
export function preloadPanels(ids: string[]): void {
  for (const id of ids) {
    if (!loaderCache.has(id) && panelLoaders[id]) {
      loadPanel(id).catch(() => { /* 预加载失败静默，不影响实际切换时重试 */ });
    }
  }
}

/**
 * 原始 loader 映射表（仅供 loadPanel 内部调用 + index.ts 启动校验）
 */
export const panelLoaders: Record<string, PanelLoader> = {
  // ===== 侦察 (Recon) =====
  favicon: () => import('./favicon/FaviconPanel.svelte'),
  gather: () => import('./gather/GatherPanel.svelte'),
  subdomain: () => import('./subdomain/SubdomainPanel.svelte'),
  asset: () => import('./asset/AssetPanel.svelte'),

  // ===== 扫描 (Scan) =====
  xssscan: () => import('./xss/XssPanel.svelte'),
  sqliscan: () => import('./sqli/SqliPanel.svelte'),
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
