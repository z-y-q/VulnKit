import type { Component } from 'svelte';
import { panelMeta, type PanelMeta } from './registry';
import { panelLoaders } from './loaders';

/**
 * 面板配置 = 元数据（registry 单一数据源）+ 动态加载器（loaders）。
 * side-panel 用 `load()` 按需 import() 对应 chunk，不再首屏加载全部组件。
 */
export interface PanelConfig extends PanelMeta {
  /** 动态加载该面板组件；切换面板时触发，Promise 缓存由 loadPanel 管理（§7.1）。 */
  load: () => Promise<{ default: Component }>;
}

// §7.1：缓存面板 import 的 Promise，使反复切换不重新显示长时间 loading；
// 加载失败时删除缓存，保证重试可重新发起 import（否则永远拿到 rejected Promise）
const panelPromiseCache = new Map<string, Promise<{ default: Component }>>();

function loadPanel(id: string, loader: () => Promise<{ default: Component }>): Promise<{ default: Component }> {
  let p = panelPromiseCache.get(id);
  if (!p) {
    p = loader();
    panelPromiseCache.set(id, p);
    p.catch(() => { panelPromiseCache.delete(id); });
  }
  return p;
}

// 启动期校验：每个 meta.id 必须有对应 loader，缺失即抛错（防 registry/loaders 不同步）。
export const panels: PanelConfig[] = panelMeta.map((meta) => {
  const loader = panelLoaders[meta.id];
  if (!loader) throw new Error(`[panels] missing loader for panel "${meta.id}"`);
  return { ...meta, load: () => loadPanel(meta.id, loader) };
});
