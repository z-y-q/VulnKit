import type { Component } from 'svelte';
import { panelMeta, type PanelMeta } from './registry';
import { panelLoaders } from './loaders';

/**
 * 面板配置 = 元数据（registry 单一数据源）+ 动态加载器（loaders）。
 * side-panel 用 `load()` 按需 import() 对应 chunk，不再首屏加载全部组件。
 */
export interface PanelConfig extends PanelMeta {
  /** 动态加载该面板组件；切换面板时触发，模块缓存由打包器管理。 */
  load: () => Promise<{ default: Component }>;
}

// 启动期校验：每个 meta.id 必须有对应 loader，缺失即抛错（防 registry/loaders 不同步）。
export const panels: PanelConfig[] = panelMeta.map((meta) => {
  const load = panelLoaders[meta.id];
  if (!load) throw new Error(`[panels] missing loader for panel "${meta.id}"`);
  return { ...meta, load };
});
