/**
 * 扫描参数 store — UI 侧响应式封装
 * 供 side-panel 扫描面板与 options 页消费。
 * background 直接用 lib/core/settings.ts 的纯函数，不走此 store。
 */
import { writable } from 'svelte/store';
import {
  DEFAULT_SCAN_SETTINGS,
  loadScanSettings,
  saveScanSettings,
  normalizeScanSettings,
  type ScanSettings,
} from '@/lib/core/settings';

function createScanSettingsStore() {
  const store = writable<ScanSettings>({ ...DEFAULT_SCAN_SETTINGS });

  async function refresh() {
    store.set(await loadScanSettings());
  }

  async function update(patch: Partial<ScanSettings>) {
    await saveScanSettings(patch);
    await refresh();
  }

  // 初始化加载
  refresh();

  // 监听 background/其他页面对 pentestSettings 的改动，保持响应式同步
  if (typeof browser !== 'undefined' && browser.storage?.onChanged) {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.pentestSettings) {
        store.set(normalizeScanSettings((changes.pentestSettings.newValue || {}) as Partial<ScanSettings>));
      }
    });
  }

  return { subscribe: store.subscribe, refresh, update };
}

export const scanSettingsStore = createScanSettingsStore();
