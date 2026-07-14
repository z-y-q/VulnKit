// 嗅探徽标 store
// 嗅探完成后，将识别到的框架/库（带版本号）写入侧栏按钮徽标。
// 持久化到 storage.session：侧栏重开/面板切换不丢失，浏览器关闭即清空。

import { writable } from 'svelte/store';

export interface SniffBadgeItem {
  name: string;
  version?: string;
}

interface SniffBadgeState {
  items: SniffBadgeItem[];
  updatedAt: number;
}

const STORAGE_KEY = 'sniffBadge';
const EMPTY: SniffBadgeState = { items: [], updatedAt: 0 };

function createSniffBadgeStore() {
  const store = writable<SniffBadgeState>(EMPTY);

  // 初始化：从 storage.session 读取上次嗅探结果
  if (typeof browser !== 'undefined' && browser.storage?.session) {
    browser.storage.session.get(STORAGE_KEY).then((r) => {
      const v = r?.[STORAGE_KEY] as SniffBadgeState | undefined;
      if (v && Array.isArray(v.items)) {
        store.set(v);
      }
    }).catch(() => { /* session storage 不可用则降级为内存 */ });
  }

  function set(items: SniffBadgeItem[]) {
    const state: SniffBadgeState = { items: items.slice(0, 5), updatedAt: Date.now() };
    store.set(state);
    if (browser.storage?.session) {
      browser.storage.session.set({ [STORAGE_KEY]: state }).catch(() => {});
    }
  }

  function clear() {
    store.set(EMPTY);
    if (browser.storage?.session) {
      browser.storage.session.remove(STORAGE_KEY).catch(() => {});
    }
  }

  return { subscribe: store.subscribe, set, clear };
}

export const sniffBadgeStore = createSniffBadgeStore();
