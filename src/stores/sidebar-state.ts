/**
 * Sidebar 状态（对齐 docs/UX-UI优化建议.md §4.1.3）
 *
 * 仅持久化「分类折叠状态」。分类折叠此前存内存（重启丢失），现落盘 storage.local。
 *
 * iconMode（窄宽折叠为图标栏）不由本 store 管理：它由 side-panel 的 ResizeObserver
 * 检测容器宽度驱动，叠加用户的临时手动覆盖，均为会话内状态、不持久化（重启回到宽度驱动，
 * 行为可预测）。见 side-panel/App.svelte 的 narrow/manualIconMode 逻辑。
 */

import { writable } from 'svelte/store';

const STORAGE_KEY = 'sidebarState';

export interface SidebarState {
  /** category id → 是否折叠 */
  collapsedCats: Record<string, boolean>;
}

const EMPTY: SidebarState = { collapsedCats: {} };

function normalize(raw: unknown): SidebarState {
  if (!raw || typeof raw !== 'object') return { ...EMPTY };
  const c = (raw as any).collapsedCats;
  return {
    collapsedCats: c && typeof c === 'object' ? { ...c } : {},
  };
}

function create() {
  const store = writable<SidebarState>({ ...EMPTY });

  async function reload(): Promise<void> {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const next = normalize(r?.[STORAGE_KEY]);
      store.set(next);
      writeQueue = Promise.resolve(next);
    } catch {
      /* ignore */
    }
  }

  let writeQueue: Promise<SidebarState> = Promise.resolve({ ...EMPTY });

  function enqueue(fn: (cur: SidebarState) => SidebarState): Promise<SidebarState> {
    writeQueue = writeQueue.then((cur) => {
      const next = fn(cur);
      store.set(next);
      browser.storage.local.set({ [STORAGE_KEY]: next }).catch(() => {});
      return next;
    });
    return writeQueue;
  }

  async function toggleCat(cat: string): Promise<void> {
    if (!cat) return;
    await enqueue((cur) => ({
      collapsedCats: { ...cur.collapsedCats, [cat]: !cur.collapsedCats[cat] },
    }));
  }

  if (typeof browser !== 'undefined' && browser.storage?.local) {
    reload();
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[STORAGE_KEY]) {
        const next = normalize(changes[STORAGE_KEY].newValue);
        store.set(next);
        writeQueue = Promise.resolve(next);
      }
    });
  }

  return { subscribe: store.subscribe, toggleCat, reload };
}

export const sidebarStateStore = create();
