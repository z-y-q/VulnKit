/**
 * 收藏面板（对齐 docs/UX-UI优化建议.md §4.1 / §9.2）
 *
 * 用户显式收藏的面板 id 集合（无序）。Sidebar 顶部「收藏」区与面板项星标共同消费。
 * 模式复用 panel-layout.ts：writable + reload + storage.onChanged + 串行写队列。
 */

import { writable } from 'svelte/store';

const STORAGE_KEY = 'favoritePanels';

function normalize(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of raw) {
    if (typeof x === 'string' && x && !seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}

function create() {
  const store = writable<string[]>([]);

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

  let writeQueue: Promise<string[]> = Promise.resolve([]);

  function enqueue(fn: (cur: string[]) => string[]): Promise<string[]> {
    writeQueue = writeQueue.then((cur) => {
      const next = fn(cur);
      store.set(next);
      browser.storage.local.set({ [STORAGE_KEY]: next }).catch(() => {});
      return next;
    });
    return writeQueue;
  }

  /** 切换收藏状态。 */
  async function toggle(id: string): Promise<void> {
    if (!id) return;
    await enqueue((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
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

  return { subscribe: store.subscribe, toggle, reload };
}

export const favoritePanelsStore = create();
