/**
 * 最近使用面板 — 灵眸 v6.0（对齐 docs/UX-UI优化建议.md §4.1 / §9.2）
 *
 * 记录用户在 Sidebar / Popup 打开过的面板 id，置顶去重，最多保留 8 项。
 * Sidebar 顶部「最近」区与 Popup「最近使用」区共同消费。
 *
 * 模式复用 panel-layout.ts：writable + reload + storage.onChanged 热更新 + 串行写队列
 * （防并发 record 时的 stale-read / last-write-wins）。
 */

import { writable } from 'svelte/store';

const STORAGE_KEY = 'recentPanels';
const MAX_RECENT = 8;

function normalize(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === 'string').slice(0, MAX_RECENT);
}

function create() {
  const store = writable<string[]>([]);

  async function reload(): Promise<void> {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const next = normalize(r?.[STORAGE_KEY]);
      store.set(next);
      writeQueue = Promise.resolve(next); // 用磁盘状态重置写队列基线
    } catch {
      /* ignore */
    }
  }

  // 串行写队列：所有变更依次「读最新结果 → 计算 → store.set + 落盘」。
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

  /** 记录一次使用：置顶去重，截断到上限。 */
  async function record(id: string): Promise<void> {
    if (!id) return;
    await enqueue((cur) => [id, ...cur.filter((x) => x !== id)].slice(0, MAX_RECENT));
  }

  async function clear(): Promise<void> {
    await enqueue(() => []);
  }

  if (typeof browser !== 'undefined' && browser.storage?.local) {
    reload();
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[STORAGE_KEY]) {
        const next = normalize(changes[STORAGE_KEY].newValue);
        store.set(next);
        writeQueue = Promise.resolve(next); // 外部写入后重置基线
      }
    });
  }

  return { subscribe: store.subscribe, record, clear, reload };
}

export const recentPanelsStore = create();
