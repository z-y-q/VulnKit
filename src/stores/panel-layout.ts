/**
 * 面板布局偏好
 * 用户可在选项页拖拽排序 / 勾选显示隐藏面板（对齐 v5 工具栏配置）。
 * 持久化到 storage.local（key: panelLayout）。popup 与 sidebar 共同消费。
 */

import { writable, type Writable } from 'svelte/store';

const STORAGE_KEY = 'panelLayout';

export interface PanelLayout {
  /** 自定义顺序的面板 id（在前）；未列入的按原默认顺序追加 */
  order: string[];
  /** 被隐藏的面板 id 集合 */
  hidden: string[];
}

const EMPTY: PanelLayout = { order: [], hidden: [] };

function normalize(raw: any): PanelLayout {
  if (!raw || typeof raw !== 'object') return { ...EMPTY };
  return {
    order: Array.isArray(raw.order) ? raw.order.filter((x: any) => typeof x === 'string') : [],
    hidden: Array.isArray(raw.hidden) ? raw.hidden.filter((x: any) => typeof x === 'string') : [],
  };
}

function create(): Writable<PanelLayout> & {
  reload: () => Promise<void>;
  setOrder: (order: string[]) => Promise<void>;
  toggleHidden: (id: string) => Promise<void>;
  reset: () => Promise<void>;
} {
  const store = writable<PanelLayout>(EMPTY);

  async function reload() {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const next = normalize(r?.[STORAGE_KEY]);
      store.set(next);
      writeQueue = Promise.resolve(next); // 用磁盘状态重置写队列基线
    } catch { /* ignore */ }
  }

  // 串行写队列：所有变更依次「读最新结果 → 计算 → store.set + 落盘」，
  // 杜绝并发 toggle/order 时的 stale-read 与 last-write-wins。
  let writeQueue: Promise<PanelLayout> = Promise.resolve({ ...EMPTY });

  function enqueue(fn: (cur: PanelLayout) => PanelLayout): Promise<PanelLayout> {
    writeQueue = writeQueue.then((cur) => {
      const next = fn(cur);
      store.set(next);
      browser.storage.local.set({ [STORAGE_KEY]: next }).catch(() => {});
      return next;
    });
    return writeQueue;
  }

  async function setOrder(order: string[]) {
    await enqueue(cur => ({ order, hidden: cur.hidden }));
  }

  async function toggleHidden(id: string) {
    await enqueue(cur => {
      const hidden = cur.hidden.includes(id) ? cur.hidden.filter(x => x !== id) : [...cur.hidden, id];
      return { order: cur.order, hidden };
    });
  }

  async function reset() {
    await enqueue(() => ({ ...EMPTY }));
  }

  // 初始化 + 监听变更（options 页修改后 popup/sidebar 热更新）
  if (typeof browser !== 'undefined' && browser.storage?.local) {
    reload();
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[STORAGE_KEY]) {
        const next = normalize(changes[STORAGE_KEY].newValue);
        store.set(next);
        writeQueue = Promise.resolve(next); // 外部写入后重置基线，避免本地队列回滚
      }
    });
  }

  return { ...store, reload, setOrder, toggleHidden, reset };
}

export const panelLayoutStore = create();

/**
 * 按 layout.order 对列表重排（不过滤 hidden）。
 * order 中未列出的项保持原相对顺序追加在后。供 options 编辑页（需保留隐藏项）使用。
 */
export function sortByLayout<T extends { id: string }>(list: T[], layout: PanelLayout): T[] {
  if (!layout.order.length) return [...list];
  const idx = new Map(layout.order.map((id, i) => [id, i]));
  return [...list].sort((a, b) => {
    const ia = idx.has(a.id) ? idx.get(a.id)! : 1e9;
    const ib = idx.has(b.id) ? idx.get(b.id)! : 1e9;
    return ia - ib;
  });
}

/**
 * 对面板元数据列表应用布局：先按 order 重排，再过滤 hidden。
 * sidebar / popup 等只读消费方统一用这个，保证顺序与可见性与 options 编辑一致。
 */
export function applyLayout<T extends { id: string }>(list: T[], layout: PanelLayout): T[] {
  const visible = list.filter(p => !layout.hidden.includes(p.id));
  return sortByLayout(visible, layout);
}
