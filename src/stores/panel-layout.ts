/**
 * 面板布局偏好 — 灵眸 v6.0
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
      store.set(normalize(r?.[STORAGE_KEY]));
    } catch { /* ignore */ }
  }

  async function persist(layout: PanelLayout) {
    store.set(layout);
    try { await browser.storage.local.set({ [STORAGE_KEY]: layout }); } catch { /* */ }
  }

  async function setOrder(order: string[]) {
    const cur = await new Promise<PanelLayout>(res => store.subscribe(v => res(v))());
    persist({ order, hidden: cur.hidden });
  }

  async function toggleHidden(id: string) {
    const cur = await new Promise<PanelLayout>(res => store.subscribe(v => res(v))());
    const hidden = cur.hidden.includes(id) ? cur.hidden.filter(x => x !== id) : [...cur.hidden, id];
    persist({ order: cur.order, hidden });
  }

  async function reset() {
    persist({ ...EMPTY });
  }

  // 初始化 + 监听变更（options 页修改后 popup/sidebar 热更新）
  if (typeof browser !== 'undefined' && browser.storage?.local) {
    reload();
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[STORAGE_KEY]) {
        store.set(normalize(changes[STORAGE_KEY].newValue));
      }
    });
  }

  return { ...store, reload, setOrder, toggleHidden, reset };
}

export const panelLayoutStore = create();

/**
 * 对面板元数据列表应用布局：按 order 重排，过滤 hidden。
 * @param list 原始面板元数据（含 id）
 */
export function applyLayout<T extends { id: string }>(list: T[], layout: PanelLayout): T[] {
  const visible = list.filter(p => !layout.hidden.includes(p.id));
  if (!layout.order.length) return visible;
  const idx = new Map(layout.order.map((id, i) => [id, i]));
  return [...visible].sort((a, b) => {
    const ia = idx.has(a.id) ? idx.get(a.id)! : 1e9;
    const ib = idx.has(b.id) ? idx.get(b.id)! : 1e9;
    return ia - ib;
  });
}
