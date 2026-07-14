/**
 * 跨面板分析上下文（对齐 docs/UX-UI优化建议.md §6.3 / §9.2）
 *
 * 统一替代散落的 `lingmou:{multiurl,fuzz,source}-pending` 字符串 storage key。
 * 一个面板 handoff 到另一面板：写 context + 自动切到目标面板（可选）+ 来源横幅提示。
 *
 * 单槽覆盖范式（同 pending-actions / recent-panels）：同一时刻只有一个待消费 context。
 * 持久化到 browser.storage.local，onChanged 跨 popup/side-panel 热更新。
 *
 * 时序：handoff(navigate=true) → 写 context + 切目标面板 → 目标面板 mount effect 调
 * consume(selfId) 读 payload 填入并清除 storage → 横幅消失。navigate=false 或用户在
 * 非目标面板时，ContextBanner 持续显示「有待处理数据 → 目标 [前往][清除]」引导投递。
 */

import { writable, get, type Readable } from 'svelte/store';
import { activePanelStore, toastStore } from '@/stores/ui';
import { panelMeta } from '@/panels/registry';

const STORAGE_KEY = 'lingmou:analysis-context';
const TTL_MS = 5 * 60 * 1000; // 5 分钟未消费自动过期清理

/** panel id → 中文标签，供 handoff toast 与横幅显示 */
const PANEL_LABELS: Record<string, string> = Object.fromEntries(
  panelMeta.map((p) => [p.id, p.label]),
);

export interface AnalysisContext {
  /** 幂等 id（nonce） */
  id: string;
  /** 来源面板 id（如 'gather'） */
  sourcePanel: string;
  /** 来源中文标签（如 '信息收集'） */
  sourceLabel: string;
  /** 目标面板 id（如 'source-loader'） */
  targetPanel: string;
  /** 结构化载荷（{text}|{paths}|{targetUrl} …），由目标面板按 key 取 */
  payload: Record<string, string>;
  /** 横幅摘要（如 '12 个 URL'） */
  summary?: string;
  createdAt: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object';
}

function normalize(raw: unknown): AnalysisContext | null {
  if (!isRecord(raw)) return null;
  if (typeof raw.sourcePanel !== 'string' || typeof raw.targetPanel !== 'string') return null;
  const payload: Record<string, string> = isRecord(raw.payload)
    ? Object.fromEntries(
        Object.entries(raw.payload).filter(
          (entry): entry is [string, string] => typeof entry[1] === 'string',
        ),
      )
    : {};
  const ctx: AnalysisContext = {
    id: typeof raw.id === 'string' ? raw.id : '',
    sourcePanel: raw.sourcePanel,
    sourceLabel: typeof raw.sourceLabel === 'string' ? raw.sourceLabel : '',
    targetPanel: raw.targetPanel,
    payload,
    summary: typeof raw.summary === 'string' ? raw.summary : undefined,
    createdAt: typeof raw.createdAt === 'number' ? raw.createdAt : 0,
  };
  // 过期则视为不存在
  if (ctx.createdAt && Date.now() - ctx.createdAt > TTL_MS) return null;
  return ctx;
}

function create(): Readable<AnalysisContext | null> & {
  handoff(
    ctx: Omit<AnalysisContext, 'id' | 'createdAt'>,
    opts?: { navigate?: boolean },
  ): Promise<void>;
  /** 读 + 清（一次性）；仅当 targetPanel 匹配才返回并清除，否则返回 null */
  consume(targetPanel: string): Promise<AnalysisContext | null>;
  /** 条件消费单个 payload key：仅当 targetPanel 匹配且 payload[key] 存在才返回值并清除。
   *  无此 key 时返回 null 且不清除（供多个消费者各取各的 key，如 UrlInput 取 targetUrl、面板 effect 取 paths） */
  consumePayload(targetPanel: string, key: string): Promise<string | null>;
  /** 读不删；供横幅/预览 */
  peek(): AnalysisContext | null;
  clear(): Promise<void>;
  /** 切回来源面板（context 未消费时有效） */
  back(): void;
  reload(): Promise<void>;
} {
  const store = writable<AnalysisContext | null>(null);

  async function reload(): Promise<void> {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const next = normalize(r?.[STORAGE_KEY]);
      store.set(next);
      if (next === null && r?.[STORAGE_KEY] !== undefined) {
        // 过期或脏数据：清理磁盘残留
        await browser.storage.local.remove(STORAGE_KEY).catch(() => {});
      }
    } catch {
      /* ignore */
    }
  }

  async function persist(next: AnalysisContext | null): Promise<void> {
    store.set(next);
    try {
      if (next === null) await browser.storage.local.remove(STORAGE_KEY);
      else await browser.storage.local.set({ [STORAGE_KEY]: next });
    } catch {
      /* ignore */
    }
  }

  async function handoff(
    ctx: Omit<AnalysisContext, 'id' | 'createdAt'>,
    opts: { navigate?: boolean } = {},
  ): Promise<void> {
    const full: AnalysisContext = {
      ...ctx,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: Date.now(),
    };
    await persist(full);
    const label = PANEL_LABELS[ctx.targetPanel] ?? ctx.targetPanel;
    toastStore.show(
      ctx.summary ? `已发送 ${ctx.summary} 到「${label}」` : `已发送到「${label}」`,
      'success',
    );
    if (opts.navigate !== false) {
      activePanelStore.set(ctx.targetPanel);
    }
  }

  async function consume(targetPanel: string): Promise<AnalysisContext | null> {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const cur = normalize(r?.[STORAGE_KEY]);
      if (!cur || cur.targetPanel !== targetPanel) return null;
      await persist(null); // 一次性消费
      return cur;
    } catch {
      return null;
    }
  }

  async function consumePayload(targetPanel: string, key: string): Promise<string | null> {
    try {
      const r = await browser.storage.local.get(STORAGE_KEY);
      const cur = normalize(r?.[STORAGE_KEY]);
      if (!cur || cur.targetPanel !== targetPanel) return null;
      const v = cur.payload[key];
      if (typeof v !== 'string' || !v) return null; // 无此 key：不消费、不清除
      await persist(null); // 有此 key：消费并清除（context 实际单 key，整体清空安全）
      return v;
    } catch {
      return null;
    }
  }

  function peek(): AnalysisContext | null {
    return get(store);
  }

  async function clear(): Promise<void> {
    await persist(null);
  }

  function back(): void {
    const cur = get(store);
    if (cur?.sourcePanel) activePanelStore.set(cur.sourcePanel);
  }

  if (typeof browser !== 'undefined' && browser.storage?.local) {
    reload();
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[STORAGE_KEY]) {
        store.set(normalize(changes[STORAGE_KEY].newValue));
      }
    });
  }

  return { subscribe: store.subscribe, handoff, consume, consumePayload, peek, clear, back, reload };
}

export const analysisContextStore = create();

export { PANEL_LABELS };
