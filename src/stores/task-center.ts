/**
 * 任务中心（历史聚合）— 灵眸 v6.0（对齐 docs/UX-UI优化建议.md §9.2 / §6.3）
 *
 * 聚合各面板 TaskController 的「已结束」任务（succeeded/partial/cancelled/failed），
 * 供 StatusBar 最近任务气泡展示与回跳。最近 20 条，持久化 storage.local。
 *
 * 务实范围（架构限制）：Svelte 5 side-panel {#key activePanel} 卸载组件，controller 是
 * 组件级闭包，切走面板时运行中任务中断。故本 store 只记录已结束任务，不做运行中实时聚合
 * （那需把 controller 提升为模块级单例 + 回改 5 面板，留独立重构）。
 *
 * 模式复用 recent-targets.ts：writable + reload + storage.onChanged + 串行写队列。
 */

import { writable, type Readable } from 'svelte/store';

const STORAGE_KEY = 'taskCenter';
const MAX_RECORDS = 20;

export type TaskRecordStatus = 'succeeded' | 'partial' | 'cancelled' | 'failed';

export interface TaskRecord {
  id: string;
  panel: string;
  label: string;
  status: TaskRecordStatus;
  summary?: string;
  finishedAt: number;
}

const STATUS_VALUES: TaskRecordStatus[] = ['succeeded', 'partial', 'cancelled', 'failed'];

function isStatus(v: unknown): v is TaskRecordStatus {
  return typeof v === 'string' && (STATUS_VALUES as string[]).includes(v);
}

function normalize(raw: unknown): TaskRecord[] {
  if (!Array.isArray(raw)) return [];
  const out: TaskRecord[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    if (typeof r.id !== 'string' || typeof r.panel !== 'string' || !isStatus(r.status)) continue;
    out.push({
      id: r.id,
      panel: r.panel,
      label: typeof r.label === 'string' ? r.label : r.panel,
      status: r.status,
      summary: typeof r.summary === 'string' ? r.summary : undefined,
      finishedAt: typeof r.finishedAt === 'number' ? r.finishedAt : 0,
    });
  }
  return out.slice(0, MAX_RECORDS);
}

function create(): Readable<TaskRecord[]> & {
  report(rec: Omit<TaskRecord, 'id' | 'finishedAt'>): void;
  clear(): Promise<void>;
  reload(): Promise<void>;
} {
  const store = writable<TaskRecord[]>([]);

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

  let writeQueue: Promise<TaskRecord[]> = Promise.resolve([]);

  function enqueue(fn: (cur: TaskRecord[]) => TaskRecord[]): void {
    writeQueue = writeQueue.then((cur) => {
      const next = fn(cur);
      store.set(next);
      browser.storage.local.set({ [STORAGE_KEY]: next }).catch(() => {});
      return next;
    });
  }

  function report(rec: Omit<TaskRecord, 'id' | 'finishedAt'>): void {
    const now = Date.now();
    const full: TaskRecord = {
      ...rec,
      id: `${now}-${Math.random().toString(36).slice(2, 8)}`,
      finishedAt: now,
    };
    enqueue((cur) => [full, ...cur].slice(0, MAX_RECORDS));
  }

  async function clear(): Promise<void> {
    enqueue(() => []);
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

  return { subscribe: store.subscribe, report, clear, reload };
}

export const taskCenterStore = create();
