/**
 * 最近目标 URL — 灵眸 v6.0（对齐 docs/UX-UI优化建议.md §4.1 / §9.2）
 *
 * 扫描类面板启动扫描时 record(url, panel)，UrlInput focus 时显示候选下拉回填，
 * 避免每次切面板重新粘贴 URL。跨面板共享（扫描 a.com 后切 cors 仍可见候选）。
 *
 * 模式复用 recent-panels.ts：writable + reload + storage.onChanged 热更新 + 串行写队列。
 * 去重按 url（同 url 不同面板用 latest 覆盖），最多保留 10 项。
 */

import { writable, type Readable } from 'svelte/store';

const STORAGE_KEY = 'recentTargets';
const MAX_TARGETS = 10;

export interface RecentTarget {
  url: string;
  domain: string;
  panel: string;
  usedAt: number;
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname || '';
  } catch {
    return '';
  }
}

function normalize(raw: unknown): RecentTarget[] {
  if (!Array.isArray(raw)) return [];
  const out: RecentTarget[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    if (typeof r.url !== 'string') continue;
    out.push({
      url: r.url,
      domain: typeof r.domain === 'string' ? r.domain : extractDomain(r.url),
      panel: typeof r.panel === 'string' ? r.panel : '',
      usedAt: typeof r.usedAt === 'number' ? r.usedAt : 0,
    });
  }
  return out.slice(0, MAX_TARGETS);
}

function create(): Readable<RecentTarget[]> & {
  record(url: string, panel: string): Promise<void>;
  remove(url: string): Promise<void>;
  clear(): Promise<void>;
  reload(): Promise<void>;
} {
  const store = writable<RecentTarget[]>([]);

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

  let writeQueue: Promise<RecentTarget[]> = Promise.resolve([]);

  function enqueue(fn: (cur: RecentTarget[]) => RecentTarget[]): Promise<RecentTarget[]> {
    writeQueue = writeQueue.then((cur) => {
      const next = fn(cur);
      store.set(next);
      browser.storage.local.set({ [STORAGE_KEY]: next }).catch(() => {});
      return next;
    });
    return writeQueue;
  }

  async function record(url: string, panel: string): Promise<void> {
    const trimmed = url?.trim();
    if (!trimmed || !/^https?:\/\//i.test(trimmed)) return;
    const entry: RecentTarget = { url: trimmed, domain: extractDomain(trimmed), panel, usedAt: Date.now() };
    await enqueue((cur) => [entry, ...cur.filter((x) => x.url !== trimmed)].slice(0, MAX_TARGETS));
  }

  async function remove(url: string): Promise<void> {
    await enqueue((cur) => cur.filter((x) => x.url !== url));
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
        writeQueue = Promise.resolve(next);
      }
    });
  }

  return { subscribe: store.subscribe, record, remove, clear, reload };
}

export const recentTargetsStore = create();
