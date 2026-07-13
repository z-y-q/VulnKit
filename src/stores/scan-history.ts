/**
 * 扫描历史 store — 灵眸 v6.0
 * 持久化所有扫描模块的发现到 browser.storage.local，供「历史档案」「统一报告」面板消费。
 * 去重 + 7 天 TTL + 每域名最多 50 条。
 */
import { writable, type Readable } from 'svelte/store';

const STORAGE_KEY = 'pentest_scan_history';
const MAX_PER_DOMAIN = 50;
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 天
const HARD_CAP = 500; // 条目硬上限：超过才在 addScan 触发裁剪，否则延迟到 refresh
const DEDUP_WINDOW_MS = 60 * 60 * 1000; // 同域同模块 1h 内合并，避免历史堆叠

export type ScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ScanFinding {
  title: string;
  severity: ScanSeverity;
  detail?: string;
  evidence?: string;
  url?: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanHistoryEntry {
  id: string;
  domain: string;
  url: string;
  module: string; // 面板 id，如 'cors' 'xssscan'
  moduleName: string; // 中文标签
  timestamp: number;
  findings: ScanFinding[];
  summary: ScanSummary;
}

/** 模块 id → 中文标签（与 panels 注册表保持一致） */
export const MODULE_LABELS: Record<string, string> = {
  xssscan: 'XSS 扫描',
  cors: 'CORS 检测',
  headers: '安全头',
  waf: 'WAF 指纹',
  redirect: '重定向检测',
  fuzz: '目录扫描',
  graphql: 'GraphQL',
  'cookie-audit': 'Cookie 审计',
  sniff: '网站嗅探',
  subdomain: '子域名',
  'storage-check': '存储检查',
  vue: 'Vue 分析',
  react: 'React 分析',
  angular: 'Angular 分析',
  svelte: 'Svelte 分析',
  ruoyi: 'RuoYi 路由',
  sourcemap: 'Source Map',
  gather: '信息收集',
};

export const SEV_ORDER: Record<ScanSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** 由 findings 计算汇总 */
export function buildSummary(findings: ScanFinding[]): ScanSummary {
  const s: ScanSummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) {
    s.total++;
    const sev = (f.severity || 'info').toLowerCase() as ScanSeverity;
    if (sev in s) s[sev]++;
    else s.info++;
  }
  return s;
}

function genId(): string {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function pruneExpired(entries: ScanHistoryEntry[]): ScanHistoryEntry[] {
  const cutoff = Date.now() - TTL_MS;
  return entries.filter(e => e.timestamp > cutoff);
}

function pruneByDomain(entries: ScanHistoryEntry[]): ScanHistoryEntry[] {
  const byDomain = new Map<string, ScanHistoryEntry[]>();
  for (const e of entries) {
    const arr = byDomain.get(e.domain) || [];
    arr.push(e);
    byDomain.set(e.domain, arr);
  }
  const keep = new Set<string>();
  for (const arr of byDomain.values()) {
    // 保留每个域名最新的 MAX_PER_DOMAIN 条
    arr.slice(-MAX_PER_DOMAIN).forEach(e => keep.add(e.id));
  }
  return entries.filter(e => keep.has(e.id));
}

interface ScanHistoryStore extends Readable<ScanHistoryEntry[]> {
  refresh: () => Promise<void>;
  addScan: (params: {
    url: string;
    module: string;
    moduleName?: string;
    findings: ScanFinding[];
  }) => Promise<void>;
  clear: () => Promise<void>;
  clearDomain: (domain: string) => Promise<void>;
  /** 删除单条记录的唯一入口（UI 不应直接操作 storage）。 */
  deleteEntry: (id: string) => Promise<void>;
}

function createScanHistoryStore(): ScanHistoryStore {
  const store = writable<ScanHistoryEntry[]>([]);

  async function readRaw(): Promise<ScanHistoryEntry[]> {
    try {
      const data = await browser.storage.local.get(STORAGE_KEY);
      return (data[STORAGE_KEY] as ScanHistoryEntry[]) || [];
    } catch {
      return [];
    }
  }

  async function writeRaw(entries: ScanHistoryEntry[]): Promise<void> {
    try {
      await browser.storage.local.set({ [STORAGE_KEY]: entries });
    } catch {
      /* ignore */
    }
  }

  async function refresh() {
    // 面板打开时做完整 compact：清过期 + 每域名裁剪
    const raw = pruneByDomain(pruneExpired(await readRaw()));
    store.set(raw);
  }

  async function addScan(params: {
    url: string;
    module: string;
    moduleName?: string;
    findings: ScanFinding[];
  }) {
    const entry: ScanHistoryEntry = {
      id: genId(),
      domain: extractDomain(params.url),
      url: params.url,
      module: params.module,
      moduleName: params.moduleName || MODULE_LABELS[params.module] || params.module,
      timestamp: Date.now(),
      findings: params.findings,
      summary: buildSummary(params.findings),
    };

    const existing = await readRaw();

    // L2 去重合并：同域同模块在 DEDUP_WINDOW_MS 内 → 覆盖 findings 而非新增
    const recentIdx = existing.findIndex(
      e =>
        e.domain === entry.domain &&
        e.module === entry.module &&
        entry.timestamp - e.timestamp < DEDUP_WINDOW_MS,
    );

    let next: ScanHistoryEntry[];
    if (recentIdx >= 0) {
      next = [...existing];
      next[recentIdx] = {
        ...next[recentIdx],
        findings: entry.findings,
        summary: entry.summary,
        timestamp: entry.timestamp,
        url: entry.url,
      };
    } else {
      next = [...existing, entry];
    }

    // P1 写放大优化：仅在超 HARD_CAP 时做双重 prune；否则完整 prune 延迟到 refresh。
    // 避免每次扫描都 O(n) 双重扫描整个历史。
    if (next.length > HARD_CAP) {
      next = pruneByDomain(pruneExpired(next));
    }

    await writeRaw(next);
    store.set(next);
  }

  async function clear() {
    await writeRaw([]);
    store.set([]);
  }

  async function clearDomain(domain: string) {
    const next = (await readRaw()).filter(e => e.domain !== domain);
    await writeRaw(next);
    store.set(next);
  }

  async function deleteEntry(id: string) {
    const next = (await readRaw()).filter(e => e.id !== id);
    await writeRaw(next);
    store.set(next);
  }

  // 初始化加载
  refresh();

  return { subscribe: store.subscribe, refresh, addScan, clear, clearDomain, deleteEntry };
}

export const scanHistoryStore = createScanHistoryStore();
