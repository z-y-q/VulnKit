/**
 * 备份/恢复字段白名单 — 灵眸 v6.0（对齐 docs/UX-UI优化建议.md §7.7 / §10.5）
 *
 * 旧实现 `storage.local.get(null)` 无条件导出全部本地存储（含 ZoomEye API Key、伪装状态、
 * pending action），既是安全问题也是 UX 问题。本模块按字段分类建立白名单：
 *
 *   preferences — UI/布局/偏好，默认导出，覆盖导入
 *   rules       — HaE 自定义规则，默认导出，覆盖导入
 *   history     — 扫描历史，默认导出（可关），合并/覆盖可选
 *   secrets     — API Key / 伪装状态，默认**不**导出，导入需单独确认，默认不覆盖本机
 *   transient   — pending / 临时状态，禁止导出与导入
 *   未知 key    — 默认拒绝（防止备份注入任意 storage 项）
 *
 * 备份对象含 schemaVersion / appVersion / exportedAt / categories 摘要，便于导入前预览。
 */

import { getAppVersion } from './app-version';

export const BACKUP_SCHEMA_VERSION = 1;

export type BackupCategory = 'preferences' | 'rules' | 'history' | 'secrets' | 'transient';

export interface FieldSpec {
  key: string;
  category: BackupCategory;
  /** 是否允许写入本机（transient / 未知 key = false） */
  importable: boolean;
}

/** 字段分类白名单。新增 storage key 必须在此登记，否则备份不会包含、导入会被拒绝。 */
export const BACKUP_SCHEMA: FieldSpec[] = [
  // preferences
  { key: 'lingmouPrefs', category: 'preferences', importable: true },
  { key: 'lingmou-theme', category: 'preferences', importable: true },
  { key: 'panelLayout', category: 'preferences', importable: true },
  { key: 'sidebarState', category: 'preferences', importable: true },
  { key: 'recentPanels', category: 'preferences', importable: true },
  { key: 'favoritePanels', category: 'preferences', importable: true },
  { key: 'pentestSettings', category: 'preferences', importable: true },
  // rules
  { key: 'haeCustomRules', category: 'rules', importable: true },
  // history
  { key: 'pentest_scan_history', category: 'history', importable: true },
  // secrets — 默认排除
  { key: 'lingmou_zoomeye_key', category: 'secrets', importable: true },
  { key: 'pentest_spoof', category: 'secrets', importable: true },
  // transient — 永不导出/导入
  { key: 'pendingAction', category: 'transient', importable: false },
  { key: '__pendingCopy', category: 'transient', importable: false },
  { key: '__extractedLinks', category: 'transient', importable: false },
  { key: 'contextSelection', category: 'transient', importable: false },
  { key: 'contextAction', category: 'transient', importable: false },
  { key: 'contextExtractedLinks', category: 'transient', importable: false },
  { key: 'contextExtractedUrl', category: 'transient', importable: false },
];

const KNOWN_KEYS = new Map<string, FieldSpec>(BACKUP_SCHEMA.map((s) => [s.key, s]));

const CATEGORY_ORDER: BackupCategory[] = ['preferences', 'rules', 'history', 'secrets'];

export interface CategorySummary {
  name: BackupCategory;
  count: number;
  bytes: number;
}

export interface BackupBundle {
  schemaVersion: number;
  appVersion: string;
  exportedAt: number;
  categories: CategorySummary[];
  data: Record<string, unknown>;
}

export interface BuildOptions {
  includeSecrets?: boolean;
  includeHistory?: boolean;
}

function sizeof(value: unknown): number {
  try {
    return new Blob([JSON.stringify(value)]).size;
  } catch {
    return 0;
  }
}

/** 按 build 选项读取白名单字段，构建带摘要的备份对象。 */
export async function buildBackup(opts: BuildOptions = {}): Promise<BackupBundle> {
  const { includeSecrets = false, includeHistory = true } = opts;
  const all = await browser.storage.local.get(null);
  const data: Record<string, unknown> = {};
  const catMap = new Map<BackupCategory, CategorySummary>();

  const bump = (cat: BackupCategory, bytes: number) => {
    const c = catMap.get(cat) ?? { name: cat, count: 0, bytes: 0 };
    c.count += 1;
    c.bytes += bytes;
    catMap.set(cat, c);
  };

  for (const [key, value] of Object.entries(all)) {
    const spec = KNOWN_KEYS.get(key);
    if (!spec) continue; // 未知 key 默认不导出
    if (spec.category === 'transient') continue; // 永不导出
    if (spec.category === 'secrets' && !includeSecrets) continue;
    if (spec.category === 'history' && !includeHistory) continue;
    data[key] = value;
    bump(spec.category, sizeof(value));
  }

  const categories = CATEGORY_ORDER.filter((c) => catMap.has(c)).map((c) => catMap.get(c)!);

  return {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    appVersion: getAppVersion(),
    exportedAt: Date.now(),
    categories,
    data,
  };
}

export interface BundleSummary {
  categories: CategorySummary[];
  totalBytes: number;
  totalKeys: number;
  hasSecrets: boolean;
  keys: string[];
}

export function summarizeBundle(b: BackupBundle): BundleSummary {
  // 基于 data 重算（不信任 b.categories，使 legacy/外部构造的 bundle 也能正确预览）
  const keys = Object.keys(b.data || {});
  const catMap = new Map<BackupCategory, CategorySummary>();
  for (const k of keys) {
    const spec = KNOWN_KEYS.get(k);
    if (!spec) continue;
    const c = catMap.get(spec.category) ?? { name: spec.category, count: 0, bytes: 0 };
    c.count += 1;
    c.bytes += sizeof(b.data[k]);
    catMap.set(spec.category, c);
  }
  const categories = CATEGORY_ORDER.filter((c) => catMap.has(c)).map((c) => catMap.get(c)!);
  return {
    categories,
    totalBytes: categories.reduce((s, c) => s + c.bytes, 0),
    totalKeys: keys.length,
    hasSecrets: catMap.has('secrets'),
    keys,
  };
}

export interface ApplyOptions {
  includeSecrets?: boolean;
  includeHistory?: boolean;
  /** merge=仅写入存在的键；overwrite=先清白名单内非敏感非临时键再写入 */
  mode?: 'merge' | 'overwrite';
}

export interface ApplyResult {
  applied: string[];
  skipped: string[];
}

/** 按白名单写入备份内容。secrets/transient/未知 key 默认跳过。 */
export async function applyBundle(
  b: BackupBundle,
  opts: ApplyOptions = {},
): Promise<ApplyResult> {
  const { includeSecrets = false, includeHistory = true, mode = 'merge' } = opts;
  const applied: string[] = [];
  const skipped: string[] = [];

  if (mode === 'overwrite') {
    // 仅清 preferences / rules / history（不清 secrets/transient，避免误删本机密钥）
    const toClear = BACKUP_SCHEMA.filter(
      (s) =>
        s.importable &&
        s.category !== 'secrets' &&
        s.category !== 'transient' &&
        !(s.category === 'history' && !includeHistory),
    ).map((s) => s.key);
    if (toClear.length) await browser.storage.local.remove(toClear);
  }

  for (const [key, value] of Object.entries(b.data || {})) {
    const spec = KNOWN_KEYS.get(key);
    if (!spec || !spec.importable) {
      skipped.push(key); // 未知 / transient 拒绝
      continue;
    }
    if (spec.category === 'secrets' && !includeSecrets) {
      skipped.push(key); // 默认不覆盖本机密钥
      continue;
    }
    if (spec.category === 'history' && !includeHistory) {
      skipped.push(key);
      continue;
    }
    await browser.storage.local.set({ [key]: value });
    applied.push(key);
  }

  return { applied, skipped };
}

export interface ParsedBackup {
  bundle: BackupBundle | null;
  legacy: boolean;
  /** 旧格式或裸对象中不在白名单的 key（将被拒绝） */
  unknownKeys: string[];
}

/**
 * 解析备份文件 JSON。支持新格式（schemaVersion + data）与旧格式（{__app, data} 或裸对象）。
 * 旧格式按白名单过滤，未知 key 收集到 unknownKeys 供 UI 提示。
 */
export function parseBackup(raw: unknown): ParsedBackup {
  if (!raw || typeof raw !== 'object') return { bundle: null, legacy: false, unknownKeys: [] };
  const obj = raw as Record<string, unknown>;

  // 新格式
  if (typeof obj.schemaVersion === 'number' && obj.data && typeof obj.data === 'object') {
    return { bundle: obj as unknown as BackupBundle, legacy: false, unknownKeys: [] };
  }

  // 旧格式：{ __app, __exportedAt, data } 或裸 storage 对象
  const sourceData =
    obj.data && typeof obj.data === 'object'
      ? (obj.data as Record<string, unknown>)
      : obj;
  const unknownKeys: string[] = [];
  const filteredData: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(sourceData)) {
    if (KNOWN_KEYS.has(k) && KNOWN_KEYS.get(k)!.category !== 'transient') {
      filteredData[k] = v;
    } else {
      unknownKeys.push(k);
    }
  }
  const bundle: BackupBundle = {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    appVersion: typeof obj.appVersion === 'string' ? obj.appVersion : 'legacy',
    exportedAt: typeof obj.__exportedAt === 'number' ? obj.__exportedAt : 0,
    categories: [],
    data: filteredData,
  };
  return { bundle, legacy: true, unknownKeys };
}
