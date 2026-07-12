/**
 * 通用偏好设置 — 灵眸 v6.0
 *
 * 对齐 v5 options 页的「工具默认值 / 采集过滤 / 远程 Payload」三类配置。
 * 统一存于 browser.storage.local key `lingmouPrefs`，供 options 页编辑、
 * 各面板（encoding/gather/payload）消费。
 */

const STORAGE_KEY = 'lingmouPrefs';

export type DefaultEncoding = 'base64' | 'url' | 'html' | 'hex';
export type DefaultHash = 'SHA-256' | 'SHA-1' | 'MD5';

/** 远程 Payload 缓存条目 */
export interface RemotePayloadCache {
  version?: string;
  updated?: string;
  fetchedAt?: number;
  payloads?: Record<string, unknown>;
}

export interface GeneralPrefs {
  /** 编码工具默认子标签 */
  defaultEncoding: DefaultEncoding;
  /** 默认哈希算法 */
  defaultHash: DefaultHash;
  /** Gather 采集域名排除列表（每行一个，支持 .example.com 精确匹配） */
  gatherExcludeDomains: string[];
  /** 远程 Payload JSON URL（空=不启用） */
  payloadRemoteUrl: string;
  /** 远程 Payload 缓存 */
  remotePayloads: RemotePayloadCache | null;
}

export const DEFAULT_PREFS: GeneralPrefs = {
  defaultEncoding: 'base64',
  defaultHash: 'SHA-256',
  gatherExcludeDomains: [],
  payloadRemoteUrl: '',
  remotePayloads: null,
};

function normalize(raw: Partial<GeneralPrefs> | undefined): GeneralPrefs {
  const r = raw || {};
  return {
    defaultEncoding: (['base64', 'url', 'html', 'hex'].includes(r.defaultEncoding as string)
      ? r.defaultEncoding
      : DEFAULT_PREFS.defaultEncoding) as DefaultEncoding,
    defaultHash: (['SHA-256', 'SHA-1', 'MD5'].includes(r.defaultHash as string)
      ? r.defaultHash
      : DEFAULT_PREFS.defaultHash) as DefaultHash,
    gatherExcludeDomains: Array.isArray(r.gatherExcludeDomains)
      ? r.gatherExcludeDomains.filter((x) => typeof x === 'string')
      : DEFAULT_PREFS.gatherExcludeDomains,
    payloadRemoteUrl:
      typeof r.payloadRemoteUrl === 'string' ? r.payloadRemoteUrl : DEFAULT_PREFS.payloadRemoteUrl,
    remotePayloads:
      r.remotePayloads && typeof r.remotePayloads === 'object'
        ? (r.remotePayloads as RemotePayloadCache)
        : null,
  };
}

export async function loadPrefs(): Promise<GeneralPrefs> {
  try {
    const data = await browser.storage.local.get(STORAGE_KEY);
    return normalize((data[STORAGE_KEY] || {}) as Partial<GeneralPrefs>);
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

export async function savePrefs(patch: Partial<GeneralPrefs>): Promise<GeneralPrefs> {
  const current = await loadPrefs();
  const next = normalize({ ...current, ...patch });
  await browser.storage.local.set({ [STORAGE_KEY]: next });
  return next;
}

export async function resetPrefs(): Promise<GeneralPrefs> {
  await browser.storage.local.set({ [STORAGE_KEY]: { ...DEFAULT_PREFS } });
  return { ...DEFAULT_PREFS };
}

/**
 * 拉取并校验远程 Payload。
 * 校验：HTTP 200 + JSON 含 version 与 payloads 字段。
 * 失败抛错，调用方 toast。
 */
export async function fetchRemotePayloads(url: string): Promise<RemotePayloadCache> {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (!data || typeof data !== 'object' || !data.payloads) {
    throw new Error('格式无效：缺少 payloads 字段');
  }
  return {
    version: typeof data.version === 'string' ? data.version : undefined,
    updated: typeof data.updated === 'string' ? data.updated : undefined,
    fetchedAt: Date.now(),
    payloads: data.payloads as Record<string, unknown>,
  };
}

/** 判断某域名是否被采集排除（支持精确 / .example.com 后缀） */
export function isDomainExcluded(host: string, exclude: string[]): boolean {
  if (!exclude.length) return false;
  const h = host.toLowerCase();
  for (const raw of exclude) {
    const rule = raw.trim().toLowerCase();
    if (!rule) continue;
    if (rule.startsWith('.')) {
      if (h.endsWith(rule) || h === rule.slice(1)) return true;
    } else if (h === rule || h.endsWith('.' + rule)) {
      return true;
    }
  }
  return false;
}
