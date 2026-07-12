/**
 * 资产测绘引擎 — 灵眸 v6.0
 * 从 vk-asset.js 提取的纯逻辑（URL 构建 / 结果标准化 / CSV 导出）
 * 无网络 / 无 DOM — 调用方负责发送消息和持久化。
 */

// ===== ZoomEye URL 构建 =====

export type ZoomEyeMode = 'host' | 'web';

/** 构建 ZoomEye API 请求 URL（与 v5 的 endpoint 形状一致） */
export function buildZoomEyeUrl(
  query: string,
  page: number,
  mode: ZoomEyeMode,
): string {
  const endpoint = mode === 'host'
    ? 'https://api.zoomeye.org/host/search'
    : 'https://api.zoomeye.org/web/search';
  const params = new URLSearchParams({
    query,
    page: String(page),
  });
  return `${endpoint}?${params.toString()}`;
}

// ===== 多平台查询 URL 构建器（浏览器直开，无需 API Key） =====

/** UTF-8 字符串 → Base64（FOFA qbase64 需要） */
function b64Utf8(s: string): string {
  return btoa(unescape(encodeURIComponent(s)));
}

/** FOFA web 搜索 URL（qbase64 编码） */
export function buildFofaWebUrl(query: string): string {
  return `https://fofa.info/result?qbase64=${b64Utf8(query)}`;
}

/** Shodan web 搜索 URL */
export function buildShodanWebUrl(query: string): string {
  return `https://www.shodan.io/search?query=${encodeURIComponent(query)}`;
}

/** Hunter (奇安信) web 搜索 URL（qbase64） */
export function buildHunterWebUrl(query: string): string {
  return `https://hunter.qianxin.com/vip/list?search=${encodeURIComponent(b64Utf8(query))}`;
}

/** Quake (360) web 搜索 URL */
export function buildQuakeWebUrl(query: string): string {
  return `https://quake.360.net/quake/#/searchResult?query=${encodeURIComponent(query)}`;
}

export interface AssetEngineMeta { id: string; label: string; build: (q: string) => string }

/** 多平台测绘入口（除 ZoomEye API 外，其余为浏览器直开） */
export const ASSET_ENGINES: AssetEngineMeta[] = [
  { id: 'fofa', label: 'FOFA', build: buildFofaWebUrl },
  { id: 'shodan', label: 'Shodan', build: buildShodanWebUrl },
  { id: 'hunter', label: 'Hunter', build: buildHunterWebUrl },
  { id: 'quake', label: 'Quake', build: buildQuakeWebUrl },
];

// ===== FOFA 面板内 API 查询 =====

/** 构建 FOFA API 请求 URL（需 email + key） */
export function buildFofaApiUrl(query: string, email: string, key: string, size = 100): string {
  const params = new URLSearchParams({
    email,
    key,
    qbase64: b64Utf8(query),
    size: String(Math.min(Math.max(size, 1), 100)),
  });
  return `https://fofa.info/api/v1/search/all?${params.toString()}`;
}

/** Shodan host 搜索 API（需 key） */
export function buildShodanApiUrl(query: string, key: string, page = 1): string {
  const params = new URLSearchParams({ key, query, page: String(page) });
  return `https://api.shodan.io/shodan/host/search?${params.toString()}`;
}

/** Shodan 单主机详情 API（IP → 端口/漏洞/服务） */
export function buildShodanHostApiUrl(ip: string, key: string): string {
  return `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
}

/** FOFA 原始结果标准化（默认字段 host,ip,port） */
export function normalizeFofaResults(raw: unknown): ZoomEyeResult[] {
  if (!raw || typeof raw !== 'object') return [];
  const obj = raw as any;
  if (obj.error) throw new Error('FOFA: ' + (obj.errmsg || obj.error));
  const results = obj.results;
  if (!Array.isArray(results)) return [];
  return results.map((r: any) => {
    // FOFA 默认返回 [host, ip, port] 数组；若用户带 fields 则可能是对象
    if (Array.isArray(r)) {
      return {
        ip: String(r[1] || '-'), port: Number(r[2]) || 0, service: '-',
        hostname: String(r[0] || '-'), country: '-', region: '-', banner: '-', title: String(r[0] || '-'),
      };
    }
    return {
      ip: String(r.ip || '-'), port: Number(r.port) || 0, service: '-',
      hostname: String(r.host || r.hostname || '-'), country: '-', region: '-', banner: '-', title: String(r.host || r.title || '-'),
    };
  });
}

/** Shodan 搜索结果标准化 */
export function normalizeShodanResults(raw: unknown): ZoomEyeResult[] {
  if (!raw || typeof raw !== 'object') return [];
  const obj = raw as any;
  if (obj.error) throw new Error('Shodan: ' + (obj.error || 'API 错误'));
  const matches = obj.matches;
  if (!Array.isArray(matches)) return [];
  return matches.map((m: any) => ({
    ip: m.ip_str || m.ip || '-',
    port: Number(m.port) || 0,
    service: m._shodan?.module || m.transport || m.product || '-',
    hostname: (Array.isArray(m.hostnames) && m.hostnames[0]) || m.host || '-',
    country: m.location?.country_name || '-',
    region: m.location?.city || '-',
    banner: m.product ? `${m.product}${m.version ? '/' + m.version : ''}` : (m.os || '-'),
    title: m.http?.title || m.product || '-',
  }));
}


// ===== ZoomEye 结果标准化 =====

export interface ZoomEyeResult {
  ip: string;
  port: number;
  service: string;
  hostname: string;
  country: string;
  region: string;
  banner: string;
  title: string;
}

interface ZoomEyeHostMatch {
  ip?: string;
  portinfo?: { port?: number; service?: string; type?: string; banner?: string; product?: string };
  geoinfo?: { country?: { names?: { en?: string; zh?: string } }; city?: { names?: { en?: string; zh?: string } } };
  webinfo?: { title?: string };
  hostname?: string[];
}

interface ZoomEyeWebResponse {
  site?: string;
  title?: string;
  domain?: string;
  ip?: string[];
  country?: string;
  city?: string;
  updated?: string;
}

/** 将 ZoomEye 原始 JSON 标准化为扁平行数组 */
export function normalizeResults(
  raw: unknown,
  mode: ZoomEyeMode,
): ZoomEyeResult[] {
  if (!raw || typeof raw !== 'object') return [];

  const obj = raw as Record<string, unknown>;

  if (mode === 'host') {
    const matches = (obj.matches ?? obj.data) as ZoomEyeHostMatch[] | undefined;
    if (!Array.isArray(matches)) return [];

    return matches.map((m) => {
      const countryNames = m.geoinfo?.country?.names;
      const regionNames = m.geoinfo?.city?.names;
      return {
        ip: m.ip || '-',
        port: m.portinfo?.port ?? 0,
        service: m.portinfo?.service || m.portinfo?.type || m.portinfo?.product || '-',
        hostname: (Array.isArray(m.hostname) ? m.hostname[0] : m.hostname) || '-',
        country: countryNames?.zh || countryNames?.en || '-',
        region: regionNames?.zh || regionNames?.en || '-',
        banner: m.portinfo?.banner || '-',
        title: m.webinfo?.title || m.portinfo?.product || '-',
      };
    });
  }

  // web 模式
  const list = (obj.matches ?? obj.data) as ZoomEyeWebResponse[] | undefined;
  if (!Array.isArray(list)) return [];

  return list.map((w) => ({
    ip: (Array.isArray(w.ip) ? w.ip[0] : w.ip) || '-',
    port: 80,
    service: '-',
    hostname: w.site || w.domain || '-',
    country: w.country || '-',
    region: w.city || '-',
    banner: w.updated || '-',
    title: w.title || '-',
  }));
}

// ===== CSV 导出 =====

const CSV_HEADERS: (keyof ZoomEyeResult)[] = [
  'ip',
  'port',
  'service',
  'hostname',
  'country',
  'region',
  'title',
];

const CSV_HEADER_LABELS: Record<string, string> = {
  ip: 'IP',
  port: '端口',
  service: '服务',
  hostname: '主机名',
  country: '国家',
  region: '地区',
  banner: 'Banner',
  title: '标题',
};

function escapeCsv(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/** 将结果列表转换为 CSV 字符串（含 BOM，兼容 Excel） */
export function buildCsv(results: ZoomEyeResult[]): string {
  const headerRow = CSV_HEADERS.map((k) => CSV_HEADER_LABELS[k] || k).join(',');
  const dataRows = results.map((r) =>
    CSV_HEADERS.map((k) => escapeCsv(String(r[k] ?? ''))).join(','),
  );
  return '﻿' + [headerRow, ...dataRows].join('\n');
}
