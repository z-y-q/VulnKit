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
