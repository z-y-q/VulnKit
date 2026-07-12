// 灵眸 v6.0 — Background 代理抓取函数
// 所有函数已与 SSRF 防护（url-guard）解耦：调用方负责校验。
// 从 background.js 提取，统一返回结构。

import type {
  FetchResult,
  ProbeResult,
  DnsResolveResult,
} from '@/lib/types/messaging';
import { acquire, hostnameOf } from '@/lib/background/rate-limit';

function createTimeoutController(timeoutMs: number) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    controller,
    cleanup: () => clearTimeout(timer),
  };
}

function collectHeaders(resp: Response): Record<string, string> {
  const hdrs: Record<string, string> = {};
  resp.headers.forEach((v, k) => {
    hdrs[k] = v;
  });
  return hdrs;
}

/** 抓取文本，可选 Range 尾部。tailOnly 传数字则取最后 N 字节，true 默认 500 字节。
 *  服务器不支持后缀 Range（返回 416 或忽略 Range 返回 200）时自动降级为全文抓取，
 *  确保 sourceMappingURL 提取不会因 Range 兼容性问题整体失败。
 */
export async function fetchUrl(
  url: string,
  tailOnly?: boolean | number,
  timeoutMs?: number,
): Promise<FetchResult> {
  const tc = createTimeoutController(timeoutMs || 10000);
  const release = await acquire(hostnameOf(url));
  try {
    // 第一次尝试：带 Range（如启用 tailOnly）
    if (tailOnly) {
      const bytes = typeof tailOnly === 'number' ? tailOnly : 500;
      try {
        const resp = await fetch(url, {
          headers: { Range: `bytes=-${bytes}` },
          signal: tc.controller.signal,
        });
        if (resp.status === 206) {
          // 服务器接受了后缀 Range，返回的就是尾部
          const data = await resp.text();
          return { success: true, data };
        }
        if (resp.ok) {
          // 服务器忽略 Range，返回全文 —— 截取尾部即可
          const full = await resp.text();
          return { success: true, data: full.slice(-bytes) };
        }
        // 416 / 其他：落到下方全文重试
      } catch (e) {
        // 网络/超时错误直接返回（重试也大概率失败）
        return { success: false, error: (e as Error).message || '请求超时' };
      }
    }
    // 全文抓取（无 tailOnly，或 Range 不被支持后的降级）
    const resp2 = await fetch(url, { signal: tc.controller.signal });
    if (!resp2.ok) {
      const body = await resp2.text().catch(() => '');
      throw new Error('HTTP ' + resp2.status + (body ? ': ' + body.slice(0, 200) : ''));
    }
    const data2 = await resp2.text();
    return { success: true, data: data2 };
  } catch (e) {
    return { success: false, error: (e as Error).message || '请求超时' };
  } finally {
    release();
    tc.cleanup();
  }
}

/** 抓取图片为 data URL（base64）。 */
export async function fetchImage(url: string): Promise<FetchResult> {
  const tc = createTimeoutController(15000);
  const release = await acquire(hostnameOf(url));
  try {
    const resp = await fetch(url, { signal: tc.controller.signal });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const buf = await resp.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      const chunk = bytes.subarray(i, Math.min(i + 8192, bytes.length));
      binary += String.fromCharCode(...chunk);
    }
    const b64 = btoa(binary);
    const mime = resp.headers.get('content-type') || 'image/jpeg';
    return { success: true, data: 'data:' + mime + ';base64,' + b64 };
  } catch (e) {
    return { success: false, error: (e as Error).message };
  } finally {
    release();
    tc.cleanup();
  }
}

// ZoomEye JWT 缓存（service worker 生命周期内有效）
let zoomEyeTokenCache: { token: string | null; expiresAt: number } = {
  token: null,
  expiresAt: 0,
};

/** 通过 ZoomEye API key 鉴权后抓取。token 缓存 1 小时；401 自动重新登录重试一次。 */
export async function fetchZoomEyeAuth(
  url: string,
  apiKey: string,
): Promise<FetchResult> {
  const release = await acquire(hostnameOf(url));
  try {
    const doRequest = async (token: string) => {
      const resp = await fetch(url, {
        headers: { Authorization: 'JWT ' + token },
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        return { ok: false, status: resp.status, body };
      }
      return { ok: true as const, text: await resp.text() };
    };

    const login = async (): Promise<string> => {
      const loginResp = await fetch('https://api.zoomeye.org/user/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey }),
        signal: AbortSignal.timeout(15000),
      });
      if (!loginResp.ok) throw new Error('ZoomEye login failed: HTTP ' + loginResp.status);
      const loginData = await loginResp.json();
      if (!loginData.access_token) throw new Error('ZoomEye login failed: no access_token');
      zoomEyeTokenCache = { token: loginData.access_token, expiresAt: Date.now() + 3600000 };
      return loginData.access_token;
    };

    const now = Date.now();
    // 1) 命中缓存
    if (zoomEyeTokenCache.token && zoomEyeTokenCache.expiresAt > now) {
      const r = await doRequest(zoomEyeTokenCache.token);
      if (r.ok) return { success: true, data: r.text };
      // 401 → 清缓存，重新登录后重试一次
      if (r.status === 401) {
        zoomEyeTokenCache = { token: null, expiresAt: 0 };
        const fresh = await login();
        const r2 = await doRequest(fresh);
        if (r2.ok) return { success: true, data: r2.text };
        throw new Error('HTTP ' + r2.status + (r2.body ? ': ' + r2.body.slice(0, 200) : ''));
      }
      throw new Error('HTTP ' + r.status + (r.body ? ': ' + r.body.slice(0, 200) : ''));
    }

    // 2) 无缓存 → 登录后请求
    const token = await login();
    const r = await doRequest(token);
    if (r.ok) return { success: true, data: r.text };
    throw new Error('HTTP ' + r.status + (r.body ? ': ' + r.body.slice(0, 200) : ''));
  } catch (e) {
    return { success: false, error: (e as Error).message || '请求超时' };
  } finally {
    release();
  }
}

export interface ProbeOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
  followRedirect?: boolean;
  includeBody?: boolean;
}

/** 通用探测：返回状态/头/耗时/可选 body。 */
export async function fetchProbe(url: string, opts: ProbeOptions = {}): Promise<ProbeResult> {
  const tc = createTimeoutController(opts.timeout || 5000);
  const t0 = performance.now();
  const release = await acquire(hostnameOf(url));
  try {
    const resp = await fetch(url, {
      method: opts.method || 'GET',
      redirect: opts.followRedirect !== false ? 'follow' : 'manual',
      signal: tc.controller.signal,
      headers: opts.headers || {},
      body: opts.body || undefined,
    });
    const elapsed = Math.round(performance.now() - t0);
    const result: ProbeResult = {
      status: resp.status,
      statusText: resp.statusText,
      headers: collectHeaders(resp),
      redirected: resp.redirected,
      url: resp.url,
      time: elapsed,
    };
    if (opts.includeBody && resp.status >= 200 && resp.status < 300) {
      result.body = await resp.text();
    }
    return result;
  } catch (e) {
    return { error: (e as Error).message, status: 0, body: '', headers: {}, time: 0 };
  } finally {
    release();
    tc.cleanup();
  }
}

/** CORS 探测：带 Origin 头，返回响应头 + body + type。 */
export async function fetchCorsProbe(
  url: string,
  opts: ProbeOptions & { credentials?: RequestCredentials } = {},
): Promise<ProbeResult> {
  const tc = createTimeoutController(opts.timeout || 10000);
  const release = await acquire(hostnameOf(url));
  try {
    const resp = await fetch(url, {
      method: opts.method || 'GET',
      redirect: 'follow',
      signal: tc.controller.signal,
      headers: opts.headers || {},
      credentials: opts.credentials || 'omit',
      body: opts.body || undefined,
    });
    const result: ProbeResult = {
      status: resp.status,
      statusText: resp.statusText,
      headers: collectHeaders(resp),
      type: resp.type as ResponseType,
    };
    result.body = await resp.text().catch(() => '');
    return result;
  } catch (e) {
    return { error: (e as Error).message, status: 0 };
  } finally {
    release();
    tc.cleanup();
  }
}

/** HEAD 探测响应头（失败回退 GET）。 */
export async function fetchHeaderProbe(url: string, timeout = 8000): Promise<ProbeResult> {
  const tc = createTimeoutController(timeout);
  const release = await acquire(hostnameOf(url));
  try {
    const resp = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: tc.controller.signal,
      credentials: 'omit',
    });
    return {
      status: resp.status,
      statusText: resp.statusText,
      headers: collectHeaders(resp),
    };
  } catch {
    // HEAD 可能被拒，回退 GET
    try {
      const resp2 = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(timeout),
        credentials: 'omit',
      });
      return {
        status: resp2.status,
        statusText: resp2.statusText,
        headers: collectHeaders(resp2),
      };
    } catch (e2) {
      return { error: (e2 as Error).message, status: 0 };
    }
  } finally {
    release();
    tc.cleanup();
  }
}

/** WAF 探测：GET 全 body（截断 50KB）。 */
export async function fetchWafProbe(
  url: string,
  opts: ProbeOptions = {},
): Promise<ProbeResult> {
  const tc = createTimeoutController(opts.timeout || 8000);
  const release = await acquire(hostnameOf(url));
  try {
    const resp = await fetch(url, {
      method: opts.method || 'GET',
      redirect: 'follow',
      signal: tc.controller.signal,
      credentials: 'omit',
      headers: opts.headers || {},
    });
    const result: ProbeResult = {
      status: resp.status,
      statusText: resp.statusText,
      headers: collectHeaders(resp),
      redirected: resp.redirected,
      url: resp.url,
    };
    const body = await resp.text().catch(() => '');
    result.body = body.length > 50000 ? body.substring(0, 50000) : body;
    return result;
  } catch (e) {
    return { error: (e as Error).message, status: 0 };
  } finally {
    release();
    tc.cleanup();
  }
}

/** no-cors 探测已下线（无调用方，FETCH_DNS_PROBE 已从协议删除）。 */

/** 通过 dns.google 解析域名。 */
export async function fetchDnsResolve(
  hostname: string,
  recordType = 'A',
): Promise<DnsResolveResult> {
  try {
    const r = await fetch(
      'https://dns.google/resolve?name=' + encodeURIComponent(hostname) + '&type=' + recordType,
    );
    const data = await r.json();
    const answers = (data.Answer || []).map((a: any) => ({
      type: a.type,
      data: a.data,
      name: a.name,
    }));
    if (recordType === 'A') {
      const addresses = answers
        .filter((a: any) => a.type === 1)
        .map((a: any) => a.data);
      return { addresses, resultCode: data.Status };
    }
    return { answers, resultCode: data.Status };
  } catch (err) {
    return { error: (err as Error).message, addresses: [] };
  }
}
