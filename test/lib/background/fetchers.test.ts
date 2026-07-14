import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  fetchUrl,
  fetchImage,
  fetchProbe,
  fetchHeaderProbe,
  fetchCorsProbe,
  fetchWafProbe,
  fetchDnsResolve,
} from '@/lib/background/fetchers';

// —— mock 全局 fetch；rate-limit 用真实模块（acquire 在 settings=null 时走默认并发，不触发 browser） ——

function makeResponse(opts: {
  status?: number;
  statusText?: string;
  body?: string;
  headers?: Record<string, string>;
  json?: any;
}) {
  const status = opts.status ?? 200;
  const headers = new Headers(opts.headers || {});
  return {
    status,
    statusText: opts.statusText ?? '',
    ok: status >= 200 && status < 300,
    headers,
    redirected: false,
    url: '',
    type: 'basic',
    // body 置空 → readTextWithLimit 走 text() fallback
    body: undefined,
    text: () => Promise.resolve(opts.body ?? ''),
    arrayBuffer: () => Promise.resolve(new TextEncoder().encode(opts.body ?? '').buffer),
    json: () => Promise.resolve(opts.json ?? null),
  } as any;
}

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  globalThis.fetch = fetchMock as any;
});

// ====== fetchUrl ======

describe('fetchers: fetchUrl 成功响应', () => {
  it('全文抓取返回 body', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: 'hello world' }));
    const r = await fetchUrl('https://example.com/a.js');
    expect(r.success).toBe(true);
    expect((r as any).data).toBe('hello world');
  });
  it('带 Range 请求头（tailOnly）', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 206, body: 'tail' }));
    await fetchUrl('https://example.com/a.js', 500);
    const init = fetchMock.mock.calls[0][1];
    expect(init.headers.Range).toBe('bytes=-500');
  });
});

describe('fetchers: fetchUrl 非 2xx', () => {
  it('404 → HTTP_ERROR', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 404, statusText: 'Not Found', body: 'not found' }));
    const r = await fetchUrl('https://example.com/x');
    expect(r.success).toBe(false);
    expect((r as any).code).toBe('HTTP_ERROR');
    expect((r as any).error).toContain('404');
  });
  it('500 → HTTP_ERROR', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 500, body: 'server error' }));
    const r = await fetchUrl('https://example.com/x');
    expect((r as any).code).toBe('HTTP_ERROR');
  });
});

describe('fetchers: fetchUrl 超时 / 取消', () => {
  it('超时触发 abort → TIMEOUT', async () => {
    // mock fetch 监听 signal，abort 后 reject AbortError（模拟真实超时）
    fetchMock.mockImplementation((_url: string, init: any) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const e = new Error('The operation was aborted');
          e.name = 'AbortError';
          reject(e);
        });
      }),
    );
    const r = await fetchUrl('https://example.com/slow', undefined, 50);
    expect(r.success).toBe(false);
    expect((r as any).code).toBe('TIMEOUT');
  }, 5000);
});

describe('fetchers: fetchUrl 网络错误', () => {
  it('普通异常 → NETWORK', async () => {
    fetchMock.mockRejectedValue(new Error('connect ECONNREFUSED'));
    const r = await fetchUrl('https://example.com/x');
    expect(r.success).toBe(false);
    expect((r as any).code).toBe('NETWORK');
    expect((r as any).error).toContain('ECONNREFUSED');
  });
});

describe('fetchers: fetchUrl 大响应', () => {
  it('content-length 超限 → TOO_LARGE', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({ status: 200, body: 'x', headers: { 'content-length': '99999999' } }),
    );
    const r = await fetchUrl('https://example.com/big', undefined, 10000, 1024); // maxBytes=1KB
    expect(r.success).toBe(false);
    expect((r as any).code).toBe('TOO_LARGE');
  });
  it('maxBytes 被 RESPONSE_HARD_CEILING 夹紧（20MB 上限）', async () => {
    // 传入超大 maxBytes 不应突破硬顶；用 content-length 介于 20MB-25MB 验证夹紧
    fetchMock.mockResolvedValue(
      makeResponse({ status: 200, body: 'x', headers: { 'content-length': String(25 * 1024 * 1024) } }),
    );
    const r = await fetchUrl('https://example.com/big', undefined, 10000, 50 * 1024 * 1024);
    // 25MB > 20MB 硬顶 → TOO_LARGE（证明 maxBytes 被夹紧到 20MB）
    expect((r as any).code).toBe('TOO_LARGE');
  });
});

describe('fetchers: fetchUrl tailOnly 降级', () => {
  it('服务器接受 Range（206）→ 返回尾部原文', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 206, body: 'tail-data' }));
    const r = await fetchUrl('https://example.com/a.js', 500);
    expect(r.success).toBe(true);
    expect((r as any).data).toBe('tail-data');
  });
  it('服务器忽略 Range（200）→ 截取尾部', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: '0123456789' }));
    const r = await fetchUrl('https://example.com/a.js', 5);
    expect(r.success).toBe(true);
    expect((r as any).data).toBe('56789'); // slice(-5)
  });
});

// ====== fetchImage ======

describe('fetchers: fetchImage', () => {
  it('成功 → data URL', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({ status: 200, body: 'binary', headers: { 'content-type': 'image/png' } }),
    );
    const r = await fetchImage('https://example.com/i.png');
    expect(r.success).toBe(true);
    expect((r as any).data).toMatch(/^data:image\/png;base64,/);
  });
  it('非 2xx → 失败', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 403 }));
    const r = await fetchImage('https://example.com/i.png');
    expect(r.success).toBe(false);
    expect((r as any).error).toContain('403');
  });
});

// ====== fetchProbe ======

describe('fetchers: fetchProbe', () => {
  it('成功 → status/headers/time', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({ status: 200, statusText: 'OK', headers: { 'content-type': 'text/html' } }),
    );
    const r = await fetchProbe('https://example.com/');
    expect(r.status).toBe(200);
    expect(r.headers?.['content-type']).toBe('text/html');
    expect(r.time).toBeGreaterThanOrEqual(0);
  });
  it('includeBody → 返回 body', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: '<html></html>' }));
    const r = await fetchProbe('https://example.com/', { includeBody: true });
    expect(r.body).toBe('<html></html>');
  });
  it('超时 → error + status 0', async () => {
    fetchMock.mockImplementation((_u: string, init: any) =>
      new Promise((_res, rej) => {
        init?.signal?.addEventListener('abort', () => {
          const e = new Error('aborted'); e.name = 'AbortError'; rej(e);
        });
      }),
    );
    const r = await fetchProbe('https://example.com/', { timeout: 50 });
    expect(r.status).toBe(0);
    expect(r.error).toBeTruthy();
  }, 5000);
});

// ====== fetchHeaderProbe（HEAD 失败回退 GET） ======

describe('fetchers: fetchHeaderProbe', () => {
  it('HEAD 成功', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({ status: 200, headers: { 'x-powered-by': 'test' } }),
    );
    const r = await fetchHeaderProbe('https://example.com/');
    expect(r.status).toBe(200);
    expect(r.headers?.['x-powered-by']).toBe('test');
    expect(fetchMock.mock.calls[0][1].method).toBe('HEAD');
  });
  it('HEAD 失败 → 回退 GET', async () => {
    fetchMock
      .mockRejectedValueOnce(new Error('HEAD not allowed'))
      .mockResolvedValueOnce(makeResponse({ status: 200, headers: { server: 'nginx' } }));
    const r = await fetchHeaderProbe('https://example.com/');
    expect(r.status).toBe(200);
    expect(r.headers?.server).toBe('nginx');
    expect(fetchMock.mock.calls[1][1].method).toBe('GET');
  });
});

// ====== fetchCorsProbe / fetchWafProbe ======

describe('fetchers: fetchCorsProbe', () => {
  it('返回 status/headers/body/type', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: '{}' }));
    const r = await fetchCorsProbe('https://example.com/');
    expect(r.status).toBe(200);
    expect(r.body).toBe('{}');
  });
});

describe('fetchers: fetchWafProbe', () => {
  it('body 超过 50KB 截断', async () => {
    const big = 'a'.repeat(60000);
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: big }));
    const r = await fetchWafProbe('https://example.com/');
    expect((r.body || '').length).toBe(50000);
  });
  it('body 不足 50KB 原样返回', async () => {
    fetchMock.mockResolvedValue(makeResponse({ status: 200, body: 'small' }));
    const r = await fetchWafProbe('https://example.com/');
    expect(r.body).toBe('small');
  });
});

// ====== fetchDnsResolve ======

describe('fetchers: fetchDnsResolve', () => {
  it('A 记录 → addresses', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({
        status: 200,
        json: {
          Status: 0,
          Answer: [
            { type: 1, data: '1.2.3.4', name: 'example.com.' },
            { type: 1, data: '5.6.7.8', name: 'example.com.' },
            { type: 16, data: '"txt"', name: 'example.com.' },
          ],
        },
      }),
    );
    const r = await fetchDnsResolve('example.com', 'A');
    expect(r.addresses).toEqual(['1.2.3.4', '5.6.7.8']);
    expect(r.resultCode).toBe(0);
  });
  it('非 A 记录 → answers', async () => {
    fetchMock.mockResolvedValue(
      makeResponse({
        status: 200,
        json: { Status: 0, Answer: [{ type: 16, data: '"v=spf1"', name: 'example.com.' }] },
      }),
    );
    const r = await fetchDnsResolve('example.com', 'TXT');
    expect(r.answers?.length).toBe(1);
  });
  it('网络错误 → error + 空 addresses', async () => {
    fetchMock.mockRejectedValue(new Error('network down'));
    const r = await fetchDnsResolve('example.com', 'A');
    expect(r.error).toBeTruthy();
    expect(r.addresses).toEqual([]);
  });
});
