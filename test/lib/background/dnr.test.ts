import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  queryJsBlocked,
  toggleJs,
  spoofUa,
  resetSpoofUa,
  spoofHeaders,
  resetSpoofHeaders,
  restoreSpoofState,
} from '@/lib/background/dnr';

const JS_BLOCK_RULE_ID = 9001;
const UA_RULE_ID = 9002;
const HEADER_RULES_START = 9010;
const MAX_HEADER_RULES = 20;

// setup.ts 未注入 declarativeNetRequest，这里补全
let dnrMock: { updateDynamicRules: ReturnType<typeof vi.fn>; getDynamicRules: ReturnType<typeof vi.fn> };

beforeEach(() => {
  dnrMock = {
    updateDynamicRules: vi.fn(() => Promise.resolve()),
    getDynamicRules: vi.fn(() => Promise.resolve([])),
  };
  (globalThis as any).browser.declarativeNetRequest = dnrMock;
  // storage 默认空
  (globalThis as any).browser.storage.local.get = vi.fn(() => Promise.resolve({}));
  (globalThis as any).browser.storage.local.set = vi.fn(() => Promise.resolve());
});

// 模块级 spoofState 跨测试残留 → afterEach 恢复默认
afterEach(async () => {
  await resetSpoofUa();
  await resetSpoofHeaders();
  vi.clearAllMocks();
});

function lastUpdate() {
  return dnrMock.updateDynamicRules.mock.calls.at(-1)?.[0];
}

// ====== JS 阻断 ======

describe('dnr: JS 阻断规则', () => {
  it('toggleJs(false) 创建阻断规则', async () => {
    await toggleJs(false);
    const u = lastUpdate();
    expect(u.removeRuleIds).toEqual([JS_BLOCK_RULE_ID]);
    expect(u.addRules).toHaveLength(1);
    expect(u.addRules[0].id).toBe(JS_BLOCK_RULE_ID);
    expect(u.addRules[0].action.type).toBe('block');
  });

  it('toggleJs(true) 删除阻断规则', async () => {
    await toggleJs(true);
    const u = lastUpdate();
    expect(u.removeRuleIds).toEqual([JS_BLOCK_RULE_ID]);
    expect(u.addRules).toBeUndefined();
  });

  it('queryJsBlocked 返回 true（规则存在）', async () => {
    dnrMock.getDynamicRules.mockResolvedValue([{ id: JS_BLOCK_RULE_ID }, { id: 9999 }]);
    expect(await queryJsBlocked()).toBe(true);
  });

  it('queryJsBlocked 返回 false（规则不存在）', async () => {
    dnrMock.getDynamicRules.mockResolvedValue([{ id: 9999 }]);
    expect(await queryJsBlocked()).toBe(false);
  });

  it('getDynamicRules 抛错 → queryJsBlocked 返回 false（容错）', async () => {
    dnrMock.getDynamicRules.mockRejectedValue(new Error('perm denied'));
    expect(await queryJsBlocked()).toBe(false);
  });
});

// ====== UA 伪造 ======

describe('dnr: UA 伪造规则', () => {
  it('spoofUa 创建 modifyHeaders 规则 + 持久化', async () => {
    await spoofUa('https://example.com/', 'MyAgent/1.0');
    const u = lastUpdate();
    expect(u.removeRuleIds).toEqual([UA_RULE_ID]);
    expect(u.addRules[0].id).toBe(UA_RULE_ID);
    expect(u.addRules[0].action.type).toBe('modifyHeaders');
    expect(u.addRules[0].action.requestHeaders[0]).toMatchObject({
      header: 'User-Agent', operation: 'set', value: 'MyAgent/1.0',
    });
    // urlFilter 取 hostname
    expect(u.addRules[0].condition.urlFilter).toBe('example.com/*');
    // 持久化到 storage
    expect((globalThis as any).browser.storage.local.set).toHaveBeenCalledWith({
      pentest_spoof: expect.objectContaining({
        ua: expect.objectContaining({ enabled: true, current: 'MyAgent/1.0' }),
      }),
    });
  });

  it('resetSpoofUa 删除规则 + 状态恢复', async () => {
    await spoofUa('https://example.com/', 'UA');
    dnrMock.updateDynamicRules.mockClear();
    await resetSpoofUa();
    const u = lastUpdate();
    expect(u.removeRuleIds).toEqual([UA_RULE_ID]);
    expect(u.addRules).toBeUndefined();
  });

  it('缺 url 或 userAgent 抛错', async () => {
    await expect(spoofUa('', 'UA')).rejects.toThrow(/Missing url or userAgent/);
    await expect(spoofUa('https://example.com/', '')).rejects.toThrow(/Missing url or userAgent/);
  });
});

// ====== 请求头伪造 ======

describe('dnr: 请求头伪造规则', () => {
  it('spoofHeaders 为每个头创建一条规则，且清理旧 header 规则位', async () => {
    await spoofHeaders('https://example.com/', {
      xff: '1.1.1.1',
      referer: 'https://ref.com/',
      custom: [{ name: 'X-Custom', value: 'v' }],
    });
    const u = lastUpdate();
    // clientIp 未传 → 不产生；xff/referer/clientIp(无)/custom 各一条 → 3 条
    expect(u.addRules).toHaveLength(3);
    // 清理整个 header 规则位段（20 个 id）
    expect(u.removeRuleIds).toEqual(
      Array.from({ length: MAX_HEADER_RULES }, (_, i) => HEADER_RULES_START + i),
    );
    // 每条规则 id 连续从 9010 起
    expect(u.addRules.map((r: any) => r.id)).toEqual([9010, 9011, 9012]);
    // 持久化
    expect((globalThis as any).browser.storage.local.set).toHaveBeenCalled();
  });

  it('clientIp 同时设置 Client-IP 与 X-Real-IP', async () => {
    await spoofHeaders('https://example.com/', { clientIp: '10.0.0.1' });
    const u = lastUpdate();
    // clientIp 产生 2 条 mods（Client-IP + X-Real-IP）
    expect(u.addRules).toHaveLength(2);
    const headerNames = u.addRules.map((r: any) => r.action.requestHeaders[0].header);
    expect(headerNames).toEqual(['Client-IP', 'X-Real-IP']);
  });

  it('空 headers 抛错', async () => {
    await expect(spoofHeaders('https://example.com/', undefined as any)).rejects.toThrow(/Missing headers/);
  });

  it('resetSpoofHeaders 删除整个 header 规则位段', async () => {
    await spoofHeaders('https://example.com/', { xff: '1.1.1.1' });
    dnrMock.updateDynamicRules.mockClear();
    await resetSpoofHeaders();
    const u = lastUpdate();
    expect(u.removeRuleIds).toEqual(
      Array.from({ length: MAX_HEADER_RULES }, (_, i) => HEADER_RULES_START + i),
    );
    expect(u.addRules).toBeUndefined();
  });
});

// ====== 启动恢复 ======

describe('dnr: restoreSpoofState', () => {
  it('storage 有 ua.enabled → 重建 UA 规则', async () => {
    (globalThis as any).browser.storage.local.get = vi.fn(() =>
      Promise.resolve({
        pentest_spoof: {
          ua: { enabled: true, current: 'StoredUA', url: 'https://example.com/' },
          headers: { xff: '', referer: '', clientIp: '', custom: [], url: '' },
        },
      }),
    );
    await restoreSpoofState();
    const u = lastUpdate();
    expect(u.addRules[0].id).toBe(UA_RULE_ID);
    expect(u.addRules[0].action.requestHeaders[0].value).toBe('StoredUA');
  });

  it('storage 有 headers → 重建 header 规则', async () => {
    (globalThis as any).browser.storage.local.get = vi.fn(() =>
      Promise.resolve({
        pentest_spoof: {
          ua: { enabled: false, current: '', url: '' },
          headers: { xff: '1.1.1.1', referer: '', clientIp: '', custom: [], url: 'https://example.com/' },
        },
      }),
    );
    await restoreSpoofState();
    const u = lastUpdate();
    expect(u.addRules).toHaveLength(1);
    expect(u.addRules[0].action.requestHeaders[0].header).toBe('X-Forwarded-For');
  });

  it('storage 空 → 不创建任何规则', async () => {
    (globalThis as any).browser.storage.local.get = vi.fn(() => Promise.resolve({}));
    await restoreSpoofState();
    expect(dnrMock.updateDynamicRules).not.toHaveBeenCalled();
  });

  it('恢复时 DNR 抛错被吞（不中断）', async () => {
    (globalThis as any).browser.storage.local.get = vi.fn(() =>
      Promise.resolve({
        pentest_spoof: {
          ua: { enabled: true, current: 'UA', url: 'https://example.com/' },
          headers: { xff: '', referer: '', clientIp: '', custom: [], url: '' },
        },
      }),
    );
    dnrMock.updateDynamicRules.mockRejectedValue(new Error('perm'));
    // 不应抛错
    await expect(restoreSpoofState()).resolves.toBeUndefined();
    // 恢复 mock，避免 afterEach 的 reset 因 reject 而失败
    dnrMock.updateDynamicRules.mockResolvedValue(undefined);
  });
});
