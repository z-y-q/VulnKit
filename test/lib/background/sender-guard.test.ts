import { describe, it, expect, beforeEach } from 'vitest';
import {
  isOwnExtension,
  isExtensionPage,
  isContentScript,
  senderMatches,
  isAuthorized,
  MESSAGE_POLICY,
  type SenderPolicy,
} from '@/lib/background/sender-guard';

// setup.ts 注入了 browser.runtime.getURL（返回 chrome-extension://test-id/），
// 但未注入 runtime.id —— sender-guard 依赖它判定「本扩展」，这里补上。
const TEST_EXT_ID = 'test-ext-id';
const EXT_ORIGIN = `chrome-extension://${TEST_EXT_ID}/`;

beforeEach(() => {
  (globalThis as any).browser.runtime.id = TEST_EXT_ID;
  (globalThis as any).browser.runtime.getURL = (path: string) => EXT_ORIGIN + path;
});

/** 扩展页面 sender：本扩展 id、无 tab、url 落在扩展 origin */
const extPageSender = { id: TEST_EXT_ID, url: EXT_ORIGIN + 'sidepanel.html' } as any;
/** content script sender：本扩展 id 且带 tab */
const contentScriptSender = { id: TEST_EXT_ID, tab: { id: 1 }, url: 'https://example.com/' } as any;
/** 外部扩展 sender：id 不匹配 */
const foreignSender = { id: 'another-extension-id', url: 'chrome-extension://another-extension-id/x.html' } as any;

describe('sender-guard: isOwnExtension', () => {
  it('本扩展页面 → true', () => {
    expect(isOwnExtension(extPageSender)).toBe(true);
  });
  it('本扩展 content script → true', () => {
    expect(isOwnExtension(contentScriptSender)).toBe(true);
  });
  it('外部扩展 → false', () => {
    expect(isOwnExtension(foreignSender)).toBe(false);
  });
  it('undefined sender → false', () => {
    expect(isOwnExtension(undefined)).toBe(false);
  });
  it('无 id 的 sender → false', () => {
    expect(isOwnExtension({ url: 'https://example.com/' } as any)).toBe(false);
  });
});

describe('sender-guard: isExtensionPage', () => {
  it('本扩展页面（无 tab）→ true', () => {
    expect(isExtensionPage(extPageSender)).toBe(true);
  });
  it('content script（带 tab）→ false（即便来自本扩展）', () => {
    expect(isExtensionPage(contentScriptSender)).toBe(false);
  });
  it('外部扩展 → false', () => {
    expect(isExtensionPage(foreignSender)).toBe(false);
  });
  it('本扩展 id 但 url 落在网页 origin → false', () => {
    expect(isExtensionPage({ id: TEST_EXT_ID, url: 'https://evil.com/fake.html' } as any)).toBe(false);
  });
  it('无 url 的本扩展 sender → true（宽松兜底）', () => {
    expect(isExtensionPage({ id: TEST_EXT_ID } as any)).toBe(true);
  });
  it('undefined → false', () => {
    expect(isExtensionPage(undefined)).toBe(false);
  });
});

describe('sender-guard: isContentScript', () => {
  it('本扩展且带 tab → true', () => {
    expect(isContentScript(contentScriptSender)).toBe(true);
  });
  it('本扩展页面（无 tab）→ false', () => {
    expect(isContentScript(extPageSender)).toBe(false);
  });
  it('外部扩展带 tab → false', () => {
    expect(isContentScript({ id: 'other', tab: { id: 2 } } as any)).toBe(false);
  });
  it('undefined → false', () => {
    expect(isContentScript(undefined)).toBe(false);
  });
});

describe('sender-guard: senderMatches', () => {
  const cases: Array<{ policy: SenderPolicy; sender: any; expected: boolean; desc: string }> = [
    { policy: 'any-trusted', sender: extPageSender, expected: true, desc: 'any-trusted 放行扩展页面' },
    { policy: 'any-trusted', sender: contentScriptSender, expected: true, desc: 'any-trusted 放行 content script' },
    { policy: 'any-trusted', sender: foreignSender, expected: false, desc: 'any-trusted 拒绝外部扩展' },
    { policy: 'extension-page', sender: extPageSender, expected: true, desc: 'extension-page 放行扩展页面' },
    { policy: 'extension-page', sender: contentScriptSender, expected: false, desc: 'extension-page 拒绝 content script' },
    { policy: 'content-script', sender: contentScriptSender, expected: true, desc: 'content-script 放行 content script' },
    { policy: 'content-script', sender: extPageSender, expected: false, desc: 'content-script 拒绝扩展页面' },
  ];
  for (const c of cases) {
    it(c.desc, () => {
      expect(senderMatches(c.sender, c.policy)).toBe(c.expected);
    });
  }
});

describe('sender-guard: isAuthorized', () => {
  it('any-trusted 消息来自扩展页面 → true', () => {
    expect(isAuthorized({ type: 'FETCH_URL' }, extPageSender)).toBe(true);
  });
  it('any-trusted 消息来自 content script → true', () => {
    expect(isAuthorized({ type: 'FETCH_PROBE' }, contentScriptSender)).toBe(true);
  });
  it('extension-page 消息来自扩展页面 → true', () => {
    expect(isAuthorized({ type: 'SPOOF_UA' }, extPageSender)).toBe(true);
  });
  it('extension-page 消息来自 content script → false（越权）', () => {
    expect(isAuthorized({ type: 'SPOOF_HEADERS' }, contentScriptSender)).toBe(false);
  });
  it('content-script 消息来自 content script → true', () => {
    expect(isAuthorized({ type: 'VK_RUOYI_HOOK_EVENT' }, contentScriptSender)).toBe(true);
  });
  it('content-script 消息来自扩展页面 → false', () => {
    expect(isAuthorized({ type: 'VK_RUOYI_HOOK_EVENT' }, extPageSender)).toBe(false);
  });
  it('任何已知消息来自外部扩展 → false', () => {
    expect(isAuthorized({ type: 'FETCH_URL' }, foreignSender)).toBe(false);
    expect(isAuthorized({ type: 'TOGGLE_JS' }, foreignSender)).toBe(false);
  });
  it('未知消息类型 → false（一律拒绝）', () => {
    expect(isAuthorized({ type: 'EVIL_INJECTED' }, extPageSender)).toBe(false);
    expect(isAuthorized({ type: 'EVIL_INJECTED' }, contentScriptSender)).toBe(false);
  });
  it('null / undefined / 无 type 消息 → false', () => {
    expect(isAuthorized(null, extPageSender)).toBe(false);
    expect(isAuthorized(undefined, extPageSender)).toBe(false);
    expect(isAuthorized({}, extPageSender)).toBe(false);
    expect(isAuthorized({ type: 123 } as any, extPageSender)).toBe(false);
  });
  it('类型守卫收窄为 BackgroundMessage', () => {
    const msg = { type: 'FETCH_URL' } as const;
    if (isAuthorized(msg, extPageSender)) {
      // 通过类型守卫后 msg 应为 BackgroundMessage（type 字面量可访问）
      expect(msg.type).toBe('FETCH_URL');
    } else {
      expect.unreachable('应通过授权');
    }
  });
});

describe('sender-guard: MESSAGE_POLICY', () => {
  it('抓取/探测类全部 any-trusted', () => {
    expect(MESSAGE_POLICY.FETCH_URL).toBe('any-trusted');
    expect(MESSAGE_POLICY.FETCH_PROBE).toBe('any-trusted');
    expect(MESSAGE_POLICY.FETCH_CORS_PROBE).toBe('any-trusted');
    expect(MESSAGE_POLICY.FETCH_WAF_PROBE).toBe('any-trusted');
    expect(MESSAGE_POLICY.FETCH_IMAGE).toBe('any-trusted');
  });
  it('伪造请求头 / JS 阻断类全部 extension-page', () => {
    expect(MESSAGE_POLICY.TOGGLE_JS).toBe('extension-page');
    expect(MESSAGE_POLICY.SPOOF_UA).toBe('extension-page');
    expect(MESSAGE_POLICY.SPOOF_HEADERS).toBe('extension-page');
    expect(MESSAGE_POLICY.REGISTER_RUOYI_HOOK).toBe('extension-page');
  });
  it('若若 Hook 事件 content-script', () => {
    expect(MESSAGE_POLICY.VK_RUOYI_HOOK_EVENT).toBe('content-script');
  });
});
