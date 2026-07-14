/**
 * 开放重定向检测引擎
 * 从 vk-redirect.js 提取的纯逻辑（payload 生成 + 响应判定）
 * 网络探测由调用方提供 probeFn
 */

export interface RedirectPayload {
  param: string;
  pattern: string;
}

export interface RedirectTestUrl {
  param: string;
  variant: string;
  url: string;
}

export interface RedirectProbeResponse {
  status?: number;
  headers?: Record<string, string> | Array<{ name: string; value: string }>;
  body?: string;
  url?: string;
  redirected?: boolean;
  time?: number;
}

export interface RedirectResult {
  param: string;
  variant: string;
  url: string;
  status: 'vulnerable' | 'safe';
  statusCode: number;
  evidence?: string;
}

/** 重定向参数 payload（29 个常见参数） */
export const REDIRECT_PAYLOADS: RedirectPayload[] = [
  { param: 'url', pattern: '?url={URL}' },
  { param: 'redirect', pattern: '?redirect={URL}' },
  { param: 'next', pattern: '?next={URL}' },
  { param: 'return', pattern: '?return={URL}' },
  { param: 'returnUrl', pattern: '?returnUrl={URL}' },
  { param: 'dest', pattern: '?dest={URL}' },
  { param: 'destination', pattern: '?destination={URL}' },
  { param: 'rurl', pattern: '?rurl={URL}' },
  { param: 'redir', pattern: '?redir={URL}' },
  { param: 'redirect_uri', pattern: '?redirect_uri={URL}' },
  { param: 'continue', pattern: '?continue={URL}' },
  { param: 'goto', pattern: '?goto={URL}' },
  { param: 'target', pattern: '?target={URL}' },
  { param: 'link', pattern: '?link={URL}' },
  { param: 'callback', pattern: '?callback={URL}' },
  { param: 'forward', pattern: '?forward={URL}' },
  { param: 'out', pattern: '?out={URL}' },
  { param: 'logout', pattern: '?logout={URL}' },
  { param: 'login', pattern: '?login={URL}' },
  { param: 'ref', pattern: '?ref={URL}' },
  { param: 'redirect_url', pattern: '?redirect_url={URL}' },
  { param: 'target_url', pattern: '?target_url={URL}' },
  { param: 'next_url', pattern: '?next_url={URL}' },
  { param: 'redirection', pattern: '?redirection={URL}' },
  { param: 'return_to', pattern: '?return_to={URL}' },
  { param: 'returnPath', pattern: '?returnPath={URL}' },
  { param: 'checkout_url', pattern: '?checkout_url={URL}' },
  { param: 'success_url', pattern: '?success_url={URL}' },
  { param: 'cancel_url', pattern: '?cancel_url={URL}' },
  { param: 'origin', pattern: '?origin={URL}' },
];

/** 协议变体（20+ 种绕过技巧） */
export const PROTOCOL_VARIANTS = [
  'https://example.com',
  '//evil.com',
  '/\\/evil.com',
  'https://evil.com',
  'https:///evil.com',
  '/evil.com',
  '\\\\evil.com',
  'http://evil.com',
  'https://evil.com%00.example.com',
  'javascript://evil.com',
  'https://attacker.com/%00/evil',
  'https://attacker.com/%0d%0a/evil',
  'data:text/html,<script>alert(1)</script>',
  'javascript:alert(1)',
  'https://attacker.com\\@target.com',
  'https://attacker.com#@target.com',
  'https://%61ttacker.com',
  'https://attacker.com%2F@target.com',
  '\\\\\\\\attacker.com',
  'https://attacker.com%09.target.com',
];

const TEST_DOMAIN = 'example.com';

/** 基于基础 URL 构建全部测试 URL */
export function buildTestUrls(baseUrl: string): RedirectTestUrl[] {
  const tests: RedirectTestUrl[] = [];
  const cleanBase = baseUrl.replace(/[?#].*$/, '');
  for (const payload of REDIRECT_PAYLOADS) {
    for (const variant of PROTOCOL_VARIANTS) {
      const fullUrl = cleanBase + payload.pattern.replace('{URL}', encodeURIComponent(variant));
      tests.push({ param: payload.param, variant, url: fullUrl });
    }
  }
  return tests;
}

/** 从响应头中提取 Location（兼容数组和对象两种格式） */
export function extractLocation(headers?: RedirectProbeResponse['headers']): string {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    for (const h of headers) {
      if (h.name && h.name.toLowerCase() === 'location') return h.value || '';
    }
    return '';
  }
  return headers['location'] || headers['Location'] || '';
}

/** 判定响应是否构成开放重定向漏洞 */
export function isRedirectVulnerable(response: RedirectProbeResponse, _variant: string): boolean {
  if (!response) return false;

  const status = response.status || 0;

  // 3xx 重定向 + Location 指向测试域
  if (status >= 300 && status < 400) {
    const location = extractLocation(response.headers);
    if (location.indexOf(TEST_DOMAIN) !== -1 || location.indexOf('evil.com') !== -1) {
      return true;
    }
  }

  // redirected 标志 + 最终 URL
  if (response.redirected && response.url) {
    if (response.url.indexOf('evil.com') !== -1 || response.url.indexOf(TEST_DOMAIN) !== -1) {
      return true;
    }
  }

  // 响应体中的 JS/meta 跳转
  const body = response.body || '';
  if (body.indexOf('evil.com') !== -1 || body.indexOf(TEST_DOMAIN) !== -1) {
    if (
      body.indexOf('http-equiv="refresh"') !== -1 ||
      body.indexOf('location.replace') !== -1 ||
      body.indexOf('location.href') !== -1 ||
      body.indexOf('location =') !== -1
    ) {
      return true;
    }
  }

  return false;
}
