// 灵眸 v6.0 — SSRF 防护与 URL 校验
// 所有 background 代理的请求都先经过这里，阻止访问私有/内网地址。

const PRIVATE_HOST_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|127\.|169\.254\.)/;
// new URL().hostname 会去掉 IPv6 方括号，故此处用无括号形式匹配
const IPV6_PRIVATE_RE = /^(::1|::ffff:(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)|fe80:|fc00:|fd00:)/;
const LINK_LOCAL_SUFFIX_RE = /\.(local|internal)$/;

/**
 * 判断 URL 是否允许被 background 代理访问。
 * 拒绝非 http(s)、loopback、私网、链路本地、纯数字主机名。
 */
export function isAllowedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    // WHATWG URL 的 hostname 对 IPv6 保留方括号（如 [::1]），统一去掉再匹配，
    // 否则 loopback [::1] 会绕过 '::1' 相等判断与 IPV6_PRIVATE_RE。
    const hostname = parsed.hostname.toLowerCase().replace(/^\[|]$/g, '');
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname.startsWith('::ffff:127.')
    ) {
      return false;
    }
    if (PRIVATE_HOST_RE.test(hostname)) return false;
    if (IPV6_PRIVATE_RE.test(hostname)) return false;
    if (/^\d+$/.test(hostname)) return false; // 纯数字（十进制 IP）
    if (LINK_LOCAL_SUFFIX_RE.test(hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

/** 校验探测 URL，返回 parsed 或 error。 */
export function validateProbeUrl(
  url: string,
): { error: string } | { parsed: URL } {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { error: 'Invalid protocol' };
    }
    return { parsed };
  } catch {
    return { error: 'Invalid URL' };
  }
}
