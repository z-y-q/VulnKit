// 灵眸 v6.0 — SSRF 防护与 URL 校验
// 所有 background 代理的请求都先经过这里，阻止访问私有/内网地址。

const PRIVATE_HOST_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|127\.|169\.254\.)/;
const IPV6_PRIVATE_RE = /\[::ffff:(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/;
const LINK_LOCAL_SUFFIX_RE = /\.(local|internal)$/;

/**
 * 判断 URL 是否允许被 background 代理访问。
 * 拒绝非 http(s)、loopback、私网、链路本地、纯数字主机名。
 */
export function isAllowedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '[::ffff:127.0.0.1]'
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
