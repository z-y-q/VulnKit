/**
 * WAF 指纹检测引擎（纯分析逻辑）
 *
 * 从 WafPanel.svelte 抽取的签名匹配核心，供 WAF 面板与 XSS/SQLi 扫描结果联动复用：
 * - analyzeResponse(headers, body)：对响应做 WAF 签名匹配（header/body/cookie 三路）
 * - detectWafInResponse(headers, body)：轻量便捷版，返回命中 WAF 名称与证据（联动标注用）
 * - looksLikeWafBlock(status, body)：无签名命中时按状态码/拦截话术判断疑似阻断
 *
 * 签名库模块加载时一次性预编译（对齐 sniff-engine 策略），运行时零 new RegExp。
 */

import signatures from '@/lib/data/waf-signatures.json';

// ====== 类型 ======

export interface WafPattern {
  __regexp__: boolean;
  source: string;
  flags: string;
}

export interface WafSignature {
  name: string;
  severity: 'high' | 'medium' | 'low';
  headerMatch: WafPattern[];
  bodyMatch: WafPattern[];
  cookieMatch: WafPattern[];
}

export interface WafEvidence {
  type: 'header' | 'body' | 'cookie';
  value: string;
}

export interface WafDetection {
  name: string;
  severity: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: WafEvidence[];
  probe?: string;
}

export const WAF_SIGNATURES: WafSignature[] = signatures as WafSignature[];

// ====== 预编译 ======

interface CompiledWafSignature {
  name: string;
  severity: string;
  header: RegExp[];
  body: RegExp[];
  cookie: RegExp[];
}

function compileList(patterns: WafPattern[]): RegExp[] {
  const out: RegExp[] = [];
  for (const p of patterns) {
    try {
      out.push(new RegExp(p.source, p.flags));
    } catch {
      /* 非法正则编译期剔除 */
    }
  }
  return out;
}

const COMPILED_SIGNATURES: CompiledWafSignature[] = WAF_SIGNATURES.map((sig) => ({
  name: sig.name,
  severity: sig.severity,
  header: compileList(sig.headerMatch),
  body: compileList(sig.bodyMatch),
  cookie: compileList(sig.cookieMatch),
}));

/** 暴露编译缓存（供测试验证预编译单例性） */
export function getCompiledWafSignatures(): CompiledWafSignature[] {
  return COMPILED_SIGNATURES;
}

// ====== 匹配 ======

function matchCompiled(text: string, regexes: RegExp[]): string[] {
  if (!text || regexes.length === 0) return [];
  const hits: string[] = [];
  for (const re of regexes) {
    const m = text.match(re);
    if (m) hits.push(m[0]);
  }
  return hits;
}

function serializeHeaders(headers: Record<string, string> | undefined): { headerStr: string; cookieStr: string } {
  let headerStr = '';
  let cookieStr = '';
  if (headers) {
    for (const k of Object.keys(headers)) {
      const val = headers[k];
      headerStr += `${k}: ${Array.isArray(val) ? val.join('\n') : val}\n`;
    }
    const sc = headers['set-cookie'] || headers['Set-Cookie'] || '';
    cookieStr = Array.isArray(sc) ? sc.join('\n') : sc;
  }
  return { headerStr, cookieStr };
}

/**
 * 对单个响应做全量 WAF 签名匹配。
 * confidence 规则与面板原逻辑一致：证据 ≥3 high / ≥2 medium / 1 low。
 */
export function analyzeResponse(
  headers: Record<string, string> | undefined,
  body: string | undefined,
): WafDetection[] {
  const { headerStr, cookieStr } = serializeHeaders(headers);
  const bodyStr = typeof body === 'string' ? body : '';

  const detected: WafDetection[] = [];
  for (const sig of COMPILED_SIGNATURES) {
    const evidence: WafEvidence[] = [];
    for (const hit of matchCompiled(headerStr, sig.header)) {
      evidence.push({ type: 'header', value: hit });
    }
    for (const hit of matchCompiled(bodyStr, sig.body)) {
      evidence.push({ type: 'body', value: hit });
    }
    for (const hit of matchCompiled(cookieStr, sig.cookie)) {
      evidence.push({ type: 'cookie', value: hit });
    }
    if (evidence.length > 0) {
      detected.push({
        name: sig.name,
        severity: sig.severity,
        confidence: evidence.length >= 3 ? 'high' : evidence.length >= 2 ? 'medium' : 'low',
        evidence,
      });
    }
  }
  return detected;
}

/** 轻量便捷版：只返回命中的 WAF 名称与证据文本（联动标注用） */
export function detectWafInResponse(
  headers: Record<string, string> | undefined,
  body: string | undefined,
): { name: string; evidence: string[] }[] {
  return analyzeResponse(headers, body).map((d) => ({
    name: d.name,
    evidence: d.evidence.map((e) => e.value),
  }));
}

// ====== 行为阻断判定 ======

/** 常见 WAF 阻断状态码 */
const BLOCK_STATUS = new Set([403, 406, 418, 429, 501]);

/** 拦截页常见话术（限定短响应，避免正文里提到 WAF 的正常页面误报） */
const BLOCK_PHRASES =
  /(?:request blocked|access denied|blocked by waf|您的请求被拦截|请求被阻断|访问被拒绝|操作已被拦截|已被防火墙拦截)/i;

/**
 * 无签名命中时的兜底判定：拦截状态码，或短响应中的拦截话术。
 */
export function looksLikeWafBlock(status: number, body?: string): boolean {
  if (status && BLOCK_STATUS.has(status)) return true;
  if (body && body.length > 0 && body.length < 20000) return BLOCK_PHRASES.test(body);
  return false;
}
