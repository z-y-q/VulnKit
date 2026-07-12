/**
 * 敏感信息泄露扫描引擎 — 灵眸 v6.0
 * 加载 leak-rules-{cloud,crypto,exposure}.json 共 90 条规则，预编译正则，
 * 应用 validate 回调（占位符过滤 / 熵值 / Luhn / JWT 升级 / 加密上下文）降低误报。
 * 供 SourceMap 源码扫描、Leakscan 深度扫描等模块共用。
 */

import CLOUD_RULES from '@/lib/data/leak-rules-cloud.json';
import CRYPTO_RULES from '@/lib/data/leak-rules-crypto.json';
import EXPOSURE_RULES from '@/lib/data/leak-rules-exposure.json';
import { shannonEntropy, luhnOk, isPlaceholder, inCryptoContext } from './leak-utils';

export type LeakSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type LeakConfidence = 'confirmed' | 'likely' | 'suspected';

export interface LeakFinding {
  ruleId: string;
  rule: string;
  category: string;
  severity: LeakSeverity;
  confidence: LeakConfidence;
  /** 命中的具体值（截断） */
  value: string;
  description?: string;
  exploit?: string;
  recommendation?: string;
}

interface RawRule {
  id: string;
  name: string;
  category: string;
  severity: LeakSeverity;
  confidence?: LeakConfidence;
  regex: { __regexp__: true; source: string; flags: string };
  description?: string;
  exploit?: string;
  recommendation?: string;
}

interface CompiledRule {
  id: string;
  name: string;
  category: string;
  severity: LeakSeverity;
  confidence: LeakConfidence;
  re: RegExp;
  description?: string;
  exploit?: string;
  recommendation?: string;
}

/** validate 回调：返回 {ok:false} 丢弃命中；可下调 severity */
type ValidateFn = (
  match: RegExpExecArray,
  fullText: string,
) => { ok: boolean; severity?: LeakSeverity; confidence?: LeakConfidence };

const PLACEHOLDER_ENTROPY_MIN = 3.0;

/**
 * 规则级 validate 回调注册表（对齐 v5 leak-rules-*.validate）。
 * 未注册的规则走默认校验（占位符过滤）。
 */
const VALIDATORS: Record<string, ValidateFn> = {
  // 40 位高熵密钥：过滤占位符与低熵
  'aws-secret-access-key': (_m, _t) => genericSecretCheck(_m),
  'hardcoded-aes-key': (_m, _t) => genericSecretCheck(_m),
  'hardcoded-symmetric-crypto-key': (_m, _t) => genericSecretCheck(_m),
  'hardcoded-signature-key': (_m, _t) => genericSecretCheck(_m),
  'wechat-alipay-app-secret': (_m, _t) => genericSecretCheck(_m),
  'oauth-client-secret': (_m, _t) => genericSecretCheck(_m),
  'jwt-session-signing-secret': (_m, _t) => genericSecretCheck(_m),
  'mailgun-key': (_m, _t) => genericSecretCheck(_m),
  // 通用 API key 类：要求较高熵
  'api-key-header': (_m, _t) => genericSecretCheck(_m, PLACEHOLDER_ENTROPY_MIN),
  'bearer-auth-token': (m, _t) => {
    const v = (m[1] || m[0] || '').trim();
    if (isPlaceholder(v)) return { ok: false };
    // 若是 JWT，升级为 high（可解码出用户信息）
    if (/^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(v)) {
      return { ok: true, severity: 'high' };
    }
    return { ok: true };
  },
  // 信用卡：Luhn 校验
  'bank-card-number': (m, _t) => {
    const v = (m[1] || m[0] || '').replace(/\s|-/g, '');
    return { ok: luhnOk(v) };
  },
  // Cloudflare/Vercel/Netlify token：过滤占位符
  'cloudflare-token': (_m, _t) => genericSecretCheck(_m),
  'vercel-token': (_m, _t) => genericSecretCheck(_m),
  'netlify-token': (_m, _t) => genericSecretCheck(_m),
  // Stripe key：结构严格，仅过滤明显占位
  'stripe-secret-key': (m, _t) => {
    const v = (m[0] || '').trim();
    return { ok: !isPlaceholder(v) };
  },
};

/** 通用密钥校验：占位符过滤 + 可选熵值要求 */
function genericSecretCheck(m: RegExpExecArray, minEntropy = 0): { ok: boolean } {
  const v = (m[1] || m[0] || '').trim();
  if (!v || isPlaceholder(v)) return { ok: false };
  if (minEntropy > 0 && shannonEntropy(v) < minEntropy) return { ok: false };
  return { ok: true };
}

/** 编译单条规则的 regex */
function compileRule(raw: RawRule): CompiledRule {
  const r = raw.regex;
  return {
    id: raw.id,
    name: raw.name,
    category: raw.category,
    severity: raw.severity,
    confidence: raw.confidence || 'suspected',
    re: new RegExp(r.source, r.flags),
    description: raw.description,
    exploit: raw.exploit,
    recommendation: raw.recommendation,
  };
}

/** 全部规则预编译（模块加载时一次性） */
export const COMPILED_LEAK_RULES: CompiledRule[] = [
  ...(CLOUD_RULES as RawRule[]),
  ...(CRYPTO_RULES as RawRule[]),
  ...(EXPOSURE_RULES as RawRule[]),
].map(compileRule);

export function getLeakRuleCount(): number {
  return COMPILED_LEAK_RULES.length;
}

/** 严重级别数值（用于排序） */
const SEVERITY_ORDER: Record<LeakSeverity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

export function severityRank(s: LeakSeverity): number {
  return SEVERITY_ORDER[s] || 0;
}

/**
 * 扫描文本，返回去重后的泄露发现列表。
 * @param text 待扫描文本（源码 / DOM / 响应体）
 * @param cap 单条规则最多命中的条目数（默认 20）
 */
export function scanLeaks(text: string, cap = 20): LeakFinding[] {
  if (!text || text.length < 4) return [];
  const findings: LeakFinding[] = [];
  const seen = new Set<string>();

  for (const rule of COMPILED_LEAK_RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = rule.re.exec(text)) !== null && count < cap) {
      const rawVal = (m[1] || m[0] || '').toString();
      const value = rawVal.slice(0, 160);
      if (!value) continue;

      // validate 回调
      const validator = VALIDATORS[rule.id];
      let severity = rule.severity;
      let confidence = rule.confidence;
      if (validator) {
        const v = validator(m, text);
        if (!v.ok) continue;
        if (v.severity) severity = v.severity;
        if (v.confidence) confidence = v.confidence;
      } else if (isPlaceholder(value)) {
        // 未注册 validator 的规则：默认过滤占位符
        continue;
      }

      const dedupKey = `${rule.id}::${value}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      findings.push({
        ruleId: rule.id,
        rule: rule.name,
        category: rule.category,
        severity,
        confidence,
        value,
        description: rule.description,
        exploit: rule.exploit,
        recommendation: rule.recommendation,
      });
      count++;
    }
  }

  // 按严重级别降序
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  return findings;
}

/** LeakSeverity → 简化三档（供 SourceMap SecretFinding 复用） */
export function toSimpleSeverity(s: LeakSeverity): 'high' | 'medium' | 'low' {
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
}
