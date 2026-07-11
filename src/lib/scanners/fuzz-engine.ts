/**
 * 目录扫描引擎 — 灵眸 v6.0
 * 从 vk-fuzz.js 提取的纯逻辑（内容分析 + 路径构建）
 * 网络探测由调用方提供 probeFn
 */

import wordlists from '../data/fuzz-wordlists.json';

export type WordlistKey = keyof typeof wordlists;

export interface ContentPattern {
  regex: RegExp;
  tag: string;
  group: 'title' | 'feature' | 'security' | 'framework' | 'infoleak';
}

export interface AnalyzedContent {
  title: string;
  tags: string[];
}

export interface FuzzProbeResponse {
  status?: number;
  body?: string;
  headers?: Record<string, string> | Array<{ name: string; value: string }>;
  time?: number;
  _method?: string;
}

export interface FuzzResult {
  path: string;
  url: string;
  status: number;
  size: number;
  time: number;
  method: string;
  analysis?: AnalyzedContent | null;
}

/** 内容识别模式（20 条） */
export const CONTENT_PATTERNS: ContentPattern[] = [
  { regex: /<title[^>]*>(.*?)<\/title>/i, tag: 'HTML 页面', group: 'title' },
  { regex: /(?:login|sign.?in|登录|authenticat)/i, tag: '登录页面', group: 'feature' },
  { regex: /(?:admin|管理|dashboard|控制台|后台)/i, tag: '管理界面', group: 'feature' },
  { regex: /(?:api|endpoint|swagger|openapi)/i, tag: 'API 接口', group: 'feature' },
  { regex: /(?:error|exception|stack.?trace|错误)/i, tag: '错误信息', group: 'feature' },
  { regex: /(?:config|配置|setting|参数)/i, tag: '配置信息', group: 'feature' },
  { regex: /(?:database|mysql|postgres|mongodb|redis)/i, tag: '数据库', group: 'feature' },
  { regex: /(?:password|passwd|secret|token|key=)/i, tag: '敏感信息', group: 'feature' },
  { regex: /WAF|防火墙|拦截|block|forbidden/i, tag: 'WAF', group: 'security' },
  { regex: /验证码|captcha|CAPTCHA|recaptcha/i, tag: '验证码', group: 'security' },
  { regex: /Location:\s*https?:\/\//i, tag: '302重定向', group: 'security' },
  { regex: /401\s+Unauthorized/i, tag: '401认证', group: 'security' },
  { regex: /403\s+Forbidden/i, tag: '403禁止', group: 'security' },
  { regex: /spring|springframework|springboot/i, tag: 'Spring', group: 'framework' },
  { regex: /laravel|symfony|django|flask|express/i, tag: '框架', group: 'framework' },
  { regex: /swagger|api-docs|openapi/i, tag: 'API文档', group: 'infoleak' },
  { regex: /phpinfo\(\)|PHP Version/i, tag: 'PHPInfo', group: 'infoleak' },
  { regex: /debug|stack\s+trace|exception|traceback/i, tag: '调试信息', group: 'infoleak' },
  { regex: /git|svn|\.git\/|\.svn\//i, tag: '版本控制', group: 'infoleak' },
  { regex: /docker|kubernetes|k8s/i, tag: '容器特征', group: 'infoleak' },
];

/** 获取指定字典 */
export function getWordlist(key: WordlistKey): string[] {
  return wordlists[key] as string[];
}

/** 获取所有字典键 */
export function getWordlistKeys(): WordlistKey[] {
  return Object.keys(wordlists) as WordlistKey[];
}

/** 从响应头提取指定头（兼容数组和对象） */
export function extractHeader(
  headers: FuzzProbeResponse['headers'],
  name: string
): string {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    for (const h of headers) {
      if (h.name && h.name.toLowerCase() === name) return h.value || '';
    }
    return '';
  }
  return headers[name] || headers[name.toLowerCase()] || '';
}

/** 提取 Content-Length */
export function extractContentLength(headers: FuzzProbeResponse['headers']): number {
  const val = extractHeader(headers, 'content-length');
  return val ? parseInt(val, 10) : 0;
}

/** 分析响应体内容（识别页面类型与特征） */
export function analyzeContent(body?: string): AnalyzedContent | null {
  if (!body || body.length < 10) return null;
  const result: AnalyzedContent = { title: '', tags: [] };
  for (const pat of CONTENT_PATTERNS) {
    const match = body.match(pat.regex);
    if (match) {
      if (pat.group === 'title') {
        result.title = match[1] ? match[1].trim().substring(0, 100) : '';
      } else {
        if (!result.tags.includes(pat.tag)) result.tags.push(pat.tag);
      }
    }
  }
  return result;
}

/** 判定状态码是否为"发现"（存在的路径） */
export function isFoundStatus(status: number): boolean {
  // 2xx、3xx、401、403 通常表示路径存在（非 404）
  return (
    (status >= 200 && status < 400) || status === 401 || status === 403 || status === 405
  );
}

/** 排序函数 */
export const FUZZ_SORT_FNS: Record<string, (a: FuzzResult, b: FuzzResult) => number> = {
  status: (a, b) => a.status - b.status,
  size: (a, b) => b.size - a.size,
  time: (a, b) => a.time - b.time,
};
