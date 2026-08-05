/**
 * 统一严重级别定义
 * 全项目唯一的 severity 真相源：引擎/面板/报告/共享组件都从这里取。
 * 避免各模块各写一份 label / order / color 映射。
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** 排序权重（越小越严重），用于结果按风险降序 */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** 中文标签 */
export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

/** UnoCSS 淡彩描边类（Apple 风格：浅底 + 同色文字 + 1px ring；暗色相应加深）。
 *  单一真相源 —— 所有扫描面板的严重级别徽章都从这里取色。 */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60',
  high: 'bg-red-50 text-red-600 ring-1 ring-inset ring-red-200 dark:bg-red-900/25 dark:text-red-300 dark:ring-red-800/50',
  medium: 'bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:ring-amber-800/60',
  low: 'bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:ring-blue-800/60',
  info: 'bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-200 dark:bg-slate-700/40 dark:text-slate-300 dark:ring-slate-600/60',
};

/** 兼容别名（部分引擎用 danger/warning/safe 等非标准级别）→ 标准 Severity */
export const SEVERITY_ALIASES: Record<string, Severity> = {
  danger: 'high',
  warning: 'medium',
  safe: 'info',
};

/** 归一化任意级别字符串为标准 Severity */
export function normalizeSeverity(s: string): Severity {
  const lower = (s || '').toLowerCase();
  if (lower in SEVERITY_ORDER) return lower as Severity;
  if (lower in SEVERITY_ALIASES) return SEVERITY_ALIASES[lower];
  return 'info';
}

/** 严重级别 → 中文标签（容错任意输入） */
export function severityLabel(s: string): string {
  return SEVERITY_LABELS[normalizeSeverity(s)] ?? s;
}

/** 比较函数：越严重越靠前 */
export function compareSeverity(a: string, b: string): number {
  return SEVERITY_ORDER[normalizeSeverity(a)] - SEVERITY_ORDER[normalizeSeverity(b)];
}
