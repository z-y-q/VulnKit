/**
 * HAE 规则引擎
 * HaE (Highlight and Extract) 风格的正则匹配引擎，对齐 v5 vk-hae-rules.js。
 * 加载 hae-default-rules.json，对文本应用 f_regex + s_regex 二次过滤 + format 模板格式化。
 */

import HAE_RULES from '@/lib/data/hae-default-rules.json';

export interface HaeRule {
  name: string;
  loaded: boolean;
  f_regex: string;
  s_regex: string;
  format: string;
  color: string;
  scope: string;
  engine: string;
  sensitive: boolean;
}

export interface HaeGroup {
  group: string;
  rules: HaeRule[];
}

export interface HaeMatch {
  rule: string;
  group: string;
  value: string;
  color: string;
  sensitive: boolean;
}

/** 默认规则组（从 JSON 加载） */
export const DEFAULT_HAE_GROUPS: HaeGroup[] = HAE_RULES as HaeGroup[];

/** format 模板替换：{0} {1} → 捕获组 */
function applyFormat(format: string, captures: string[]): string {
  let result = format || '{0}';
  for (let i = 0; i < captures.length; i++) {
    result = result.replace(new RegExp(`\\{${i}\\}`, 'g'), captures[i] || '');
  }
  return result;
}

/**
 * 对单条文本应用一条规则，返回所有匹配（格式化后的值）。
 */
export function matchSingleRule(text: string, rule: HaeRule): string[] {
  if (!rule.loaded || !rule.f_regex) return [];
  const results: string[] = [];
  let regex: RegExp;
  try {
    const flags = rule.engine === 'dfa' ? 'g' : 'gi';
    regex = new RegExp(rule.f_regex, flags);
  } catch {
    return []; // 非则正则
  }
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = regex.exec(text)) !== null && count < 50) {
    const captures: string[] = [];
    for (let i = 0; i < (m.length || 1); i++) captures.push(m[i] || '');
    const value = applyFormat(rule.format || '{0}', captures);
    // s_regex 二次过滤：值必须匹配 s_regex 才保留
    if (rule.s_regex && rule.s_regex.trim() !== '') {
      try {
        const sRegex = new RegExp(rule.s_regex, 'i');
        if (!sRegex.test(value)) continue;
      } catch {
        // 非法 s_regex，跳过过滤
      }
    }
    if (!results.includes(value)) {
      results.push(value);
      count++;
    }
    // 防零宽匹配死循环
    if (m.index === regex.lastIndex) regex.lastIndex++;
  }
  return results;
}

/** 对文本应用所有已加载规则，返回匹配列表（按敏感度+分组排序） */
export function matchAllRules(text: string, groups: HaeGroup[] = DEFAULT_HAE_GROUPS): HaeMatch[] {
  if (!text) return [];
  const matches: HaeMatch[] = [];
  for (const grp of groups) {
    for (const rule of grp.rules) {
      const values = matchSingleRule(text, rule);
      for (const value of values) {
        matches.push({
          rule: rule.name,
          group: grp.group,
          value,
          color: rule.color || 'gray',
          sensitive: !!rule.sensitive,
        });
      }
    }
  }
  // 敏感优先，再按分组
  matches.sort((a, b) => (b.sensitive ? 1 : 0) - (a.sensitive ? 1 : 0) || a.group.localeCompare(b.group));
  return matches;
}

/** 颜色名 → CSS 类（HaE 风格） */
export const HAE_COLOR_CLASS: Record<string, string> = {
  green: 'bg-green-500',
  yellow: 'bg-yellow-500',
  orange: 'bg-orange-500',
  red: 'bg-red-500',
  pink: 'bg-pink-500',
  purple: 'bg-purple-500',
  blue: 'bg-blue-500',
  gray: 'bg-gray-500',
  cyan: 'bg-cyan-500',
};
