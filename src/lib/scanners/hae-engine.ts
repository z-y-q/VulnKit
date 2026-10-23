/**
 * HAE 规则引擎（构建优化 P1 — 动态加载规则 JSON）
 * HaE (Highlight and Extract) 风格的正则匹配引擎，对齐 v5 vk-hae-rules.js。
 * 运行时从 /rules/hae-default-rules.json 动态加载规则，减少主 bundle 体积。
 */

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

/** 默认规则组缓存（首次调用时从 JSON 加载） */
let _defaultRulesCache: HaeGroup[] | null = null;

/** 动态加载默认规则组（构建优化：从 bundle 移到运行时 fetch）*/
async function loadDefaultRules(): Promise<HaeGroup[]> {
  if (_defaultRulesCache) return _defaultRulesCache;

  try {
    const response = await fetch(browser.runtime.getURL('rules/hae-default-rules.json'));
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    _defaultRulesCache = (await response.json()) as HaeGroup[];
    return _defaultRulesCache;
  } catch (e) {
    console.error('加载 HAE 默认规则失败，降级为空规则集:', e);
    _defaultRulesCache = [];
    return [];
  }
}

/** 默认规则组（兼容同步访问场景 — 必须先调用 loadDefaultRules）*/
export const DEFAULT_HAE_GROUPS: HaeGroup[] = [];

/** 初始化默认规则（扩展启动时调用一次）*/
export async function initDefaultRules(): Promise<void> {
  const rules = await loadDefaultRules();
  DEFAULT_HAE_GROUPS.length = 0;
  DEFAULT_HAE_GROUPS.push(...rules);
}

/** 获取默认规则组（异步版本，确保规则已加载）*/
export async function getDefaultRules(): Promise<HaeGroup[]> {
  return await loadDefaultRules();
}

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
