/**
 * HaE 自定义规则持久化 — 灵眸 v6.0
 * 用户可在选项页用 YAML 编辑自定义 HaE 规则（对齐 v5 vk-hae-rules.js 的 YAML 管理）。
 * 自定义规则与默认规则合并后供 gather / leakscan 使用。
 */

import * as yaml from 'js-yaml';
import { DEFAULT_HAE_GROUPS, type HaeGroup, type HaeRule } from './hae-engine';

const STORAGE_KEY = 'haeCustomRules';

/** 默认规则的 YAML 文本（选项页初始化 / 恢复默认用） */
export function defaultRulesToYaml(): string {
  return yaml.dump(DEFAULT_HAE_GROUPS, { lineWidth: -1 });
}

/** 读取 storage 中的自定义规则 YAML 文本，无则返回空串 */
export async function loadCustomRulesYaml(): Promise<string> {
  try {
    const r = await browser.storage.local.get(STORAGE_KEY);
    return (r?.[STORAGE_KEY] as string) ?? '';
  } catch {
    return '';
  }
}

/** 保存自定义规则 YAML 文本到 storage */
export async function saveCustomRulesYaml(text: string): Promise<void> {
  await browser.storage.local.set({ [STORAGE_KEY]: text });
}

/** 清除自定义规则（恢复为仅使用默认规则） */
export async function clearCustomRules(): Promise<void> {
  await browser.storage.local.remove(STORAGE_KEY);
}

/** 校验并解析 YAML → HaeGroup[]，非法时抛错（含行号信息） */
export function parseRulesYaml(text: string): HaeGroup[] {
  if (!text.trim()) return [];
  const obj = yaml.load(text);
  if (!Array.isArray(obj)) throw new Error('YAML 顶层应为规则组数组');
  // 轻量结构校验 + 字段补全
  return (obj as any[]).map((g, gi) => {
    if (!g || typeof g !== 'object' || !Array.isArray(g.rules)) {
      throw new Error(`第 ${gi + 1} 组缺少 rules 数组`);
    }
    return {
      group: String(g.group ?? `分组${gi + 1}`),
      rules: g.rules.map((r: any, ri: number) => {
        if (!r || typeof r !== 'object') throw new Error(`第 ${gi + 1} 组第 ${ri + 1} 条规则格式错误`);
        if (!r.f_regex) throw new Error(`第 ${gi + 1} 组第 ${ri + 1} 条规则缺少 f_regex`);
        const rule: HaeRule = {
          name: String(r.name ?? `rule${ri + 1}`),
          loaded: r.loaded !== false,
          f_regex: String(r.f_regex),
          s_regex: String(r.s_regex ?? ''),
          format: String(r.format ?? '{0}'),
          color: String(r.color ?? 'gray'),
          scope: String(r.scope ?? 'response'),
          engine: String(r.engine ?? 'nfa'),
          sensitive: !!r.sensitive,
        };
        // 预校验正则合法性
        try { new RegExp(rule.f_regex); } catch (e: any) {
          throw new Error(`规则「${rule.name}」f_regex 非法: ${e.message}`);
        }
        return rule;
      }),
    };
  });
}

/**
 * 加载合并后的规则组：默认规则 + 自定义规则（自定义追加在末尾）。
 * 自定义规则解析失败时降级为仅默认规则。
 */
export async function loadMergedGroups(): Promise<HaeGroup[]> {
  try {
    const text = await loadCustomRulesYaml();
    if (!text.trim()) return DEFAULT_HAE_GROUPS;
    const custom = parseRulesYaml(text);
    return [...DEFAULT_HAE_GROUPS, ...custom];
  } catch {
    return DEFAULT_HAE_GROUPS;
  }
}
