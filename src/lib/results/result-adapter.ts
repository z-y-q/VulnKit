/**
 * 结果查询适配器 — 灵眸 v6.0
 *
 * 对齐 docs/UX-UI优化建议.md §10.3：不强迫面板共享同一种 finding 结构，
 * 而是共享 query 协议。ResultToolbar 通过 adapter.apply(rawItems, query) 得到
 * 统一的展示/统计/复制/导出结果，各面板只定义自己的字段与筛选语义。
 */

export interface ResultQuery {
  /** 关键字搜索（在 adapter.getSearchText 上做不区分大小写子串匹配） */
  search: string;
  /** 自定义筛选槽：key → 选中的值集合（语义由 adapter 解读，约定 AND 跨 key / OR 同 key 内） */
  filters: Record<string, string[]>;
  /** 排序 */
  sort: { key: string; direction: 'asc' | 'desc' };
}

export interface ResultAdapter<TItem> {
  /** 应用 query（搜索 + 筛选 + 排序），返回应展示的子集 */
  apply(items: TItem[], query: ResultQuery): TItem[];
  /** 取项的可搜索文本（拼接所有可搜字段） */
  getSearchText(item: TItem): string;
  /** 取项的唯一 id（用于 :key 列表渲染） */
  getId(item: TItem): string;
}

export const EMPTY_QUERY: ResultQuery = {
  search: '',
  filters: {},
  sort: { key: '', direction: 'asc' },
};

/** 判断 query 是否有任意生效的筛选（用于「清除筛选」按钮的显隐） */
export function hasActiveQuery(query: ResultQuery): boolean {
  if (query.search.trim()) return true;
  for (const k in query.filters) {
    if (query.filters[k] && query.filters[k].length > 0) return true;
  }
  return false;
}

/** 深拷贝一个 query（filters 内部数组也独立，便于面板 bind 时产生新引用触发派生） */
export function cloneQuery(query: ResultQuery): ResultQuery {
  return {
    search: query.search,
    filters: Object.fromEntries(
      Object.entries(query.filters).map(([k, v]) => [k, [...v]]),
    ),
    sort: { ...query.sort },
  };
}
