/**
 * ResponsiveTable 列逻辑（纯函数，便于单测）— 灵眸 v6（§7.4 / §14.3）
 * 表格在窄宽下按 hideUnder 隐藏次要列，更窄时切换为卡片列表。
 */

export interface Col {
  /** 行数据中对应的字段名 */
  key: string;
  /** 表头文案 */
  header: string;
  /** 视口宽度（px）小于此值时在表格中隐藏该列；卡片模式下仍显示 */
  hideUnder?: number;
  /** 卡片模式下作为卡片标题的列（建议仅一列） */
  primary?: boolean;
}

/**
 * 表格模式下当前可见列：未设 hideUnder 的列恒显示；设了 hideUnder 的列仅在
 * width >= hideUnder 时显示。width 为 0（如 SSR/初始）时只显示无 hideUnder 的列。
 */
export function visibleColumns<T extends Col>(cols: T[], width: number): T[] {
  return cols.filter((c) => !c.hideUnder || width >= c.hideUnder);
}

/** 选取卡片标题列：第一个 primary；否则回退第一列；空数组返回 undefined。 */
export function pickPrimary<T extends Col>(cols: T[]): T | undefined {
  return cols.find((c) => c.primary) ?? cols[0];
}

/** 卡片模式下除标题列外的其余列（键值对展示）。 */
export function cardColumns<T extends Col>(cols: T[], primary: T | undefined): T[] {
  if (!primary) return [];
  return cols.filter((c) => c !== primary);
}

/** 是否进入卡片模式：宽度低于 cardBreakpoint。 */
export function shouldUseCardMode(width: number, cardBreakpoint = 480): boolean {
  return width < cardBreakpoint;
}

/** 分页计算结果 */
export interface PaginationResult {
  totalPages: number;
  /** 夹紧到 [1, totalPages] 后的当前页 */
  safePage: number;
  /** 可见行起始下标（含） */
  start: number;
  /** 可见行结束下标（不含） */
  end: number;
}

/**
 * 分页计算（§4.1）：返回总页数、夹紧后的当前页与可见行范围 [start, end)。
 * pageSize ≤ 0 视为 1；page 超界自动夹紧；total 为 0 时 totalPages=1、start=end=0。
 */
export function paginate(total: number, page: number, pageSize: number): PaginationResult {
  const ps = Math.max(1, Math.floor(pageSize) || 1);
  const totalPages = Math.max(1, Math.ceil(total / ps));
  const safePage = Math.min(Math.max(1, Math.floor(page) || 1), totalPages);
  const start = (safePage - 1) * ps;
  const end = Math.min(start + ps, Math.max(0, total));
  return { totalPages, safePage, start, end };
}
