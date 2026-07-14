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
