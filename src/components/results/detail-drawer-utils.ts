/**
 * DetailDrawer 纯函数与类型（对齐 docs/UX-UI优化建议.md §5.3）
 *
 * 从 DetailDrawer.svelte 抽出，便于单测与面板复用（面板构造 fields/actions 时直接 import 类型）。
 */

/** 详情字段（键值对，mono 等宽渲染，如 URL/Header/ACAO） */
export interface DetailField {
  label: string;
  value: string;
  mono?: boolean;
}

/** 跨面板交接动作：点击 → analysisContextStore.handoff 到目标面板 */
export interface DetailHandoffAction<T> {
  label: string;
  targetPanel: string;
  build: (item: T) => { payload: Record<string, string>; summary?: string };
}

/** 严重度 → 颜色 tone（容错未知值，大小写无关；不耦合各面板严格枚举类型） */
export function severityTone(sev: string | undefined | null): string {
  switch ((sev ?? '').toLowerCase()) {
    case 'critical':
    case 'danger':
    case 'high':
      return 'danger';
    case 'warning':
    case 'medium':
      return 'warn';
    case 'low':
      return 'low';
    case 'safe':
    case 'pass':
      return 'ok';
    case 'info':
      return 'info';
    default:
      return 'muted';
  }
}
