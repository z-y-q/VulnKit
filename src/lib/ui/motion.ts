/**
 * Apple Design 动效构造器（技能 §3 中断性 / §4 弹簧 / §7 对称路径）。
 *
 * Svelte 内置 transition 不会自动响应 prefers-reduced-motion；这里集中处理，
 * 在动效偏好下降级为瞬切（duration: 0）。shared.css 另有全局
 * `animation-duration: 0.001ms !important` 兜底，此处显式处理更干净、不依赖顺序。
 *
 * 全部使用「临界阻尼近似」(cubicOut) —— 专业工具不加弹性回弹，只做顺滑收尾。
 * 用 `transition:` 指令而非 `in:`/`out:`，则进/出共用同一曲线，自动满足 §7 对称路径。
 */
import { cubicOut } from 'svelte/easing';
import type { TransitionConfig } from 'svelte/transition';

/** 当前是否偏好减弱动效（SSR/非浏览器环境安全降级） */
export function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

/** reduced-motion 下的瞬切配置 */
const INSTANT: TransitionConfig = { duration: 0 };

/**
 * 抽屉 / Sheet：从右侧滑入 + 轻微缩放「物质化抵达」(§12)，退出镜像滑出 (§7)。
 * 用于 DetailDrawer。
 */
export function sheetTransition(
  node: Element,
  { distance = 24, duration = 260 }: { distance?: number; duration?: number } = {},
): TransitionConfig {
  if (prefersReducedMotion()) return INSTANT;
  return {
    duration,
    easing: cubicOut,
    css: (t) =>
      `transform: translateX(${(1 - t) * distance}px) scale(${0.985 + 0.015 * t}); opacity: ${t}`,
  };
}

/**
 * 遮罩：纯淡入/淡出。
 * 用于模态遮罩（DetailDrawer / ConfirmDialog 的 scrim）。
 */
export function scrimFade(
  node: Element,
  { duration = 200 }: { duration?: number } = {},
): TransitionConfig {
  if (prefersReducedMotion()) return INSTANT;
  return {
    duration,
    easing: cubicOut,
    css: (t) => `opacity: ${t}`,
  };
}

/**
 * 弹出 / 对话框：缩放 + 淡入「物质化抵达」(§12)，退出镜像 (§7)。
 * 用于 ConfirmDialog。
 */
export function popTransition(
  node: Element,
  { duration = 200 }: { duration?: number } = {},
): TransitionConfig {
  if (prefersReducedMotion()) return INSTANT;
  return {
    duration,
    easing: cubicOut,
    css: (t) => `transform: scale(${0.96 + 0.04 * t}); opacity: ${t}`,
  };
}

/**
 * Toast：从右侧滑入 / 滑出 + 淡入/淡出 (§7)。
 * 用 `transition:` 双向，dismiss 时滑出而非凭空消失。
 */
export function toastFly(
  node: Element,
  { distance = 24, duration = 240 }: { distance?: number; duration?: number } = {},
): TransitionConfig {
  if (prefersReducedMotion()) return INSTANT;
  return {
    duration,
    easing: cubicOut,
    css: (t) => `transform: translateX(${(1 - t) * distance}px); opacity: ${t}`,
  };
}

/**
 * 下拉/浮层：从顶部缩放展开（transform-origin: top）+ 淡入 (§12)。
 * 用于 UrlInput 候选下拉等小浮层（导出菜单因 <details> 结构改用 CSS）。
 */
export function menuPop(
  node: Element,
  { duration = 160 }: { duration?: number } = {},
): TransitionConfig {
  if (prefersReducedMotion()) return INSTANT;
  return {
    duration,
    easing: cubicOut,
    css: (t) => `transform: scale(${0.96 + 0.04 * t}); transform-origin: top; opacity: ${t}`,
  };
}
