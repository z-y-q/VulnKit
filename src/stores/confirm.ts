/**
 * 确认对话框 store（对齐 docs/UX-UI优化建议.md §4.3.7 / §8）
 *
 * Imperative API：`await confirmStore.ask({...})` 返回 Promise<boolean>。
 * 替代浏览器原生 confirm()，由 ConfirmDialog 组件渲染模态。Options 各危险操作调用。
 *
 * 比每调用点 bind open 状态干净：调用方写顺序逻辑（if (!(await ask())) return;），
 * 与原 confirm() 控制流一致，迁移成本低。
 */

import { writable } from 'svelte/store';

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** danger = 红色确认按钮（清空/删除/覆盖等不可逆操作） */
  variant?: 'default' | 'danger';
}

interface ActiveRequest extends ConfirmOptions {
  id: number;
  resolve: (ok: boolean) => void;
}

let _id = 0;
const store = writable<ActiveRequest | null>(null);

/** 发起确认；用户响应后 resolve true/false。同一时刻只保留最后一个请求。 */
function ask(opts: ConfirmOptions): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const id = ++_id;
    store.update((cur) => {
      // 若已有未响应请求，先拒绝旧的（避免泄漏 Promise）
      cur?.resolve(false);
      return { id, ...opts, resolve };
    });
  });
}

/** ConfirmDialog 组件调用：回传用户选择并清空。 */
function respond(ok: boolean): void {
  store.update((cur) => {
    cur?.resolve(ok);
    return null;
  });
}

export const confirmStore = {
  subscribe: store.subscribe,
  ask,
  respond,
};
