/**
 * 剪贴板操作
 *
 * 统一各面板裸 `navigator.clipboard.writeText` 调用。
 * 对齐 docs/UX-UI优化建议.md §6.1：Promise 成功后才提示成功；
 * 失败显示原因与 fallback，不静默报成功（修 xss:637 / sourcemap:715 等）。
 */

import { toastStore } from '@/stores/ui';

/**
 * 复制文本到剪贴板。成功才 toast（默认「已复制」），失败 toast 警告。
 * @returns 是否复制成功（供调用方决定后续动作）
 */
export async function copyText(text: string, successMsg = '已复制'): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    toastStore.show(successMsg, 'success');
    return true;
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    toastStore.show(`复制失败：${reason || '剪贴板不可用'}，请手动选择文本`, 'warning');
    return false;
  }
}

/** 复制多行（\n 拼接）。空数组直接警告并返回 false。 */
export async function copyLines(lines: string[], successMsg?: string): Promise<boolean> {
  if (lines.length === 0) {
    toastStore.show('没有可复制的内容', 'warning');
    return false;
  }
  return copyText(lines.join('\n'), successMsg ?? `已复制 ${lines.length} 项`);
}
