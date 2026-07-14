/**
 * 结构化错误模型 — 灵眸 v6.0
 *
 * 对齐 docs/UX-UI优化建议.md §5.4：Toast 不应是错误的唯一载体。
 * ActionableError 携带 code/title/message/cause 与一组恢复动作，
 * 供 ErrorState 组件渲染内联卡片 + 恢复按钮。
 * TaskController 与各面板 catch 后用 toActionableError() 归一化。
 */

export interface ActionableError {
  code: string;
  title: string;
  message: string;
  cause?: string;
  recovery: Array<{
    label: string;
    action: 'retry' | 'open-settings' | 'refresh-page' | 'copy-diagnostics';
  }>;
}

/**
 * 常见错误映射（§5.4 表）。
 * 调用方可直接取 COMMON_ERRORS.CODE 用，或由 toActionableError 按关键字匹配。
 */
export const COMMON_ERRORS: Record<string, ActionableError> = {
  NO_ACTIVE_TAB: {
    code: 'NO_ACTIVE_TAB',
    title: '无法访问当前页面',
    message: '未识别到可操作的浏览器标签页。',
    recovery: [{ label: '切换到普通网页后重试', action: 'refresh-page' }],
  },
  CONTENT_SCRIPT_DISCONNECTED: {
    code: 'CONTENT_SCRIPT_DISCONNECTED',
    title: '页面连接已失效',
    message: '内容脚本未连接，可能是页面刚导航或刷新。',
    recovery: [{ label: '刷新页面并重试', action: 'refresh-page' }],
  },
  API_KEY_MISSING: {
    code: 'API_KEY_MISSING',
    title: '尚未配置 API Key',
    message: '此功能需要先在设置中配置 ZoomEye API Key。',
    recovery: [{ label: '打开设置', action: 'open-settings' }],
  },
  API_QUOTA_EXCEEDED: {
    code: 'API_QUOTA_EXCEEDED',
    title: '今日额度已用尽',
    message: '远程数据 API 请求额度已达上限。',
    recovery: [
      { label: '查看配置', action: 'open-settings' },
      { label: '稍后重试', action: 'retry' },
    ],
  },
  REQUEST_TIMEOUT: {
    code: 'REQUEST_TIMEOUT',
    title: '目标响应超时',
    message: '请求未在限定时间内返回。',
    recovery: [{ label: '重试', action: 'retry' }],
  },
  PERMISSION_DENIED: {
    code: 'PERMISSION_DENIED',
    title: '当前页面不允许此操作',
    message: '浏览器拒绝了对该页面执行此操作。',
    recovery: [{ label: '查看权限说明', action: 'open-settings' }],
  },
  CLIPBOARD_FAILED: {
    code: 'CLIPBOARD_FAILED',
    title: '复制失败',
    message: '浏览器拒绝或暂不可用剪贴板写入。',
    recovery: [{ label: '手动选择文本', action: 'copy-diagnostics' }],
  },
};

const DEFAULT_ERROR: ActionableError = {
  code: 'UNKNOWN',
  title: '发生错误',
  message: '操作未完成。',
  recovery: [
    { label: '重试', action: 'retry' },
    { label: '复制诊断信息', action: 'copy-diagnostics' },
  ],
};

function looksLikeActionableError(e: unknown): e is ActionableError {
  return (
    !!e &&
    typeof e === 'object' &&
    typeof (e as any).code === 'string' &&
    typeof (e as any).title === 'string' &&
    Array.isArray((e as any).recovery)
  );
}

/**
 * 把 catch 到的任意值归一化为 ActionableError。
 * - 已是 ActionableError → 原样返回（保留 cause）
 * - Error → 按 message/name 关键字匹配常见错误，否则 DEFAULT + cause
 * - 非空字符串 → 当 message
 * - 其他 → DEFAULT_ERROR
 */
export function toActionableError(e: unknown): ActionableError {
  if (looksLikeActionableError(e)) return e;

  if (e instanceof Error) {
    const msg = e.message || String(e);
    const lower = `${e.name} ${msg}`.toLowerCase();
    if (/timeout|超时/.test(lower)) {
      return { ...COMMON_ERRORS.REQUEST_TIMEOUT, cause: msg };
    }
    if (/clipboard|剪贴板/.test(lower)) {
      return { ...COMMON_ERRORS.CLIPBOARD_FAILED, cause: msg };
    }
    const cause = e.stack ? e.stack.split('\n').slice(0, 2).join('\n').trim() : undefined;
    return { ...DEFAULT_ERROR, message: msg, cause };
  }

  if (typeof e === 'string' && e.trim()) {
    return { ...DEFAULT_ERROR, message: e };
  }

  return { ...DEFAULT_ERROR };
}
