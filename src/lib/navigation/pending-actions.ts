/**
 * Pending Action — Popup / 右键菜单 → Side Panel 的待处理任务（对齐 docs/UX-UI优化建议.md §3.1）。
 *
 * 务实隔离方案（plan 已确认）：pending 带 tabId + 过期时间，side-panel 消费前比对当前
 * active tab.id，不匹配则**不消费**（保留待正确 tab 的 side-panel 消费或过期清理）。
 *
 * - 解决多 tab 串台：每个 tab 的 side-panel 只消费自己的 pending；
 * - 解决「已开 side-panel 消费错误 tab」：不匹配即忽略；
 * - sidePanel.open 失败不再静默：由调用方（popup）展示错误并保留 pending。
 *
 * 局限（已接受）：同 tab 快速连触两个 action → 后者覆盖前者；非原子 claim（单消费者场景竞争极小）。
 */

const STORAGE_KEY = 'pendingAction';
const TTL_MS = 60_000; // 60s 有效期

export interface PendingAction {
  panel: string;
  tabId: number;
  url: string;
  mode: 'open' | 'autorun';
  nonce: number;
  createdAt: number;
  expiresAt: number;
}

/** 写入一条 pending action（自动盖时间戳与过期）。覆盖式单槽。 */
export async function setPendingAction(
  action: Omit<PendingAction, 'createdAt' | 'expiresAt'>,
): Promise<void> {
  const now = Date.now();
  const full: PendingAction = { ...action, createdAt: now, expiresAt: now + TTL_MS };
  await browser.storage.local.set({ [STORAGE_KEY]: full });
}

/** 读取未过期的 pending；过期则清理并返回 null。 */
export async function getPendingAction(): Promise<PendingAction | null> {
  try {
    const data = await browser.storage.local.get(STORAGE_KEY);
    const p = data[STORAGE_KEY] as PendingAction | undefined;
    if (!p || typeof p !== 'object') return null;
    if (Date.now() > p.expiresAt) {
      await browser.storage.local.remove(STORAGE_KEY);
      return null;
    }
    return p;
  } catch {
    return null;
  }
}

/**
 * 仅当 pending.tabId === activeTabId 才消费（删除并返回）；不匹配则保留返回 null。
 * 这是 tab 隔离的核心：错误的 tab 拿不到别人的任务。
 */
export async function claimPendingAction(activeTabId: number): Promise<PendingAction | null> {
  const p = await getPendingAction();
  if (!p) return null;
  if (p.tabId !== activeTabId) return null;
  await browser.storage.local.remove(STORAGE_KEY);
  return p;
}

/** tab 关闭时清理该 tab 的 pending（background 在 tabs.onRemoved 调用）。 */
export async function clearPendingActionForTab(tabId: number): Promise<void> {
  const p = await getPendingAction();
  if (p && p.tabId === tabId) await browser.storage.local.remove(STORAGE_KEY);
}

/**
 * 一次性迁移：清理旧版全局单槽 pendingPanel / pendingAutoRun。
 * 旧 key 无 tabId，与新隔离模型不兼容，直接清除避免幽灵消费。
 */
export async function migrateLegacyPending(): Promise<void> {
  try {
    const data = await browser.storage.local.get(['pendingPanel', 'pendingAutoRun']);
    if (data.pendingPanel || data.pendingAutoRun) {
      await browser.storage.local.remove(['pendingPanel', 'pendingAutoRun']);
    }
  } catch {
    /* ignore */
  }
}

export const PENDING_ACTION_STORAGE_KEY = STORAGE_KEY;
