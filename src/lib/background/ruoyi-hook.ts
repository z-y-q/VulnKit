// 灵眸 v6.0 — 若依路由 Hook（动态注册 MAIN world content script）

const RUOYI_HOOK_CS_ID = 'ruoyi-route-hook-auto';

/** 为指定 origin 注册 MAIN world 注入脚本（document_start）。 */
export async function registerRuoYiHook(origin: string): Promise<void> {
  try {
    await browser.scripting
      .unregisterContentScripts({ ids: [RUOYI_HOOK_CS_ID] })
      .catch(() => {});
    await browser.scripting.registerContentScripts([
      {
        id: RUOYI_HOOK_CS_ID,
        js: ['inject/ruoyi-route-hook.js'],
        matches: [origin + '/*'],
        runAt: 'document_start',
        world: 'MAIN',
      },
    ]);
  } catch (e) {
    console.warn('[灵眸] registerRuoYiHook:', e);
  }
}

export async function unregisterRuoYiHook(): Promise<void> {
  try {
    await browser.scripting.unregisterContentScripts({ ids: [RUOYI_HOOK_CS_ID] });
  } catch {
    /* 未注册时忽略 */
  }
}

/** service worker 启动时恢复已注册的 hook。 */
export async function restoreRuoYiHook(): Promise<void> {
  const result = await browser.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin']);
  if (result.ruoyiHookEnabled && result.ruoyiHookOrigin) {
    await registerRuoYiHook(result.ruoyiHookOrigin as string);
  }
}

/** tab 关闭时清理关联标记（hook 按 origin 持久存在）。 */
export function cleanupRuoYiTabOnClose(tabId: number): void {
  browser.storage.local.get(['ruoyiHookTabId'], result => {
    if (result.ruoyiHookTabId === tabId) {
      browser.storage.local.remove(['ruoyiHookTabId']).catch(() => {});
    }
  });
}
