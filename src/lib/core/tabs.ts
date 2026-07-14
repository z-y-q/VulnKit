// Tab 操作工具
// 面板调用：获取当前标签、在页面执行脚本（MAIN/ISOLATED world）、注入 CSS。

/** 获取当前活跃标签页。 */
export async function getActiveTab(): Promise<Browser.tabs.Tab | null> {
  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  } catch {
    return null;
  }
}

/** 获取当前标签页 URL（http/https），非网页返回 null。 */
export async function getActiveTabUrl(): Promise<string | null> {
  const tab = await getActiveTab();
  if (!tab?.url) return null;
  try {
    const u = new URL(tab.url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return tab.url;
  } catch {
    return null;
  }
}

export interface ExecOptions {
  world?: 'MAIN' | 'ISOLATED';
  args?: any[];
}

/**
 * 在指定标签页执行函数，返回结果。
 * 默认 ISOLATED world（可访问 chrome API）；设 world:'MAIN' 在页面上下文执行。
 */
export async function execInTab<T = any>(
  tabId: number,
  func: (...args: any[]) => T,
  opts: ExecOptions = {},
): Promise<T | null> {
  try {
    const results = await browser.scripting.executeScript({
      target: { tabId },
      func,
      args: opts.args || [],
      world: opts.world || 'ISOLATED',
    } as any);
    if (results && results.length > 0) {
      return (results[0] as any).result as T;
    }
    return null;
  } catch {
    return null;
  }
}

/** 向标签页注入 CSS。 */
export async function insertCss(tabId: number, css: string): Promise<void> {
  try {
    await browser.scripting.insertCSS({ target: { tabId }, css });
  } catch {
    /* ignore */
  }
}
