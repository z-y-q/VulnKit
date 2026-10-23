import { chromium, type BrowserContext, type Page } from '@playwright/test';
import path from 'node:path';

/**
 * Playwright 扩展测试工具 — 灵眸 v6
 *
 * Chrome 扩展测试需要：
 * 1. launchPersistentContext（保留扩展状态）
 * 2. 加载未打包的扩展（.output/chrome-mv3）
 * 3. 串行执行（workers: 1，扩展只能单实例）
 */

export interface ExtensionContext {
  context: BrowserContext;
  extensionId: string;
  backgroundPage: Page;
}

/**
 * 加载扩展并返回上下文
 * @param userDataDir - 用户数据目录（用于持久化扩展状态）
 * @returns ExtensionContext
 */
export async function loadExtension(userDataDir?: string): Promise<ExtensionContext> {
  const extensionPath = path.resolve(__dirname, '../../.output/chrome-mv3');

  const context = await chromium.launchPersistentContext(userDataDir || '', {
    headless: false, // 扩展测试需要有界面
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      '--no-sandbox',
    ],
  });

  // 等待 Service Worker 加载
  await context.waitForEvent('serviceworker');

  // 获取扩展 ID
  const backgroundPages = context.serviceWorkers();
  if (backgroundPages.length === 0) {
    throw new Error('扩展 Service Worker 未加载');
  }

  const backgroundPage = backgroundPages[0];
  const extensionId = backgroundPage.url().split('/')[2];

  return { context, extensionId, backgroundPage };
}

/**
 * 打开扩展 Popup
 * @param context - ExtensionContext
 * @returns Popup 页面
 */
export async function openPopup(ctx: ExtensionContext): Promise<Page> {
  const popupUrl = `chrome-extension://${ctx.extensionId}/popup.html`;
  const page = await ctx.context.newPage();
  await page.goto(popupUrl);
  await page.waitForLoadState('domcontentloaded');
  return page;
}

/**
 * 打开扩展 Side Panel
 * @param context - ExtensionContext
 * @returns Side Panel 页面
 */
export async function openSidePanel(ctx: ExtensionContext): Promise<Page> {
  const sidePanelUrl = `chrome-extension://${ctx.extensionId}/sidepanel.html`;
  const page = await ctx.context.newPage();
  await page.goto(sidePanelUrl);
  await page.waitForLoadState('domcontentloaded');
  return page;
}

/**
 * 等待侧边栏面板切换完成
 * @param page - Side Panel 页面
 * @param panelId - 面板 ID（如 'gather', 'asset'）
 * @param timeout - 超时时间（毫秒）
 */
export async function waitForPanel(page: Page, panelId: string, timeout = 5000): Promise<void> {
  await page.waitForSelector(`[data-panel-id="${panelId}"]`, { timeout });
}

/**
 * 清理扩展上下文
 * @param context - ExtensionContext
 */
export async function closeExtension(ctx: ExtensionContext): Promise<void> {
  await ctx.context.close();
}
