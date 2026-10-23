import { test, expect } from '@playwright/test';
import { loadExtension, openPopup, openSidePanel, closeExtension, type ExtensionContext } from '../helpers/extension';
import path from 'node:path';

/**
 * Popup 快捷运行测试 — 灵眸 v6
 *
 * 测试场景：
 * 1. 用户打开 Popup
 * 2. 选择面板（如 Gather）
 * 3. 输入 URL
 * 4. 点击「运行」
 * 5. 验证 Side Panel 自动打开并切换到对应面板
 * 6. 验证任务开始执行
 */

let extCtx: ExtensionContext;

test.beforeAll(async () => {
  // 使用临时用户数据目录（每次测试独立）
  const userDataDir = path.join(__dirname, '../../.temp/user-data-popup');
  extCtx = await loadExtension(userDataDir);
});

test.afterAll(async () => {
  await closeExtension(extCtx);
});

test.describe('Popup 快捷运行', () => {
  test('应该从 Popup 启动 Gather 面板扫描', async () => {
    // 1. 打开 Popup
    const popup = await openPopup(extCtx);

    // 2. 选择 Gather 面板
    await popup.click('[data-panel-id="gather"]');

    // 3. 输入目标 URL
    const urlInput = popup.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://example.com');

    // 4. 点击「运行」按钮
    const runButton = popup.locator('button:has-text("运行")');
    await runButton.click();

    // 5. 验证 Side Panel 打开
    // 注意：Side Panel 可能在新 Tab 或现有 Tab 中打开，取决于扩展实现
    const pages = extCtx.context.pages();
    const sidePanel = pages.find(p => p.url().includes('sidepanel.html'));

    if (!sidePanel) {
      throw new Error('Side Panel 未打开');
    }

    // 6. 验证面板切换到 Gather
    await sidePanel.waitForSelector('[data-panel-id="gather"]', { timeout: 5000 });

    // 7. 验证 URL 已填充
    const sidePanelUrlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await expect(sidePanelUrlInput).toHaveValue('https://example.com');

    // 8. 验证任务状态（运行中或已完成）
    const isRunning = await sidePanel.locator('.task-running, .scan-progress').isVisible({ timeout: 2000 }).catch(() => false);
    const isCompleted = await sidePanel.locator('.task-succeeded, .result-table').isVisible({ timeout: 2000 }).catch(() => false);

    expect(isRunning || isCompleted).toBe(true);

    // 清理
    await popup.close();
    await sidePanel.close();
  });

  test('应该在 Popup 中显示历史记录', async () => {
    const popup = await openPopup(extCtx);

    // 检查是否有历史记录区域
    const historySection = popup.locator('[data-testid="history-section"], .history-list, text=历史记录');
    const hasHistory = await historySection.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasHistory) {
      // 验证历史记录项可点击
      const historyItems = popup.locator('.history-item, [data-history-item]');
      const count = await historyItems.count();

      if (count > 0) {
        // 点击第一个历史记录
        await historyItems.first().click();

        // 验证 URL 自动填充
        const urlInput = popup.locator('input[type="text"][placeholder*="https://"]');
        const urlValue = await urlInput.inputValue();
        expect(urlValue).toBeTruthy();
      }
    }

    await popup.close();
  });

  test('应该在 Popup 中验证无效 URL', async () => {
    const popup = await openPopup(extCtx);

    // 选择任意面板
    await popup.click('[data-panel-id="gather"]');

    // 输入无效 URL
    const urlInput = popup.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('invalid-url');

    // 点击运行
    const runButton = popup.locator('button:has-text("运行")');
    await runButton.click();

    // 验证错误提示
    const errorToast = popup.locator('.toast-error, [role="alert"], text=/无效|错误/');
    await expect(errorToast).toBeVisible({ timeout: 3000 });

    await popup.close();
  });
});
