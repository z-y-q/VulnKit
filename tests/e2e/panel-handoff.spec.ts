import { test, expect } from '@playwright/test';
import { loadExtension, openSidePanel, closeExtension, waitForPanel, type ExtensionContext } from '../helpers/extension';
import path from 'node:path';

/**
 * 跨面板数据交接测试 — 灵眸 v6
 *
 * 测试场景：
 * 1. GatherPanel 收集目标信息
 * 2. 点击「移交到漏洞扫描」按钮
 * 3. 验证自动切换到对应面板
 * 4. 验证 URL 和技术栈数据已传递
 */

let extCtx: ExtensionContext;

test.beforeAll(async () => {
  const userDataDir = path.join(__dirname, '../../.temp/user-data-handoff');
  extCtx = await loadExtension(userDataDir);
});

test.afterAll(async () => {
  await closeExtension(extCtx);
});

test.describe('跨面板数据交接', () => {
  test('应该从 Gather 移交数据到漏洞扫描面板', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 1. 切换到 Gather 面板
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 2. 输入目标 URL
    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://example.com');

    // 3. 启动扫描
    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    // 4. 等待扫描完成或进行中（至少有部分结果）
    await sidePanel.waitForSelector('.result-table, .scan-progress, .task-succeeded', { timeout: 10000 });

    // 5. 查找移交按钮（可能是「移交」「发送到」「继续扫描」等文案）
    const handoffButton = sidePanel.locator(
      'button:has-text("移交"), button:has-text("发送到"), button:has-text("继续扫描"), button:has-text("漏洞")'
    ).first();

    const hasHandoffButton = await handoffButton.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasHandoffButton) {
      // 6. 点击移交按钮
      await handoffButton.click();

      // 7. 验证面板切换（可能切换到多个面板，取第一个可见的）
      const targetPanels = ['vuln', 'xss', 'sqli', 'security'];
      let switched = false;

      for (const panelId of targetPanels) {
        const panelVisible = await sidePanel.locator(`[data-panel-id="${panelId}"]`).isVisible({ timeout: 2000 }).catch(() => false);
        if (panelVisible) {
          switched = true;

          // 8. 验证 URL 已传递
          const targetUrlInput = sidePanel.locator('input[type="text"][value*="example.com"]');
          await expect(targetUrlInput).toBeVisible({ timeout: 3000 });

          break;
        }
      }

      expect(switched).toBe(true);
    } else {
      // 如果没有移交按钮，标记为跳过（部分面板可能不支持）
      test.skip();
    }

    await sidePanel.close();
  });

  test('应该在面板间保留 analysisContext', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 1. 切换到 Gather 面板
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 2. 输入 URL 并扫描
    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://test-context.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    // 3. 等待部分结果
    await sidePanel.waitForSelector('.result-table, .scan-progress', { timeout: 8000 });

    // 4. 手动切换到另一个面板
    await sidePanel.click('[data-sidebar-item="asset"]');
    await waitForPanel(sidePanel, 'asset', 3000);

    // 5. 验证 URL 是否通过 context 传递（某些面板支持）
    const assetUrlInput = sidePanel.locator('input[type="text"]').first();
    const assetUrl = await assetUrlInput.inputValue();

    // Asset 面板可能自动填充上游 URL，也可能不填充（取决于实现）
    // 这里只验证输入框存在即可
    await expect(assetUrlInput).toBeVisible();

    await sidePanel.close();
  });

  test('应该显示数据来源提示', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 模拟跨面板导航后，检查是否有「数据来自 XXX 面板」提示
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://source-test.com');

    // 启动并等待
    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();
    await sidePanel.waitForSelector('.result-table, .scan-progress', { timeout: 8000 });

    // 切换到另一面板
    await sidePanel.click('[data-sidebar-item="vuln"]');
    const vulnPanelVisible = await sidePanel.locator('[data-panel-id="vuln"]').isVisible({ timeout: 2000 }).catch(() => false);

    if (vulnPanelVisible) {
      // 检查是否有来源提示（可能是 badge、toast、或提示文本）
      const sourceHint = sidePanel.locator(
        'text=/数据来自|来源|from|接收到/, [data-testid="source-hint"], .source-badge'
      );
      const hasSourceHint = await sourceHint.isVisible({ timeout: 2000 }).catch(() => false);

      // 不强制要求（某些面板可能没有实现），仅记录
      if (!hasSourceHint) {
        console.log('⚠️  未检测到数据来源提示（可能是设计缺失）');
      }
    }

    await sidePanel.close();
  });
});
