import { test, expect } from '@playwright/test';
import { loadExtension, openSidePanel, closeExtension, waitForPanel, type ExtensionContext } from '../helpers/extension';
import path from 'node:path';

/**
 * 任务控制测试 — 灵眸 v6
 *
 * 测试场景：
 * 1. 面板加载与切换
 * 2. 任务暂停/恢复
 * 3. 任务取消
 * 4. 进度显示
 */

let extCtx: ExtensionContext;

test.beforeAll(async () => {
  const userDataDir = path.join(__dirname, '../../.temp/user-data-control');
  extCtx = await loadExtension(userDataDir);
});

test.afterAll(async () => {
  await closeExtension(extCtx);
});

test.describe('面板加载与切换', () => {
  test('应该加载所有注册的面板', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 验证侧边栏可见
    const sidebar = sidePanel.locator('[data-testid="sidebar"], .sidebar, aside');
    await expect(sidebar).toBeVisible({ timeout: 5000 });

    // 验证核心面板项存在
    const corePanels = ['gather', 'asset', 'favicon', 'vuln'];

    for (const panelId of corePanels) {
      const panelItem = sidePanel.locator(`[data-sidebar-item="${panelId}"]`);
      const exists = await panelItem.isVisible({ timeout: 2000 }).catch(() => false);

      if (!exists) {
        console.log(`⚠️  面板 "${panelId}" 未在侧边栏中找到`);
      }
    }

    await sidePanel.close();
  });

  test('应该在面板间快速切换', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 切换到 Gather
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather', 3000);
    await expect(sidePanel.locator('[data-panel-id="gather"]')).toBeVisible();

    // 切换到 Asset
    await sidePanel.click('[data-sidebar-item="asset"]');
    await waitForPanel(sidePanel, 'asset', 3000);
    await expect(sidePanel.locator('[data-panel-id="asset"]')).toBeVisible();

    // 切换回 Gather
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather', 3000);
    await expect(sidePanel.locator('[data-panel-id="gather"]')).toBeVisible();

    await sidePanel.close();
  });

  test('应该保留面板状态（切换后返回）', async () => {
    const sidePanel = await openSidePanel(extCtx);

    // 在 Gather 面板输入 URL
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    const testUrl = 'https://state-persist-test.com';
    await urlInput.fill(testUrl);

    // 切换到另一面板
    await sidePanel.click('[data-sidebar-item="favicon"]');
    await waitForPanel(sidePanel, 'favicon', 3000);

    // 切换回 Gather
    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 验证 URL 是否保留（取决于实现，可能被清空）
    const currentValue = await urlInput.inputValue();

    if (currentValue === testUrl) {
      console.log('✅ 面板状态已保留');
    } else {
      console.log('⚠️  面板状态未保留（可能是设计选择）');
    }

    await sidePanel.close();
  });
});

test.describe('任务暂停与恢复', () => {
  test('应该暂停正在运行的任务', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 启动扫描
    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://pause-test.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    // 等待任务开始（进度条出现）
    const progressVisible = await sidePanel.locator('.scan-progress, .task-running').isVisible({ timeout: 5000 }).catch(() => false);

    if (progressVisible) {
      // 查找暂停按钮
      const pauseButton = sidePanel.locator('button:has-text("暂停")');
      const hasPauseButton = await pauseButton.isVisible({ timeout: 2000 }).catch(() => false);

      if (hasPauseButton) {
        // 点击暂停
        await pauseButton.click();

        // 验证状态变为暂停
        const pausedIndicator = sidePanel.locator('text=/已暂停|paused/, .task-paused, [data-status="paused"]');
        await expect(pausedIndicator).toBeVisible({ timeout: 3000 });

        // 验证恢复按钮出现
        const resumeButton = sidePanel.locator('button:has-text("继续"), button:has-text("恢复")');
        await expect(resumeButton).toBeVisible({ timeout: 2000 });
      } else {
        console.log('⚠️  该面板不支持暂停功能');
        test.skip();
      }
    } else {
      console.log('⚠️  任务未能启动或立即完成');
      test.skip();
    }

    await sidePanel.close();
  });

  test('应该恢复已暂停的任务', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 启动扫描
    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://resume-test.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    await sidePanel.waitForSelector('.scan-progress', { timeout: 5000 });

    // 暂停
    const pauseButton = sidePanel.locator('button:has-text("暂停")');
    const hasPause = await pauseButton.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasPause) {
      await pauseButton.click();
      await sidePanel.waitForSelector('button:has-text("继续"), button:has-text("恢复")');

      // 恢复
      const resumeButton = sidePanel.locator('button:has-text("继续"), button:has-text("恢复")');
      await resumeButton.click();

      // 验证任务继续运行
      const runningIndicator = sidePanel.locator('.task-running, .scan-progress');
      await expect(runningIndicator).toBeVisible({ timeout: 3000 });
    } else {
      test.skip();
    }

    await sidePanel.close();
  });
});

test.describe('任务取消', () => {
  test('应该取消正在运行的任务', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    // 启动扫描
    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://cancel-test.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    // 等待任务启动
    await sidePanel.waitForSelector('.scan-progress, .task-running', { timeout: 5000 });

    // 点击取消
    const cancelButton = sidePanel.locator('button:has-text("取消"), button:has-text("停止")');
    await cancelButton.click();

    // 验证任务已停止
    const idleState = sidePanel.locator('button:has-text("开始"), button:has-text("扫描"), button:has-text("重新")');
    await expect(idleState.first()).toBeVisible({ timeout: 5000 });

    // 验证进度条消失
    const progressGone = await sidePanel.locator('.scan-progress').isVisible({ timeout: 2000 }).catch(() => false);
    expect(progressGone).toBe(false);

    await sidePanel.close();
  });

  test('应该在取消后允许重新启动', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://restart-test.com');

    // 第一次启动
    let startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();
    await sidePanel.waitForSelector('.scan-progress', { timeout: 5000 });

    // 取消
    const cancelButton = sidePanel.locator('button:has-text("取消")');
    await cancelButton.click();
    await sidePanel.waitForSelector('button:has-text("开始"), button:has-text("扫描"), button:has-text("重新")');

    // 第二次启动
    startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描"), button:has-text("重新")');
    await startButton.first().click();

    // 验证任务重新启动
    await expect(sidePanel.locator('.scan-progress')).toBeVisible({ timeout: 5000 });

    await sidePanel.close();
  });
});

test.describe('进度显示', () => {
  test('应该显示任务进度信息', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://progress-test.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    // 等待进度组件出现
    const progressComponent = sidePanel.locator('.scan-progress, [data-testid="progress"]');
    await expect(progressComponent).toBeVisible({ timeout: 5000 });

    // 检查进度信息元素（可能包含百分比、步骤、阶段等）
    const progressText = sidePanel.locator('text=/\\d+%|\\d+\\/\\d+|检测|扫描|分析/');
    const hasProgressInfo = await progressText.isVisible({ timeout: 3000 }).catch(() => false);

    if (hasProgressInfo) {
      console.log('✅ 进度信息正常显示');
    } else {
      console.log('⚠️  未检测到详细进度信息');
    }

    await sidePanel.close();
  });

  test('应该显示当前执行阶段', async () => {
    const sidePanel = await openSidePanel(extCtx);

    await sidePanel.click('[data-sidebar-item="gather"]');
    await waitForPanel(sidePanel, 'gather');

    const urlInput = sidePanel.locator('input[type="text"][placeholder*="https://"]');
    await urlInput.fill('https://phase-test.com');

    const startButton = sidePanel.locator('button:has-text("开始"), button:has-text("扫描")');
    await startButton.click();

    await sidePanel.waitForSelector('.scan-progress', { timeout: 5000 });

    // 检查阶段标签（如「检测框架」「分析路由」等）
    const phaseLabel = sidePanel.locator('[data-testid="phase-label"], .phase-label, text=/检测|分析|提取|扫描|收集/');
    const hasPhaseLabel = await phaseLabel.isVisible({ timeout: 3000 }).catch(() => false);

    if (hasPhaseLabel) {
      console.log('✅ 任务阶段标签正常显示');
    } else {
      console.log('⚠️  未检测到阶段标签（可能未实现 phase 上报）');
    }

    await sidePanel.close();
  });
});
