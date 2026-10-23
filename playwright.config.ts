import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

/**
 * Playwright 配置 — 灵眸 v6 端到端测试
 * 测试范围：Popup 快捷运行、跨面板数据交接、面板加载、任务取消
 *
 * Chrome 扩展测试需要：
 * 1. 加载未打包的扩展（.output/chrome-mv3）
 * 2. 持久化上下文（保留扩展状态）
 * 3. 使用 chromium.launchPersistentContext
 */
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false, // 扩展测试需要串行（共享浏览器实例）
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // 扩展只能单实例
  reporter: [['html', { outputFolder: 'test-results/html' }]],
  timeout: 30 * 1000,

  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium-extension',
      use: {
        ...devices['Desktop Chrome'],
        // 扩展路径在测试中动态加载
      },
    },
  ],
});
