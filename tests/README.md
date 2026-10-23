# 灵眸 v6 — 端到端测试

## 概述

使用 Playwright 对 Chrome 扩展进行端到端测试，覆盖核心用户流程。

## 测试场景

### 1. Popup 快捷运行 (`popup-autorun.spec.ts`)

- 从 Popup 选择面板并输入 URL
- 验证 Side Panel 自动打开并切换到对应面板
- 验证任务自动启动
- 验证历史记录功能
- 验证无效 URL 校验

### 2. 跨面板数据交接 (`panel-handoff.spec.ts`)

- GatherPanel → 漏洞扫描面板数据移交
- analysisContext 在面板间传递
- 数据来源提示显示

### 3. 任务控制 (`task-control.spec.ts`)

- 面板加载与切换
- 任务暂停/恢复
- 任务取消
- 进度显示与阶段标签

## 运行测试

### 前置条件

1. 构建扩展：

```bash
pnpm build
```

构建输出位于 `.output/chrome-mv3/`

2. 安装 Playwright 浏览器（首次运行）：

```bash
pnpm exec playwright install chromium
```

### 运行所有测试

```bash
pnpm test:e2e
```

### 运行单个测试文件

```bash
pnpm exec playwright test tests/e2e/popup-autorun.spec.ts
```

### 调试模式（打开 UI）

```bash
pnpm exec playwright test --ui
```

### 查看测试报告

```bash
pnpm exec playwright show-report test-results/html
```

## 测试架构

```
tests/
├── e2e/                          # 测试用例
│   ├── popup-autorun.spec.ts     # Popup 快捷运行
│   ├── panel-handoff.spec.ts     # 跨面板数据交接
│   └── task-control.spec.ts      # 任务控制
├── helpers/                      # 工具函数
│   └── extension.ts              # 扩展加载/访问工具
└── README.md                     # 本文档
```

## 工具函数

### `extension.ts`

提供扩展测试所需的工具函数：

- `loadExtension(userDataDir?)` — 加载扩展并返回上下文
- `openPopup(ctx)` — 打开扩展 Popup
- `openSidePanel(ctx)` — 打开扩展 Side Panel
- `waitForPanel(page, panelId, timeout?)` — 等待面板切换完成
- `closeExtension(ctx)` — 清理扩展上下文

**示例：**

```typescript
import { loadExtension, openSidePanel, waitForPanel } from '../helpers/extension';

const ctx = await loadExtension();
const page = await openSidePanel(ctx);
await waitForPanel(page, 'gather');
```

## 常见问题

### Q: 测试失败：扩展 Service Worker 未加载

**A:** 确保已运行 `pnpm build` 且 `.output/chrome-mv3/` 存在。检查 `manifest.json` 是否正确。

### Q: 测试超时

**A:** Chrome 扩展测试需要 headless: false（有界面），首次加载较慢。调整 `timeout` 参数：

```typescript
await page.waitForSelector('.selector', { timeout: 10000 });
```

### Q: 如何调试测试？

**A:** 使用 Playwright Inspector：

```bash
PWDEBUG=1 pnpm exec playwright test tests/e2e/popup-autorun.spec.ts
```

或使用 UI 模式：

```bash
pnpm exec playwright test --ui
```

### Q: 测试数据目录在哪？

**A:** 临时用户数据存储在 `tests/.temp/user-data-*`，测试结束后自动清理。持久化测试数据请手动指定 `userDataDir`。

## CI/CD 集成

GitHub Actions 配置示例：

```yaml
- name: Install Playwright browsers
  run: pnpm exec playwright install --with-deps chromium

- name: Build extension
  run: pnpm build

- name: Run E2E tests
  run: pnpm test:e2e

- name: Upload test results
  if: always()
  uses: actions/upload-artifact@v3
  with:
    name: playwright-report
    path: test-results/html
```

## 贡献

添加新测试用例：

1. 在 `tests/e2e/` 创建 `*.spec.ts` 文件
2. 使用 `loadExtension` 加载扩展
3. 编写测试场景
4. 运行 `pnpm test:e2e` 验证

参考现有测试用例获取最佳实践。

---

🎯 **目标：** 确保核心用户流程在每次发布前通过自动化测试验证。
