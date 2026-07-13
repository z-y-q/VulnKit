# 灵眸浏览器插件 UX/UI 优化建议书

> 文档版本：v1.0  
> 分析日期：2026-07-13  
> 对应项目版本：7.2.0  
> 技术栈：WXT 0.20.x + Svelte 5 + TypeScript 5.9 + UnoCSS  
> 文档用途：交付给后续产品、视觉设计、交互设计与前端开发人员，作为 UX/UI 优化实施依据。  
> 分析边界：仅审计当前本地插件代码和界面实现，未执行任何外部安全测试。

---

## 1. 执行摘要

灵眸目前已具备完整的浏览器安全工具产品形态：Popup 负责快速启动，Side Panel 承载 35 个主要工具面板，Options 管理密钥、规则、扫描参数、布局、备份和存储，History/Report 负责结果沉淀。现有界面已经建立了按钮、卡片、输入框、徽章等 UnoCSS 快捷类，也完成了面板动态加载和用户自定义排序，功能覆盖度很高。

当前的主要问题不是“界面不好看”，而是**高密度功能缺少统一的任务模型和导航模型**。用户能找到很多工具，却无法始终清楚地知道：

1. 当前操作是否真正开始；
2. 正在执行哪个阶段、还要多久；
3. 能否暂停、取消或重试；
4. 当前看到和导出的是否是同一批结果；
5. 一项发现如何继续交给另一个工具分析；
6. Popup、Side Panel、Options 是否共享同一状态和视觉语言。

建议优化目标不是一次性重做全部 35 个面板，而是先建立一套共享的产品骨架：

- **导航骨架**：搜索、最近使用、收藏、分类、有效面板校验、窄宽折叠；
- **任务骨架**：输入 → 校验 → 运行 → 进度 → 取消 → 完成/失败/部分结果；
- **结果骨架**：统计 → 搜索/筛选/排序 → 详情 → 复制/导出 → 历史/跨面板交接；
- **反馈骨架**：LoadingState、EmptyState、ErrorState、Toast、ConfirmDialog；
- **设计系统**：语义颜色、字号、间距、控件高度、焦点、暗色主题和响应式规则。

### 1.1 最高优先级结论

| 优先级 | 主题 | 用户影响 |
|---|---|---|
| P0 | Popup→Side Panel 的 pending 状态按 tab 隔离，并补齐失败反馈 | 防止多标签页串台、点击后无反应、自动扫描目标错误 |
| P0 | 当前面板必须来自“可见且有效”的统一列表 | 防止进入已隐藏面板、初始面板与用户设置冲突 |
| P0 | 动态加载提供真实重试；长任务统一进度、取消和部分结果语义 | 防止“请重试但无按钮”、取消后仍显示成功 |
| P0 | 修复报告严重度筛选与导出内容不一致 | 防止用户导出超出当前筛选范围的数据 |
| P1 | 建立导航搜索、最近使用和收藏，支持窄宽折叠 | 35 个工具下显著降低查找成本 |
| P1 | 统一 ResultToolbar、ErrorState、复制/导出和详情抽屉 | 降低面板间学习成本，提升错误恢复能力 |
| P1 | Options 改为分区导航和统一保存状态 | 减少长单页滚动、遗漏保存和配置认知负担 |
| P1 | 统一版本、主题和语义设计令牌 | 消除 v6.0/v7.0/v7.2 与入口视觉割裂 |
| P2 | 全量键盘、ARIA、对比度、焦点和 reduced motion 整改 | 提升可访问性并消除现有 43 条检查警告 |
| P2 | 建立跨面板上下文交接和任务中心 | 从“工具集合”升级为连续分析工作台 |

---

## 2. 当前产品结构与用户路径

## 2.1 产品入口

```text
Chrome 扩展图标
  └─ Popup（320px 快速启动器）
      ├─ 一键操作：CORS / 安全头 / 子域名 / 嗅探 / WAF / 链接
      ├─ 分类 + 分页工具网格
      └─ 写入 pendingPanel / pendingAutoRun
            ↓
Side Panel
  ├─ 顶栏：品牌 / 版本 / 主题 / 设置
  ├─ Sidebar：6 分类、35 个工具、Alt+1~8
  ├─ PanelHeader：当前工具与分类
  ├─ 动态加载的工具面板
  ├─ StatusBar
  └─ Toast
            ↓
Options
  ├─ API Key
  ├─ HaE YAML
  ├─ 面板排序与隐藏
  ├─ 扫描参数
  ├─ 工具默认值与采集过滤
  ├─ 远程 Payload
  ├─ 数据备份/恢复
  ├─ 历史与存储管理
  └─ 主题与关于
```

运行能力由 Background、Content Bridge 和 MAIN world 注入脚本提供：

```text
Panel → runtime message → Background → 网络代理/探测/DNR/右键/Hook
Panel → content bridge → MAIN world inject → 页面 DOM/框架/存储数据
```

关键代码：

- `src/entrypoints/popup/App.svelte:48-77`
- `src/entrypoints/side-panel/App.svelte:24-51,83-153`
- `src/components/layout/Sidebar.svelte:20-102`
- `src/entrypoints/options/App.svelte:24-339`
- `src/panels/registry.ts:16-63`
- `src/panels/loaders.ts:9-60`

## 2.2 典型任务流

### 流程 A：当前页面一键检测

```text
点击扩展 → Popup 一键操作 → 写入目标面板与 URL
→ 打开当前 tab 的 Side Panel → 消费 pending 状态
→ 切换目标面板 → 面板自动运行 → 展示结果
→ 写入扫描历史 → History / Report 汇总
```

断点：Popup 在 tab 不可用、URL 不支持、Side Panel 打开失败或自动运行失败时几乎没有反馈；`pendingPanel` 是全局单槽且不包含 `tabId`。

### 流程 B：手动选择工具

```text
Popup 分类/分页选择，或 Sidebar 选择
→ currentPanel.load()
→ 面板挂载 → 输入目标 → 运行 → 查看/复制/导出
```

断点：35 个工具依赖分类浏览和记忆；无搜索、最近、收藏；动态加载失败只有“请重试”文字，没有重试控件。

### 流程 C：配置插件

```text
Side Panel 设置按钮 → Options 长单页
→ 找到配置区 → 修改并保存 → storage/store 同步
→ 返回 Side Panel 验证生效
```

断点：页面很长、无左侧目录或锚点；不同分区有即时保存、显式保存和重置三种模式，但缺少统一说明；危险操作大量使用原生 `confirm()`。

### 流程 D：从发现继续分析

```text
某面板发现 URL/域名/脚本/风险
→ 手动复制
→ 切换另一个面板
→ 再粘贴或重新获取当前页
```

断点：跨面板基本依赖复制粘贴或新开标签。缺少“在安全头/CORS/XSS/源码加载中打开”“设为目标”“加入报告”等上下文交接。

---

## 3. 关键体验问题详述

## 3.1 P0：跨入口状态可能串台，失败被吞掉

### 现状

Popup 把 `pendingPanel` 和 `pendingAutoRun` 写入 `storage.local`，Side Panel 再读取并删除：

- `src/entrypoints/popup/App.svelte:56-76`
- `src/entrypoints/side-panel/App.svelte:24-51`

该状态没有绑定 `tabId`，还是一个全局单槽。用户快速在多个窗口或标签页操作时，后一次写入可能覆盖前一次，已经打开的 Side Panel 也可能消费不属于本 tab 的任务。`quickAction()` 对 `sidePanel.open()` 的异常直接忽略。

### 建议

定义明确的 pending schema。推荐由 Background 按 tab 管理任务队列，而不是继续把单个全局对象直接放在 `storage.local`：

```ts
interface PendingAction {
  id: string;
  tabId: number;
  panelId: string;
  url: string;
  mode: 'open' | 'autorun';
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'consumed' | 'failed';
}
```

实施要求：

1. Popup 先校验 active tab、协议和 URL；不支持时留在 Popup 展示错误，不立即关闭。
2. Popup 将 action 和目标 `tabId` 发送给 Background，由 Background 维护 `tabId → queue`；Side Panel 通过 Background 查询它所关联目标 tab 的待处理任务。
3. Background 提供 `claim → acknowledged/failed` 状态转移，负责单消费者认领；不要依赖 `storage.local` 的非原子“读取后删除”模拟锁。
4. Side Panel 只认领与当前目标 tab 匹配且未过期的 action；需要为 Side Panel 如何取得目标 tab 上下文建立明确的 runtime 消息接口。
5. 打开失败时显示内联错误和“重试打开”按钮。
6. 自动运行超时或失败时保留目标 URL，并提供“手动运行”。
7. action 设置 30-60 秒有效期，Background 在启动、tab 关闭和导航时清理；重复 action 通过唯一 id 保证幂等。
8. 如果短期仍使用 storage，至少改为按 tabId 键控的队列，并接受它无法提供严格原子 claim 的限制。

### 验收

- 同时在两个 tab 点击不同快捷操作，各自只运行自己的任务。
- 同一 tab 快速连续触发两个 action 时按队列顺序执行或明确覆盖，且不会重复消费。
- Side Panel 已打开与未打开两种情况下，claim/ack 行为一致。
- `chrome://`、空 tab、无权限页面不会静默关闭 Popup。
- Side Panel 打开失败后用户能看到原因并重试。
- 任务失败后目标 URL 不丢失。

## 3.2 P0：隐藏面板仍可能成为当前面板

### 现状

Side Panel 的快捷键使用可见列表，但 `currentPanel` 来自全量 `panels`；pending 也只校验全量 panels：

- `src/entrypoints/side-panel/App.svelte:16-20,26-30`
- `src/stores/ui.ts:11-40`（初始面板固定为 encoding）
- `src/components/layout/Sidebar.svelte:6-8`

如果用户隐藏了 encoding，首次进入仍可能显示它；隐藏面板也可能被 pending 直接打开。Options 文案还写着“隐藏后仍可通过快捷方式访问”，与“隐藏”的用户预期不清晰。

### 建议

建立唯一的 `visiblePanels` / `resolveActivePanel()`：

1. 当前面板必须存在于应用布局后的可见列表。
2. 初次启动优先恢复“最近有效面板”；无效时选择第一个可见面板。
3. 用户隐藏当前面板后，立即切换到同分类下一个可见面板或全局第一个。
4. 明确定义“隐藏”：建议所有普通入口均不可访问；如需要保留深链访问，改名为“从导航隐藏（仍可通过快捷入口访问）”。
5. pending 指向隐藏面板时，显示确认或回退，而不是悄悄打开。

### 验收

- 隐藏默认面板并重启后，不再进入隐藏面板。
- 排序、Sidebar、Popup、Alt+1~8 和最近使用采用同一列表。
- 所有面板都隐藏时显示可恢复空态和“前往设置恢复”。

## 3.3 P0：动态加载错误没有真实恢复路径

### 现状

`src/entrypoints/side-panel/App.svelte:120-131` 的加载状态只有一行 `加载中…`；catch 只显示“面板加载失败，请重试”，但没有按钮、错误编号或恢复建议。

### 建议

新增共享组件：

- `PanelLoadingState`：保留 PanelHeader，显示 2-3 行 skeleton、工具名和“正在加载”；
- `PanelErrorState`：错误摘要、错误编号、重试按钮、复制诊断、返回上一个面板；
- 重试通过独立 `loadNonce` 或显式 loader 状态触发，不依赖刷新整个扩展；
- loader 缓存失败时允许清除失败缓存后重新 import；
- 状态容器使用 `role="status"` / `role="alert"`，加载完成后把焦点移到面板主标题或主要输入。

### 验收

- 模拟 chunk 加载失败，键盘可以聚焦并执行重试。
- 重试不丢失当前工具和已保存目标上下文。
- 读屏能收到“加载中/失败/已加载”。

## 3.4 P0：长任务缺少统一状态机

### 现状

35 个面板中，UrlInput 仅 11 个、ScanProgress 仅 7 个、FilterBar 仅 6 个面板复用。JS 归档单独实现了相对完整的状态机，而 Fuzz、Vue、Multiurl 等采用不同的暂停、布尔值或计时器语义。

共享组件本身也表达力不足：

- `UrlInput.svelte:20-24`：无 Enter 提交、即时校验、错误关联和取消；
- `ScanProgress.svelte:10-22`：`total=0` 只能显示 0%，无 indeterminate、阶段、耗时、失败数、取消状态；
- `FuzzPanel.svelte:174-200`：取消后仍会完成结果整理；当前取消分支不会写入历史，但缺少统一的 `cancelled/partial` 结果模型；
- `MultiurlPanel.svelte:45-69`：批量开标签无取消和逐项错误统计；
- `JsArchivePanel.svelte:39-60,282-323`：已有可借鉴的明确阶段。

### 建议：统一 TaskRunner / ScanShell

状态模型：

```text
idle
→ validating
→ running ↔ paused
→ succeeded
→ partial
→ cancelled
→ failed
```

标准字段：

```ts
interface TaskState {
  status: TaskStatus;
  phase: string;
  completed: number;
  total?: number;
  succeeded: number;
  failed: number;
  skipped: number;
  startedAt?: number;
  elapsedMs: number;
  canPause: boolean;
  canCancel: boolean;
  error?: ActionableError;
}
```

交互规则：

1. 输入可按 Enter 提交；运行时 Enter 不重复派发。
2. 不知道总量时显示 indeterminate 进度和阶段，不显示 `0/0`。
3. 取消必须停止继续派发；已完成结果可保留，但标记为“部分结果”。
4. cancelled 不能复用 success 文案，也不默认写入完整历史。
5. 失败保留输入、过滤条件和已完成结果，提供重试失败项/重跑全部。
6. 所有长任务显示耗时；超过预期时给出“仍在等待目标响应”。
7. 任务切换面板时可选择后台继续，或明确提示切换会终止。

### 首批试点

1. JS Archive：作为状态机基准；
2. Fuzz：验证暂停/取消/部分结果；
3. XSS：验证大量任务、参数和历史；
4. SourceMap：验证多阶段任务；
5. Multiurl：验证逐项成功/失败和取消。

## 3.5 P0：报告筛选和导出范围不一致

### 现状

`src/panels/report/ReportPanel.svelte:36-54` 中严重度筛选仅生成 `severityFiltered`；列表聚合和 `exportCsv/Json/Markdown/Html` 仍使用 `filteredEntries`（`73-107`）。用户选择“高危”后，界面意图是只看高危，但导出可能仍包含其他级别。

### 建议

建立单一 `ReportQuery`：

```ts
interface ReportQuery {
  domains: string[];
  severities: ScanSeverity[];
  modules: string[];
  keyword: string;
  range?: { from: number; to: number };
}
```

展示、统计、结果数量和默认导出全部使用同一个 query 结果。另提供明确分离的：

- `导出当前筛选（12）`
- `导出全部记录（138）`

### 验收

- 选中“高危”后，列表、计数、CSV/JSON/MD/HTML 内容完全一致。
- 按钮显示实际导出数量。
- 全量审计明确标为“忽略当前筛选”，并在确认区域说明范围。

---

## 4. 信息架构与导航优化

## 4.1 Sidebar 从分类列表升级为工具导航

### 当前问题

- 固定宽度 `w-44`（176px），窄 Side Panel 下主内容被严重压缩：`Sidebar.svelte:47`；
- 35 个工具依赖滚动和分类记忆；
- 分类折叠只存内存，重启丢失：`Sidebar.svelte:31-36`；
- 快捷数字、图标、文本和 sniff badge 竞争有限宽度：`Sidebar.svelte:69-95`；
- 缺少搜索、最近、收藏和“正在运行”状态。

### 建议布局

```text
[搜索工具 / ⌘K]
[最近] [收藏]
────────────
侦察（4）  ▾
  图标识别
  信息收集       ●运行中
  ...
扫描（11） ▾
  ...
────────────
[折叠侧栏]
```

具体规则：

1. 搜索同时匹配名称、别名、分类和能力关键词，如“header/响应头/安全头”。
2. 最近使用保留 5-8 项；收藏由用户显式维护。
3. 分类显示可见数量，折叠状态持久化到本地。
4. 面板有运行任务时显示状态点、进度或错误点。
5. 小于 520px 时默认折叠为 48-56px 图标栏；小于 400px 时允许抽屉式导航。
6. 折叠态必须保留可访问名称和 focus tooltip，不能只依赖 emoji。
7. Alt+1~8 对应最近/固定快捷位，而不是排序变化后含义不断漂移；或者在设置中明确“按当前可见顺序”。

## 4.2 Popup 重新聚焦“快速行动”

### 当前问题

Popup 同时承担分类浏览、分页工具网格和一键操作，320px 内信息密度较高：`popup/App.svelte:112-177`。16 项分页使用户需要记忆工具在哪一页；页面只有亮色 CSS，与 Side Panel 主题不一致；版本硬编码 v7.0。

### 推荐结构

```text
灵眸 v7.2             [设置]
当前页：example.com
[搜索工具…]

常用操作
[CORS] [安全头] [嗅探]
[链接] [WAF]   [更多]

最近使用
[信息收集] [JS归档] [报告]

[打开完整工具面板]
```

建议：

1. Popup 默认只展示 6 个可配置快捷操作 + 4 个最近使用。
2. 搜索替代“全部分类下分页 16 项”的主要发现方式。
3. 分类工具浏览可放到“全部工具”二级视图。
4. 展示当前 tab 域名和可执行状态；不支持页面直接禁用并说明。
5. 点击后保持 Popup 到收到 `sidePanel.open` 成功；失败不关闭。
6. 使用与 Side Panel 相同的主题和语义 token。
7. 版本从 manifest 动态读取。

## 4.3 Options 改为可定位、可理解的配置中心

### 当前问题

`options/App.svelte` 是长单页，包含至少 9 类配置。不同区块的保存模式不一致；危险操作大量使用浏览器原生 confirm；面板排序仍是上下箭头，不适合 35 项长列表。

### 推荐桌面布局

```text
设置
├─ 常规
├─ 扫描与限流
├─ API 与远程数据
├─ HaE 规则
├─ 工具与导航
├─ 历史与存储
├─ 备份与恢复
└─ 关于

右侧：当前分区内容
底部：保存状态 / 未保存修改 / 保存 / 撤销
```

实施细则：

1. 左侧目录使用锚点或路由，支持 URL hash 深链。
2. 每个区块顶部说明“自动保存”或“修改后需保存”。
3. 全局显示 `已保存`、`正在保存`、`保存失败`、`有未保存修改`。
4. 离开有未保存 YAML/文本编辑时提示。
5. 面板排序支持拖拽和键盘“上移/下移”，并提供分类内排序。
6. API Key 增加显示/隐藏、连接验证、最后验证时间和错误 CTA。
7. 危险操作使用统一 ConfirmDialog，默认焦点在“取消”，清楚说明影响范围。
8. 清空数据、恢复备份前显示将受影响的数据类别和数量。
9. 备份默认对 API Key、Token 等敏感字段提供“包含/排除敏感配置”选项。

---

## 5. 面板统一交互规范

## 5.1 标准页面骨架

所有需要输入并运行的面板建议遵循以下顺序：

```text
1. Target / Input
2. Advanced options（默认折叠）
3. Run controls
4. Task status / progress
5. Result summary
6. ResultToolbar（搜索/筛选/排序/数量）
7. Result list/table
8. DetailDrawer
9. Copy / Export / History / Handoff
```

### 输入区

- 明确可见 label，不用 placeholder 替代 label；
- URL 输入提供协议补全、即时校验和错误说明；
- Enter 提交，Escape 清除错误或关闭高级项；
- 默认读取当前 tab，但明确标注“来源：当前页面”；
- 保留上次输入或最近目标；
- 高风险/高请求量设置显示预估请求数。

### 运行区

- 主要按钮使用动词 + 对象：`扫描 URL`、`分析脚本`，避免泛化的“开始”；
- 运行后主要按钮变为暂停/取消，而不是仅 disabled；
- 防止重复运行；
- 状态区显示阶段、进度、成功/失败/跳过、耗时；
- 网络等待和处理阶段分开表达。

### 结果区

- 将“未运行”“运行中无结果”“完成但无发现”“筛选后无结果”“加载失败”设计为五种不同状态；
- 默认展示最重要发现，并允许展开证据；
- 表格在窄宽下切换为卡片列表；
- 行点击区域与行内操作按钮分离，避免嵌套交互控件；
- URL、证据和原始响应可单独复制。

## 5.2 ResultToolbar

建议统一：

```text
发现 138 · 当前显示 12
[搜索…] [严重度▼] [状态▼] [排序▼] [清除筛选]
[复制当前 12] [导出▼]
```

接口建议：

```ts
interface ResultQuery {
  search: string;
  severities: string[];
  statuses: string[];
  sort: { key: string; direction: 'asc' | 'desc' };
}
```

规则：

- 筛选按钮使用 `aria-pressed` 或真实 checkbox/radio；
- active 不只靠颜色，还需选中图标或文字；
- “复制/导出”默认作用于当前筛选集，并显示数量；
- 清除筛选在有筛选时才出现；
- 结果数较大时提供分页或虚拟滚动。

## 5.3 DetailDrawer

用于替代各面板零散的展开卡片和 modal：

- 标题、严重度、来源模块、目标；
- 发现描述、证据、原始响应摘要；
- 关联 URL/参数/脚本；
- 复制单字段、复制全部；
- `在 XSS 中打开`、`在安全头中检测`、`设为目标`、`加入报告`；
- 上一条/下一条；
- Escape 关闭，关闭后焦点回到原结果行。

## 5.4 错误模型与恢复

Toast 只适合短暂确认，不应是错误的唯一载体。建议结构化错误：

```ts
interface ActionableError {
  code: string;
  title: string;
  message: string;
  cause?: string;
  recovery: Array<{
    label: string;
    action: 'retry' | 'open-settings' | 'refresh-page' | 'copy-diagnostics';
  }>;
}
```

常见映射：

| 错误 | 用户文案 | 恢复动作 |
|---|---|---|
| 无当前 tab | 无法访问当前页面 | 切换到普通网页 |
| content script 未连接 | 页面连接已失效 | 刷新页面并重试 |
| API Key 缺失 | 尚未配置 ZoomEye API Key | 打开设置 |
| API 限额 | 今日额度已用尽 | 查看配置/稍后重试 |
| 请求超时 | 目标响应超时 | 重试/增加超时 |
| 权限拒绝 | 当前页面不允许此操作 | 查看权限说明 |
| 复制失败 | 浏览器拒绝剪贴板访问 | 手动选择文本/重试 |

---

## 6. 复制、导出、历史和跨面板协同

## 6.1 统一复制与导出

当前多个面板直接调用 `navigator.clipboard.writeText` 或手动创建 Blob，部分调用未 await/catch，可能在权限拒绝时仍显示成功。例如：

- `src/panels/leakscan/LeakscanPanel.svelte:132-161`
- `src/panels/cors/CorsPanel.svelte:220-266`
- `src/panels/fuzz/FuzzPanel.svelte:244-292`
- `src/entrypoints/extracted-links/App.svelte:153`

建议组件/服务：

- `ClipboardAction`
- `ExportMenu`
- `downloadFile()`
- serializer adapters：JSON / CSV / Markdown / HTML / text

统一规则：

1. Promise 成功后才能提示成功。
2. 失败显示原因和 fallback。
3. 导出默认当前筛选结果。
4. 文件名：`lingmou-{module}-{yyyy-mm-dd}.{ext}`。
5. `URL.revokeObjectURL` 在 finally 或安全延迟后执行。
6. 空结果时禁用按钮并解释。
7. 导出敏感数据前显示范围与脱敏选项。

## 6.2 History 数据层和体验

`HistoryPanel.svelte:59-73` 删除单条直接操作 `pentest_scan_history`，绕过 store；`123-168` 将整行设为 button 又嵌入删除按钮，语义冲突。

建议：

- `scanHistoryStore.deleteEntry(id)` 作为唯一删除入口；
- `HistoryPanel.svelte:123-168` 当前以可聚焦的 `div[role="button"]` 实现整行展开，内部又嵌入“域名清空”和删除按钮；应改为独立的真实展开 button 与右侧操作区；
- 历史项显示任务状态：complete / partial / cancelled / failed；
- 记录当时 query、耗时、请求统计和来源 tab；
- 详情支持复制、导出和回到源面板；
- 提供按时间、域名、模块、严重度、状态筛选；
- 删除单条与清空域名分离，不放在同一整行点击区；
- 支持多选批量删除/导出。

## 6.3 跨面板上下文

新增轻量 `analysisContextStore`：

```ts
interface AnalysisContext {
  sourcePanel: string;
  tabId?: number;
  targetUrl?: string;
  domain?: string;
  scriptUrl?: string;
  findingIds?: string[];
  evidence?: string;
  createdAt: number;
}
```

推荐入口：

- URL → CORS / Headers / XSS / Redirect / Source Loader；
- JS URL → Source Loader / JS Archive / Leak Scan；
- Domain → Subdomain / Asset / History；
- Finding → Report / History；
- 当前筛选集 → 批量开标签或批量分析。

切换面板后，顶部显示来源：`来自 信息收集 · 12 个 URL`，用户可接受、清除或返回。

---

## 7. 视觉设计系统优化

## 7.1 当前基础

`uno.config.ts:17-45` 已定义 btn、card、input、badge 和 panel-label，是良好基础；但只有 primary/danger/warning/success 四个颜色 token，实际面板大量直接写 gray/red/yellow/blue 和透明度。`card` 自带 `p-3.5`，许多使用处又写 `card p-2/p-3/p-4`，形成覆盖式间距。

## 7.2 建议设计令牌

### 颜色

```text
surface.canvas
surface.panel
surface.raised
surface.sunken
text.primary
text.secondary
text.muted
border.default
border.strong
focus.ring
accent.primary
status.info / success / warning / danger / critical
```

要求：

- 组件只使用语义 token，不直接绑定业务色；
- 分类色只作为小面积辅助，不直接用于低对比正文；
- 状态色同时有图标/文字，不能只靠颜色；
- 暗色主题单独校验，不用简单透明叠加推测对比度。

### 字号

当前大量使用 9-11px 辅助文字。建议最小正文 12px，核心正文 13-14px：

| 用途 | 建议 |
|---|---|
| 页面标题 | 16-18px / 600-700 |
| 区块标题 | 14px / 600 |
| 正文/控件 | 13px / 400-500 |
| 辅助信息 | 12px / 400 |
| 极少量标签 | 11px / 600，仅高对比 |

不要用 9-10px 承载关键快捷键、状态或版本之外的信息。

### 间距与尺寸

采用 4px 基础网格：

- 控件高度：32px（紧凑）/ 36px（标准）；
- 图标按钮点击区不小于 32×32px；
- 卡片内边距：12px 或 16px，不在使用处覆盖基础 card padding；
- 面板纵向间距：12px；
- 圆角：输入 8px，卡片 10-12px，徽章 full；
- 表格行高至少 32px。

## 7.3 减少玻璃效果和无意义动效

当前 Header、Sidebar、StatusBar、Toast 等广泛使用 blur/glass。Side Panel 面积小，过多透明与模糊会降低信息清晰度并增加渲染成本。

建议：

- 仅顶栏或浮层使用轻量玻璃效果；
- 主内容卡片使用实体 surface；
- hover scale 仅用于少量图标/启动器，不用于高密度表格和 Toast；
- 切换面板采用 120-180ms opacity，不做明显位移；
- `prefers-reduced-motion` 覆盖 Uno 的 transition、pulse、scale，不只覆盖 `.vk-*`。

## 7.4 表格和窄宽策略

Asset、JS Archive、WAF 等 5-7 列表格在固定 176px Sidebar 下容易横向溢出。建议：

- `>= 720px`：完整表格；
- `480-719px`：隐藏低优先级列，详情抽屉查看；
- `< 480px`：卡片列表；
- 表格设置明确 min-width、table-layout 和 sticky header 背景/z-index；
- 允许用户选择列；
- 长 URL 不只 truncate，提供 tooltip、复制与详情。

## 7.5 统一多入口样式加载策略

当前只有 `src/entrypoints/side-panel/main.ts:3-4` 显式引入 `virtual:uno.css` 和 Side Panel 全局样式；Popup 采用独立 scoped CSS，Options 与 Extracted Links 入口也未建立一致的共享样式导入。这会带来两个问题：一是三入口视觉语言持续漂移；二是共享组件被复用到其他入口时，`btn`、`card`、`input` 等 Uno shortcut 可能没有对应样式。

建议：

1. 抽取不依赖页面布局的 `src/styles/shared.css`，包含 reset、字体、focus-visible、语义 CSS 变量、表单基础和 reduced-motion；
2. 所有可视入口显式导入 `virtual:uno.css` 和 `shared.css`；
3. Side Panel 专属的高度、overflow、Sidebar 和动画留在自己的 `app.css`；
4. Popup 可保留紧凑布局 CSS，但颜色、字体、焦点、按钮状态改用共享 token；
5. 为每个入口增加最小视觉 smoke test，防止某入口忘记导入样式。

## 7.6 版本来源必须覆盖 UI 与导出物

当前版本漂移不仅存在于 Popup：

- `src/entrypoints/popup/App.svelte:118`：`v7.0`；
- `src/components/layout/StatusBar.svelte:19`：`v6.0`；
- `src/entrypoints/options/App.svelte:347,645`：`v6.0`；
- `src/lib/report/report-builder.ts:181`：报告元数据仍写入 `6.0.0`；
- Side Panel 顶栏则从 manifest 动态读取当前版本。

建议建立集中 `getAppVersion()` 或构建时常量：可视入口优先读取 `browser.runtime.getManifest().version`，报告构建器通过参数接收同一版本。代码注释不应保留“灵眸 v6.0”一类易过时标记。验收时同时检查 Popup、Side Panel、Options、Extracted Links、下载报告元数据和 About 区域。

## 7.7 备份默认排除敏感配置

`src/entrypoints/options/App.svelte:143-155` 当前通过 `browser.storage.local.get(null)` 无条件导出全部本地存储，其中可能包括 ZoomEye API Key、历史、pending 状态和其他敏感配置。这既是安全问题，也是用户无法理解导出范围的高风险 UX 问题，建议列为 P1：

1. 默认排除 API Key、Token、Cookie、临时 pending action 等敏感或短生命周期字段；
2. 导出前列出数据类别、条数、大小及是否包含敏感配置；
3. 用户主动选择包含密钥时进行二次确认，并明确备份文件为明文；
4. 导入时对敏感字段单独确认，默认不覆盖本机现有密钥；
5. 维护明确的字段分类和备份 schema version，而不是直接导入任意 storage 对象；
6. 验收：默认备份文件不含 API Key，除非用户明确确认，导入也不会静默覆盖密钥。

---

## 8. 可访问性优化

当前 `pnpm check` 结果为 **0 errors、43 warnings、12 个问题文件**，主要是缺失 label、可点击非交互元素和旧式 ignore。代码搜索显示 ARIA/role/tabindex/focus 语义只覆盖少量文件。

## 8.1 优先级分层

可访问性不能全部推迟到 P2，应分层处理：

- **P0/P1 核心流程阻断项**：Toast 可关闭、UrlInput label、ScanProgress 语义、Dialog 焦点、Popup/Sidebar 键盘路径；
- **P1 共享组件项**：FilterBar、ErrorState、ResultToolbar、Sidebar 当前/折叠状态；
- **P2 全量治理**：剩余 warning、全主题对比度、forced-colors、reduced-motion 和视觉回归。

## 8.2 全局要求

1. 所有交互元素使用 button、a、input、details 等原生语义；
2. icon-only button 必须有 `aria-label`；
3. 全部按钮补 `type="button"`，防止未来嵌入 form 后误提交；
4. 全局建立明显的 `:focus-visible`；
5. 文本和状态对比度达到 WCAG AA；
6. 动态结果区使用适当 `aria-live`，不抢焦点；
7. modal 实现标题关联、焦点移入、焦点陷阱、Escape、关闭后恢复焦点；
8. 选中筛选使用 `aria-pressed`；
9. 导航当前项使用 `aria-current="page"`；
10. 折叠分类使用 `aria-expanded` 和 `aria-controls`。

## 8.3 重点问题

- Toast：`src/components/ui/Toast.svelte:25-37` 以可点击 div 关闭，键盘不可达；
- ScanProgress：`src/components/scanner/ScanProgress.svelte:13-22` 无 progressbar 语义；
- Sidebar：`src/components/layout/Sidebar.svelte:51-96` 无 expanded/current；
- FilterBar：`src/components/scanner/FilterBar.svelte:25-33` active 仅靠颜色；
- 主题/设置按钮：`side-panel/App.svelte:92-101` 仅 title；
- Payload、Vue、React、Sniff、SourceMap 存在可点击 div/span；
- Cookie/SourceMap dialog 缺 focus trap/restore；
- UrlInput、Multiurl、Report 等存在缺少显式 label 的输入。

## 8.4 Toast 推荐结构

- 外层分别使用 `aria-live="polite"` 和错误 `aria-live="assertive"`；
- Toast 内容不是整体可点击 div；
- 提供明确关闭 button，带 `aria-label="关闭通知"`；
- 成功 Toast 3-4 秒自动关闭，错误默认 8 秒或手动关闭；
- 支持操作按钮，如“重试”“查看”；
- 宽度 `min(360px, calc(100vw - 2rem))`。

## 8.5 验收工具和场景

- `pnpm check`：0 a11y warnings；
- 仅键盘完成 Popup → Side Panel → 运行 Headers → 筛选 → 导出；
- macOS VoiceOver 完成同一流程；
- 200% 缩放和 320/400px 宽度下无不可达控件；
- `prefers-reduced-motion` 下无 pulse/slide/scale；
- Windows High Contrast / forced-colors 下当前项和焦点仍可辨识。

---

## 9. 组件与代码落地建议

## 9.1 建议新增组件

```text
src/components/
├─ layout/
│  ├─ ResponsiveSidebar.svelte
│  ├─ PanelShell.svelte
│  └─ TaskCenter.svelte
├─ task/
│  ├─ TaskRunner.svelte
│  ├─ TaskProgress.svelte
│  ├─ TaskControls.svelte
│  └─ TaskSummary.svelte
├─ results/
│  ├─ ResultToolbar.svelte
│  ├─ ResultList.svelte
│  ├─ ResponsiveTable.svelte
│  ├─ DetailDrawer.svelte
│  └─ ExportMenu.svelte
├─ feedback/
│  ├─ LoadingState.svelte
│  ├─ EmptyState.svelte
│  ├─ ErrorState.svelte
│  ├─ ConfirmDialog.svelte
│  └─ ToastViewport.svelte
└─ form/
   ├─ Field.svelte
   ├─ UrlField.svelte
   ├─ SearchField.svelte
   └─ SecretField.svelte
```

不建议一开始建立过度通用的大组件。每个组件先在 2-3 个代表性面板试用，再固化 API。

## 9.2 建议新增服务/Store

```text
src/lib/tasks/task-controller.ts
src/lib/actions/clipboard.ts
src/lib/actions/download.ts
src/lib/errors/actionable-error.ts
src/lib/navigation/pending-actions.ts
src/stores/recent-panels.ts
src/stores/favorite-panels.ts
src/stores/analysis-context.ts
src/stores/task-center.ts
```

## 9.3 扩展 PanelMeta

当前 `PanelMeta` 只有 id、label、icon、category、categoryLabel、catColor。建议增加：

```ts
interface PanelMeta {
  id: string;
  label: string;
  shortLabel?: string;
  aliases: string[];
  keywords: string[];
  category: string;
  icon: string;
  capabilities: Array<
    'target-url' | 'task' | 'filter' | 'detail' |
    'copy' | 'export' | 'history' | 'handoff'
  >;
  supportsAutoRun: boolean;
  supportedProtocols?: string[];
}
```

用途：驱动搜索、快捷入口、自动运行校验、统一工具栏和可访问名称。

---

## 10. 开发契约（试点实施前必须确认）

以下契约用于把建议转成可直接开发的边界，避免各面板再次自行定义状态。

### 10.1 PendingAction 消息时序

```text
Popup
  ├─ 查询 active tab / 校验 URL
  ├─ CREATE_PENDING_ACTION(action, tabId)
  ▼
Background
  ├─ 写入 tabId 队列
  ├─ 请求 browser.sidePanel.open(tabId)
  ▼
Side Panel
  ├─ GET_PANEL_CONTEXT → targetTabId
  ├─ CLAIM_PENDING_ACTION(targetTabId)
  ├─ 切换到有效可见面板
  ├─ 运行成功 → ACK_PENDING_ACTION(id)
  └─ 运行失败 → FAIL_PENDING_ACTION(id, recoverableError)
```

状态转移：

```text
pending → claimed → acknowledged
                 └→ failed → pending（用户重试）
pending/claimed → expired
```

约束：action id 幂等；Background 是唯一 claim 方；tab 关闭、导航或超时统一清理；Side Panel 不直接删除队列记录。

### 10.2 TaskController 最小 API

```ts
type TaskStatus =
  | 'idle' | 'validating' | 'running' | 'paused'
  | 'succeeded' | 'partial' | 'cancelled' | 'failed';

interface TaskAdapter<TInput, TResult> {
  validate(input: TInput): Promise<void> | void;
  run(input: TInput, ctx: {
    signal: AbortSignal;
    reportProgress(update: Partial<TaskState>): void;
  }): Promise<TResult>;
  summarize(result: TResult): TaskSummary;
}

interface TaskController<TInput, TResult> {
  state: Readable<TaskState>;
  start(input: TInput): Promise<TResult | undefined>;
  pause?(): void;
  resume?(): void;
  cancel(): void;
  retry(mode: 'all' | 'failed'): Promise<TResult | undefined>;
}
```

取消必须通过 `AbortSignal` 向 background fetch、并发队列和本地处理传播；仅设置 UI 布尔值不算完成适配。底层不支持立即 abort 时，至少停止派发后续工作，并把状态标为 partial/cancelled。

### 10.3 ResultToolbar 适配边界

不强迫不同面板共享同一种 finding 数据结构，而是共享 query 协议：

```ts
interface ResultAdapter<TItem, TQuery> {
  apply(items: TItem[], query: TQuery): TItem[];
  getSearchText(item: TItem): string;
  serialize(items: TItem[], format: ExportFormat): string | Blob;
  getId(item: TItem): string;
}
```

页面展示、统计、复制和导出必须使用同一个 `adapter.apply(rawItems, query)` 结果。各面板只定义自己的字段、列和 serializer，不重写筛选状态语义。

### 10.4 试点面板适配清单

| 面板 | 输入 | 底层取消 | 结果 | 重点验收 |
|---|---|---|---|---|
| JS Archive | 当前 tab/URL/归档选项 | fetch + 打包阶段 | 文件与 manifest | 多阶段、取消不下载完整包 |
| Fuzz | URL/字典/并发 | 并发队列停止派发 | HTTP 结果 | partial 与失败项重试 |
| XSS | URL/注入点/payload | probe 队列 + fetch | XSS finding | 大任务统计与历史 |
| SourceMap | URL/资源列表 | fetch/解析/下载 | 源文件 | 阶段与详情抽屉 |
| Multiurl | URL 列表/间隔 | 创建标签循环 | 逐项结果 | 取消和失败统计 |

### 10.5 备份字段策略

| 类别 | 默认导出 | 导入策略 |
|---|---|---|
| UI/布局/普通偏好 | 是 | 可覆盖，展示摘要 |
| 扫描历史 | 用户可选，默认是 | 合并或覆盖需选择 |
| 自定义规则 | 是 | 校验 schema 后覆盖/合并 |
| API Key/Token/Cookie | 否 | 单独确认，不静默覆盖 |
| pending action/临时状态 | 否 | 禁止导入 |
| 未知 storage key | 否 | 拒绝或仅高级模式显式选择 |

备份文件包含 `schemaVersion`、`appVersion`、`exportedAt` 和类别摘要。

### 10.6 版本规范

- runtime UI：`browser.runtime.getManifest().version`；
- 非 runtime 纯函数：由调用方注入 `appVersion`；
- 报告/备份元数据：写入同一版本；
- CI 搜索并禁止新增 `v6.0`、`v7.0`、`6.0.0` 等硬编码展示版本；
- 代码注释只描述能力，不写易过期产品版本。

---

## 11. 面板能力审计摘要

符号：`✓` 完整、`~` 部分、`—` 缺失。维度：输入 I、运行/进度 R、筛选 F、详情 D、复制 C、导出 E、错误恢复 X。

| 类别 | 面板 | I | R | F | D | C | E | X | 重点建议 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| 侦察 | favicon | ✓ | — | — | ~ | ✓ | — | ~ | 增加状态、空态和导出 |
| 侦察 | gather | ✓ | ~ | ✓ | ✓ | ✓ | ✓ | ✓ | 纳入统一任务进度 |
| 侦察 | subdomain | ✓ | ✓ | ✓ | ✓ | ✓ | ~ | ✓ | 统一导出菜单 |
| 侦察 | asset | ✓ | ~ | ✓ | ✓ | ✓ | ✓ | ✓ | API 错误增加设置/重试 CTA |
| 扫描 | xss | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 任务控制器首批试点 |
| 扫描 | cors/headers | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 复制失败处理、共享工具栏 |
| 扫描 | waf | ✓ | ~ | — | ~ | ✓ | ✓ | ✓ | 增加筛选、详情和明确进度 |
| 扫描 | fuzz | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 修正取消/部分历史语义 |
| 扫描 | graphql | ✓ | ✓ | ✓ | ✓ | ✓ | ~ | ✓ | 补齐统一导出 |
| 扫描 | cookie-audit | ✓ | ~ | ✓ | ✓ | ✓ | ✓ | ✓ | 修复 dialog 焦点 |
| 扫描 | sniff/leakscan | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 目标来源说明、复制异常 |
| 扫描 | hae | ✓ | — | ✓ | ~ | ✓ | — | ✓ | 增加规则结果导出/详情 |
| 利用 | encoding | ✓ | — | — | ~ | ✓ | — | ✓ | 强化输入输出分区 |
| 利用 | payload | ✓ | — | ✓ | ✓ | ✓ | — | ✓ | 修复可点击 div，支持导出 |
| 利用 | spoof | ✓ | — | ✓ | ✓ | ~ | ~ | ✓ | 统一复制/导出与状态 |
| 利用 | jsctrl | — | ~ | — | ~ | ✓ | — | ✓ | 明确操作结果和恢复 |
| 框架 | vue/react/angular | ✓ | ~ | ✓ | ✓ | ✓ | ✓ | ~ | 长任务纳入 TaskRunner |
| 框架 | svelte | — | ✓ | — | ✓ | ✓ | ✓ | ✓ | 增加筛选 |
| 框架 | ruoyi | ✓ | ~ | ✓ | ✓ | ✓ | ✓ | ✓ | Hook 状态进入任务中心 |
| 框架 | sourcemap | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 修复 modal，可作详情抽屉试点 |
| 工具 | links | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 加跨面板交接 |
| 工具 | multiurl | ✓ | — | — | — | ✓ | ✓ | ~ | 取消、逐项失败、结果列表 |
| 工具 | history | ✓ | — | ✓ | ✓ | — | — | ✓ | Store 删除、回跳、导出 |
| 工具 | tabsave | — | — | — | — | ✓ | ✓ | ~ | 增加失败统计和恢复 |
| 工具 | exif | ✓ | ✓ | — | ✓ | ✓ | ~ | ✓ | 筛选和统一导出 |
| 工具 | storage-check | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 适配响应式表格 |
| 工具 | source-loader | ✓ | ~ | — | ✓ | ✓ | ✓ | ✓ | 搜索/大文件/任务状态 |
| 工具 | jsarchive | ✓ | ✓ | — | ✓ | — | ✓ | ✓ | 作为任务状态基准，补复制 |
| 报告 | report | ✓ | ~ | ✓ | ✓ | — | ✓ | ✓ | 修复筛选与导出同源 |

---

## 12. 分阶段实施路线

## 阶段 0：建立体验基线（0.5-1 天）

- 记录当前 320/400/600/900px 四种 Side Panel 截图；
- 记录 Popup、Side Panel、Options 的亮/暗主题截图；
- 建立 5 条核心任务的完成时间和失败点；
- 保存 `pnpm check` 基线：0 errors / 43 warnings；
- 建立组件清单和 token 使用规则。

交付物：基线截图、任务录像、问题清单、设计 token 草案。

## 阶段 1：P0 可靠性与反馈（3-5 天）

1. pending action 按 tab 隔离、过期和失败恢复；
2. 统一有效 activePanel 与 hidden 规则；
3. 动态加载 Loading/Error/Retry；
4. 修复 Report 严重度筛选导出；
5. 修复 History 单条删除 Store 和嵌套交互；
6. 统一 Popup、StatusBar、Options 与报告元数据的版本来源；
7. UrlInput 增加 label、Enter、校验；
8. ScanProgress 增加 indeterminate 和 ARIA；
9. Toast 增加关闭按钮、live region 和错误时长。

验收：核心点击不再静默失败；无明显错误范围导出；关键通用组件可键盘使用。

## 阶段 2：导航与响应式（5-8 天）

1. Sidebar 搜索、最近、收藏；
2. 分类折叠持久化；
3. 520px/400px 响应式折叠；
4. Popup 改为当前页 + 快捷操作 + 最近 + 搜索；
5. 版本和主题统一；
6. Options 增加分区导航和保存状态；
7. 备份建立字段白名单，默认排除敏感配置，并为敏感导入/导出增加确认。

验收：新用户 10 秒内找到指定工具；320/400px 无关键控件不可达；三入口视觉一致。

## 阶段 3：统一任务和结果（1-2 周）

1. TaskRunner 在 JS Archive、Fuzz、XSS、SourceMap、Multiurl 试点；
2. ResultToolbar 在 CORS、Headers、XSS、Report 试点；
3. ErrorState 覆盖 API、权限、content script、超时；
4. ClipboardAction / ExportMenu 全局替换；
5. ResponsiveTable 和 DetailDrawer 试点。

验收：五个试点面板状态一致；取消不会伪报成功；复制失败不会显示成功；导出范围可预测。

## 阶段 4：跨面板工作流（1 周）

1. analysisContextStore；
2. History/Report 回跳源面板；
3. URL/脚本/发现的“在其他工具中打开”；
4. 全局 TaskCenter；
5. 最近目标和任务恢复。

验收：从信息收集发现一个脚本到 Source Loader/JS Archive 分析，不再需要复制粘贴。

## 阶段 5：全量迁移与可访问性（持续）

- 按类别迁移剩余面板；
- 消除 43 条 Svelte warning；
- VoiceOver、键盘、对比度和 reduced-motion 验收；
- 建立视觉回归和核心 E2E。

---

## 13. 优先级与投入估算

| 工作项 | 优先级 | 粗略投入 | 影响范围 | 风险 |
|---|---:|---:|---|---|
| pending 按 tab 隔离 | P0 | 1-2 天 | Popup/Side Panel/store | 中 |
| 有效 activePanel 规则 | P0 | 0.5-1 天 | Side Panel/layout | 低 |
| 加载/错误/重试 | P0 | 1 天 | Side Panel/反馈组件 | 低 |
| Report 导出修复 | P0 | 0.5-1 天 | Report/report builder | 中 |
| Toast/Progress/UrlInput a11y | P0/P1 | 1-2 天 | 多面板共享组件 | 中 |
| Sidebar 搜索/最近/收藏 | P1 | 3-5 天 | 导航/store/options | 中 |
| Popup 重构 | P1 | 2-3 天 | Popup | 低 |
| Options 分区导航 | P1 | 3-5 天 | Options | 中 |
| TaskRunner 试点 | P1 | 5-8 天 | 5 个复杂面板 | 高 |
| ResultToolbar/ExportMenu | P1 | 4-6 天 | 多面板 | 中 |
| 跨面板上下文 | P2 | 4-6 天 | panels/store/history | 中高 |
| 全量 a11y/响应式迁移 | P2 | 1-2 周 | 全 UI | 中 |

估算不含视觉稿评审、产品确认和浏览器兼容测试。

---

## 14. 验收指标

## 14.1 任务效率

- 从 Popup 启动 CORS/Headers 到看到运行状态：≤ 2 次点击；
- 从 Side Panel 找到任意已知名称工具：≤ 5 秒；
- 从某 URL 发现转到另一个分析面板：≤ 2 次点击，无复制粘贴；
- Options 任意配置区：≤ 1 次导航点击；
- 用户取消任务后 500ms 内停止派发新工作并显示 cancelled。

## 14.2 可靠性

- 多 tab pending action 100% 不串台；
- 所有动态加载失败均可重试；
- 所有复制/下载操作只有真实成功后才提示成功；
- 展示结果、统计数量和“导出当前筛选”完全一致；
- 切换/重启后不会打开隐藏或不存在的面板。

## 14.3 响应式

测试宽度：320、400、520、720、1024px。

- 无页面级不可控横向滚动；
- 所有主要操作可见或可通过明确菜单访问；
- Sidebar 不使主内容小于可用阈值；
- Toast、Dialog、Drawer 不超出视口；
- 表格在窄宽下可切换卡片或隐藏次要列。

## 14.4 可访问性

- `pnpm check` 0 errors、0 a11y warnings；
- 核心流程全部可键盘完成；
- 所有 icon-only button 有稳定可访问名称；
- modal 焦点不逃逸，关闭后正确恢复；
- 文本/控件/状态达到 WCAG AA；
- 动态状态可被读屏感知但不频繁打断；
- reduced-motion 下不使用 pulse/slide/scale。

## 14.5 视觉一致性

- 三入口版本、主题、品牌和 token 一致；
- 同类控件高度、圆角、间距一致；
- 不再通过使用处 `card p-*` 随意覆盖卡片基础内边距；
- 状态颜色只来自语义 token；
- 关键辅助文字不低于 12px。

---

## 15. 测试建议

### 组件测试

- UrlField：校验、Enter、disabled、错误关联；
- TaskProgress：确定/不确定/取消/部分失败；
- ResultToolbar：筛选、数量、清除、导出范围；
- ErrorState：重试、打开设置、复制诊断；
- Dialog/Drawer：焦点陷阱、Escape、焦点恢复；
- Sidebar：搜索、收藏、折叠、当前项、窄宽。

### E2E 核心流程

1. Popup 在普通网页运行 Headers；
2. Popup 在不支持页面正确阻止并解释；
3. 两个 tab 同时运行不同 quick action；
4. 动态面板加载失败后重试；
5. Fuzz/XSS 运行中取消并保留部分结果；
6. Report 严重度筛选后导出并校验文件内容；
7. Options 修改布局后 Popup/Sidebar 同步；
8. History 详情回到源面板；
9. 320px 键盘操作完整流程；
10. 暗色主题与 reduced-motion 快照。

### 视觉回归

至少覆盖：

- Popup：默认、搜索、错误、暗色；
- Side Panel：展开/折叠导航、加载、错误、空态、运行、结果、Dialog；
- Options：各分区、未保存、危险确认；
- 宽度 320/400/720/1024；
- 亮色/暗色/high contrast。

---

## 16. 给后续实施人员的工作原则

1. **先修任务反馈，再调视觉细节。** 用户不知道是否运行成功时，圆角和渐变没有价值。
2. **先做共享骨架试点，再批量迁移。** 不要一次重写 35 个面板。
3. **展示、统计、复制、导出必须来自同一个 query。**
4. **Toast 不能替代持久错误状态。** 错误消失后仍要有恢复入口。
5. **取消是独立状态，不是失败，也不是成功。**
6. **隐藏、排序、最近、快捷键必须共享一个导航数据源。**
7. **跨面板传递结构化上下文，不依赖剪贴板。**
8. **不要用 title、placeholder、颜色作为唯一语义。**
9. **所有长任务都必须可观测、可停止、可恢复。**
10. **每个阶段都用真实浏览器和窄 Side Panel 验证，不只看静态代码。**

---

## 17. 最终建议

如果只安排一轮优化，建议严格按以下顺序执行：

1. 修复 pending 按 tab 隔离、Popup 失败反馈和自动运行恢复；
2. 统一有效 activePanel，消除隐藏面板被激活；
3. 为动态加载增加真实重试和可访问状态；
4. 修复 Report 筛选/导出不一致和 History 数据层绕过；
5. 升级 UrlInput、ScanProgress、Toast、FilterBar 四个共享组件；
6. 实现 Sidebar 搜索、最近使用、收藏与窄宽折叠；
7. 重构 Popup 为“当前页快速行动”，Options 为分区配置中心；
8. 在五个复杂面板试点 TaskRunner、ResultToolbar、ErrorState、ExportMenu；
9. 建立跨面板上下文和 History/Report 回跳；
10. 最后完成全量 a11y、响应式和视觉 token 迁移。

完成前四项后，灵眸的可靠性和信任感会明显提升；完成前八项后，35 个工具会从“功能集合”形成一致的专业工作台；完成全部路线后，产品才具备可持续扩展的 UX/UI 基础。
