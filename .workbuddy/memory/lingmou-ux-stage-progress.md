---
name: lingmou-ux-stage-progress
description: 灵眸 v6 浏览器扩展 UX/UI 优化的分阶段实施进度
metadata: 
  node_type: memory
  type: project
  originSessionId: b8cddc58-50c7-4695-8b5a-21459a5809ca
---

灵眸 v6（WXT + Svelte 5 + TypeScript 浏览器安全扩展，35 个工具面板）的 UX/UI 优化按 `docs/UX-UI优化建议.md` §12 分 6 阶段推进。

**阶段 1（P0 可靠性与反馈）已于 2026-07-13 完成**，9 项：
1. 版本来源统一 — 新增 `src/lib/core/app-version.ts` `getAppVersion()`，替换 Popup(v7.0)/StatusBar(v6.0)/Options(v6.0) 硬编码；report-builder `version` 参数化
2. UrlInput — label/Enter 提交/即时校验（可选 onValidate）/type=button（向后兼容）
3. ScanProgress — indeterminate（total=0 不再显示 0/0）+ role=progressbar + phase/elapsedMs/failed
4. Toast — aria-live（role=alert/status）+ 关闭按钮 + 错误默认 7s
5. History — scan-history store 新增 `deleteEntry(id)` 唯一入口；拆整行 role=button 内嵌删除的嵌套交互
6. Report — domain+severity 单一 query，展示/统计/导出同源；导出 toast 显示数量
7. 统一有效 activePanel — side-panel `$effect` 纠正：activePanel 必须在 visiblePanels，否则回退首个可见
8. 动态加载重试 — 新增 `PanelLoadState`/`PanelErrorState`，loadNonce 驱动 {#key} 重载，失败可重试/返回/复制诊断
9. pending 按 tab 隔离 — 新增 `src/lib/navigation/pending-actions.ts`，pending 带 tabId+60s 过期，side-panel 按 active tab 认领，popup 失败不静默关闭；background onRemoved 清理

**采用务实方案（非完整 Background 队列）**：Chrome sidePanel API 下 side-panel 无法直接获知绑定 tab，故用 tabId 比对认领而非 claim/ack 状态机。局限：同 tab 连触会覆盖、非原子 claim（已接受）。

验证基线（阶段1后）：svelte-check 0 errors / 40 warnings / 11 files；wxt build 1.25MB；vitest 530/530。

**阶段 2（导航与响应式）已于 2026-07-14 完成**，3 批 7 项：
- 批次2a 导航骨架：新增 `recent-panels`/`favorite-panels`/`sidebar-state` 三个 store（复用 panel-layout 范式）；Sidebar 重写（搜索⌘K + 最近 + 收藏 + 分类折叠持久化 + iconMode 图标栏 + 行点击/星标分离不嵌套）；Popup 重构（当前页域名状态 + 搜索替代分页 + 最近使用区 + 一键禁用反馈）；side-panel setActivePanel 记录 recent + ResizeObserver <520px 自动 iconMode
- 批次2b Options 分区：新增 `confirm` store（imperative ask()）+ `ConfirmDialog`（role=dialog aria-modal，默认焦点取消，Escape，焦点陷阱/恢复）；Options 重写为左侧目录(8分区)+hash 路由+每区保存说明+顶部未保存状态条；10 处原生 confirm() 全替换；修 importInput $state warning
- 批次2c 备份安全+样式：新增 `backup.ts` 字段白名单（preferences/rules/history/secrets/transient + 未知拒绝，schemaVersion=1，默认排除 API Key/pending/伪装状态）；Options 备份区重写（摘要预览+包含密钥二次确认+合并/覆盖模式+未知 key 拒绝）；新增 `shared.css`（reset/font/focus-visible/reduced-motion/语义变量亮暗），三入口 main.ts 导入；Popup 接入 themeStore 暗色（最小 :global(.dark) 覆盖）；backup 单测 12 条

验证基线（阶段2后）：svelte-check 0 errors / 40 warnings（持平）/ 11 files；wxt build 1.28MB；vitest 542/542（+12 backup）。

**阶段 3（统一 TaskRunner/ResultToolbar/ExportMenu/ErrorState）已于 2026-07-14 完成**，4 批：
- 批次3a 共享骨架（零面板改动）：新增 `src/lib/actions/{clipboard,download,serializers}.ts`（copyText 成功才 toast+失败 fallback；buildFilename `lingmou-{module}-{date}.{ext}`；toCsv/toJson/toMarkdownTable）、`src/lib/errors/actionable-error.ts`（ActionableError + COMMON_ERRORS §5.4 映射 + toActionableError 归一化）、`src/lib/results/result-adapter.ts`（ResultQuery/ResultAdapter/hasActiveQuery/cloneQuery）；新增组件 `ErrorState`（role=alert + recovery 按钮）、`ExportMenu`（details 下拉，复制当前+CSV/JSON/MD，空禁用）；test/setup.ts 加 matchMedia polyfill；+25 单测
- 批次3b TaskController：新增 `src/lib/tasks/task-controller.ts` createTaskController（writable<TaskState> 工厂，8 态，AbortSignal 适配 runConcurrent 零破坏，pause/resume/cancel/reset）+ `TaskRunner` 组件；jsarchive 接入（多阶段 collecting/fetching/packaging → adapter.run 面板闭包，保留"取消绝不 zipSync/下载/成功"语义，ErrorState 替代 toast）；+10 单测
- 批次3c ResultToolbar+fuzz：新增 `ResultToolbar`（发现N·显示M + 搜索 + slot 自定义筛选 + 清除 + 复制，aria-pressed）；fuzz 接入（controller 替换 cancelled/paused；statusFilter/sortBy/search → query；ExportMenu 替换 CSV/TXT/MD；copyText 修复未 await；probeSmart HEAD 优先逻辑不动）
- 批次3d 批量：multiurl 完整接入（controller 逐项成败 + 可取消 sleep + confirmStore 替代原生 confirm + ExportMenu）；xss 导出统一（buildFilename）+ clipboard 修复（copyFinding/copyText await，经 alias clipboardCopy 避本地重名）；sourcemap 导出统一（exportResultsCsv/exportEndpoints）+ clipboard 修复（copyPathsTree 715 未 catch）

验证基线（阶段3后）：svelte-check 0 errors / 40 warnings（持平）/ 11 files；wxt build 1.29MB；vitest 577/577（+35：25 服务层 + 10 task-controller）。

**xss/sourcemap controller 接入留后续**：xss scan 两阶段 + vulnCount/reflectedCount 派生耦合 + 10+ UI 引用，sourcemap 958 行多阶段 fetch/解析/下载，完整 controller 接入风险高于收益。controller 模式已在 jsarchive/fuzz/multiurl 3 面板充分验证（8 态 + AbortSignal + pause/cancel/partial）。xss/sourcemap 本轮做导出统一 + clipboard 修复（文档 §10.4 fallback："否则仅导出+clipboard+cancel"）。

**阶段 4（跨面板工作流：analysisContextStore/handoff/回跳/recent-targets/TaskCenter）已于 2026-07-14 完成**，3 批：
- 批次4a analysisContextStore 核心 + 来源横幅：新增 `src/stores/analysis-context.ts`（handoff 写+自动切面板+toast、consume 读+清一次性、consumePayload 条件消费单 key、peek/clear/back、storage 持久化+onChanged 同步+5min TTL）、`src/components/layout/ContextBanner.svelte`（来源横幅：前往/清除/返回）；side-panel App PanelHeader 下挂载；+17 单测
- 批次4b 迁移 6 处散落 handoff + History 回跳 + recent-targets：删除 3 个 `lingmou:{multiurl,fuzz,source}-pending` 字符串 key，写方（history-archive×2/links/gather）改 handoff，读方（multiurl/fuzz/source-loader）改 consume/consumePayload；HistoryPanel 每条增「↩ 回到」按钮 handoff targetUrl 回源面板；新增 `recent-targets` store + 9 单测；UrlInput 增 recordTarget prop（focus 候选下拉）+ mount consumePayload('targetUrl') 统一回填（所有扫描面板零改动获得回跳回填）；fuzz/cors/xss 试点 recordTarget
- 批次4c TaskCenter 历史聚合：新增 `src/stores/task-center.ts`（report 置顶+截断 20+持久化）、`TaskCenterPopover.svelte`（StatusBar 气泡：最近任务状态色点+计数，点击展开列表，点条目切面板）；task-controller 增 centerPanel/centerLabel 可选选项，5 终态（succeeded/partial/cancelled/failed×2）上报；jsarchive/fuzz/multiurl 传 centerLabel；+8 单测

验证基线（阶段4后）：svelte-check 0 errors / 40 warnings（持平）/ 11 files；wxt build 1.31MB；vitest 611/611（+34：analysis-context 17 + recent-targets 9 + task-center 8）。

**TaskCenter 架构限制（诚实）**：Svelte 5 side-panel {#key activePanel} 卸载组件，阶段3 controller 是组件级闭包，切走面板时运行中任务中断。本轮 TaskCenter 只聚合已结束任务（succeeded/partial/cancelled/failed），不做运行中实时聚合（那需 controller 提升模块级单例+回改 5 面板，留独立重构）。

**阶段 5（全量迁移与可访问性）已于 2026-07-14 完成**，4 批（v7.6–v7.9），达成文档 §14.4 硬指标 `pnpm check` 0 errors / **0 warnings**：
- 批次5a a11y 清零（v7.6 `c7b9738`）：40→0 warnings。三类机械修复：旧格式 svelte-ignore 改下划线（cookie-audit/sourcemap）；label 关联 for/id（cookie-audit/encoding/payload/spoof 共 15 处）；div/span 交互补 role+tabindex+keydown（payload/vue/react/sniff/storage-check，exif 拖拽区+sourcemap 文件行补 keydown）。ConfirmDialog 遮罩改 role=button+aria-label+keydown；清 cookie-audit/sourcemap 弹窗无效 stopPropagation；sourcemap 关闭背景改 `<button>`。**踩坑**：svelte-ignore 连字符→下划线改名后抑制仍失效（机制不明），故 overlay 类改真实 role 而非抑制
- 批次5b PanelMeta 扩展（v7.7）：registry.ts 加可选 aliases/keywords/capabilities/supportsAutoRun + `panelMatches(meta,q)` 工具（自 trim+toLowerCase）；35 面板全填中英文别名/关键词；Sidebar+Popup 搜索统一调 panelMatches（搜「跨域」→CORS、「cookie」→Cookie审计、「嗅探」→sniff）；+12 单测
- 批次5c form/ 组件族（v7.8）：Field（label+控件 snippet 经 {id,describedBy} 关联，结构性消除 label 警告）/SearchField（图标+Esc 清空+rest 透传 combobox a11y+bind:inputEl）/SecretField（密钥显隐）/UrlField（组合 Field）。试点：Sidebar 搜索→SearchField、Options API Key→SecretField、Options 远程 Payload URL→UrlField。全用 $derived 派生 uid 规避 state_referenced_locally
- 批次5d ResponsiveTable+注释清理（v7.9 `113 files`）：ResponsiveTable.svelte（泛型 T，宽屏表格按 hideUnder 逐级隐藏，<480px 切卡片，ResizeObserver 探宽）+ responsive-table-utils.ts 纯函数 +10 单测；AssetPanel 7 列试点。107 文件去「灵眸 v6.0」标记。**重大踩坑**：首次 Python 清理用 `re.sub(r'\(\s*\)','',t)` 想删空标记，误删全文件所有零参 `()`（函数定义/无参调用）破坏 78 文件，已 `git restore` 回退；二次 `\s` 跨行合并注释与 import 行，再次回退；三次改用 newline-safe `[ \t—–-]` 分隔符才成功——教训：批量正则替换必须排除换行且绝不匹配括号

验证基线（阶段5后）：svelte-check **0 errors / 0 warnings**（达成 §14.4）；wxt build 1.32MB；vitest 633/633（+22：panelMatches 12 + responsive-table-utils 10）。

**方向1（DetailDrawer + ResultToolbar/ExportMenu 推广，§5.2/§5.3/§6.1）已于 2026-07-14 完成**，3 批（v7.10–v7.12）：
- 批次A（v7.10 `ab77a0f`）：新建 `src/components/results/DetailDrawer.svelte`（右侧抽屉，混合模型：通用字段 props + children snippet 兜底；跨面板 handoff 复用 analysisContextStore；focus trap/Escape/焦点恢复/上一条下一条，a11y 复刻 ConfirmDialog）+ severityTone/类型抽到 `detail-drawer-utils.ts`（便于单测，避免 .svelte 解析）；CORS 接入完整闭环（ResultToolbar + ExportMenu + DetailDrawer：点卡片看详情 + 「在 XSS/安全头 中打开」handoff + verifyCredential 移入抽屉；修 copyIssue/copyAll/copyMarkdown 的 navigator.clipboard 未 await）；+7 单测
- 批次B（v7.11 `8d8adb7`）：Headers 复制文本/MD+导出CSV 3 按钮 → ExportMenu（CSV/MD/TXT，修未 await；保留 FilterBar/评分环/分组/infoLeaks/cookie/csp）；Report CSV/JSON/MD 3 按钮 → ExportMenu（复用 report-builder）+ clearAll 原生 confirm → confirmStore.ask（HTML/全量审计保留独立按钮）
- 批次C（v7.12 `1137d69`）：XSS findings 区 filter badge+sortBy+手写导出 → ResultToolbar（搜索/漏洞筛选/排序/计数）+ ExportMenu（CSV/MD/TXT，展示/导出同源 §6.1）；**不接 task-controller**（保持自管 scanning/cancelled），vulnCount/reflectedCount 不变；PoC/Console 保留为 children slot；删 exportFindingsCsv/copyMarkdown

**关键决策**：ResultToolbar/ExportMenu 独立于 task-controller（纯结果区可用），故 XSS 可只换结果区不碰状态机。分面板定深度——CORS 扁平完整套+DetailDrawer 试点；Headers/Report 多 section/聚合视图只换 ExportMenu（保留各自展示）；DetailDrawer 混合模型（不耦合 SeverityBadge 严格类型，severity 经 severityTone 映射）。

验证基线（方向1 主体后）：svelte-check 0 errors / 0 warnings；wxt build 1.34MB；vitest 640/640（+7 DetailDrawer）。

**方向1 收尾（ResultToolbar/ExportMenu 推广到更多面板 + DetailDrawer 推广，§5.2/§6.1）已于 2026-07-14 完成**，4 批（v7.13–v7.16）：
- 批次D（v7.13 `31f1382`）：leakscan（保留 FilterBar 5 档 severity，3 按钮→ExportMenu JSON/MD/TXT）+ redirect（FilterBar→ResultToolbar 搜索/漏洞筛选 + ExportMenu CSV/TXT/MD）；修未 await
- 批次E（v7.14 `1a798b1`）：sniff（保留分类 badge 筛选/分组/展开证据/框架跳转，3 按钮→ExportMenu）+ waf（3 按钮→ExportMenu；startScan 原生 confirm → confirmStore.ask danger）
- 批次F（v7.15 `970c00b`）：graphql（FilterBar→ResultToolbar 搜索/风险/排序 + ExportMenu JSON/MD/TXT 含 endpoints/schemaInfo）+ subdomain（手写工具栏→ResultToolbar 搜索/排序/存活·总计 + ExportMenu CSV/TXT）
- 批次G（v7.16 `263d774`）：XSS findings 卡片→DetailDrawer（看完整 payload/evidence + 在 Fuzz/安全头 中检测 handoff）+ Report finding 卡片→DetailDrawer（看完整 detail + 按模块分组导航 + 单条复制，补原卡片无操作）

**推广进度汇总**：ResultToolbar/ExportMenu 已覆盖 fuzz/multiurl(阶段3) + cors/headers/xss/report(方向1 主体) + leakscan/redirect/sniff/waf/graphql/subdomain(收尾) = **11 面板**。DetailDrawer：cors/xss/report = **3 面板**。原生 confirm→confirmStore 已清（waf+report，加阶段2 的 options）。clipboard 未 await 大面积修复。

验证基线（方向1 全部后）：svelte-check 0 errors / 0 warnings；wxt build 1.34MB；vitest 640/640。

**方向2（XSS/Sourcemap 接入 TaskController，§10.4 五试点凑齐）已于 2026-07-14 完成**，2 批（v7.18–v7.19）：
- 批次1（v7.18 `bcf35c8`）：XSS scan() 两阶段（反射过滤 + Payload 探测）→ createTaskController.run，ctx.signal.aborted 取代 cancelled（Phase1/Phase2 均传），reportProgress 上报 phase/completed/total；删 scanning/cancelled/scanned/total，cs+archiving；ScanProgress 接 cs；取消 controller.cancel；保留 vulnCount/reflectedCount 派生 + DOM Sink/AJAX 拦截/采集注入点独立 + 方向1 ResultToolbar/ExportMenu/DetailDrawer
- 批次2（v7.19 `9c4b15a`）：Sourcemap scan()（并发 scanBundle + scanAllSourceContent + saveFindings）→ controller.run，ctx.signal 取代 cancelled，取消时保留部分 results 跳过聚合；detect() 保持独立（phase detecting/detected）；type Phase 删 scanning/done；cs+scanning2/scanDone 派生；ScanProgress 接 cs；phase==='done' → scanDone

**§10.4 五试点全部接入 controller**：jsarchive(3b)+fuzz(3c)+multiurl(3d)+xss(v7.18)+sourcemap(v7.19)。memory 原"风险高于收益"已化解——保守策略（保留派生/UI/独立操作，只收敛状态机+取消+进度+task-center）。

验证基线（方向2 后）：svelte-check 0 errors / 0 warnings；wxt build 1.34MB；vitest 640/640。

**阶段 3/4 收尾：retry（§10.2/§3.4）已于 2026-07-14 完成**（v7.20 `5a4791e`）：
- controller 加 `retry(input?) = start(input ?? lastInput)`；start 缓存 lastInput；retry 无参=retry 'all'，传参=retry 'failed' 复用。+2 单测。
- multiurl（retry 'failed' 试点）：run 记 failedUrls + TResult 加；openAll 存 lastFailedUrls；「重试失败 N 个」按钮 → `controller.retry({urls: failedUrls})`。
- **TaskCenter 运行中实时聚合——评估跳过（架构重构）**：完整方案需 controller+adapter 提升模块级单例 + run 解耦组件 state（结果外置 store）+ 5 面板回改；务实替代（仅上报运行中显示）不解决切面板中断核心且可能误导，留独立大重构。task-center.ts / TaskCenterPopover.svelte 注释已记录该限制。

验证基线（retry 后）：svelte-check 0 errors / 0 warnings；wxt build 1.34MB；vitest 642/642。

**方向2 全量推广（TaskController/ExportMenu 覆盖剩余扫描面板）已于 2026-07-14 完成**，4 批（v7.21–v7.24），把项目评价指出的"TC 14%、EM 40%"短板补齐：
- 批次1（v7.21 `92a2552`）：8 经典扫描面板接入 TC——headers/leakscan/redirect/cors/graphql/sniff/subdomain/waf。统一 scanning/cancelled → createTaskController 状态机；ScanProgress 接 cs.completed/total/phase；waf 保留 confirmStore.ask（先确认再 start）；subdomain helper（verifyAndMerge/httpProbeVerify）改接 ctx 信号。**TC 覆盖 5→13/35**
- 批次2（v7.22 `db7df9f`）：6 工具面板——jsctrl（反调试 TC+native confirm→confirmStore+EM）、exif（仅 EM+copyText 修复，scanPageImages 简单未接 TC）、storage-check（TC+EM 替换手写 blob）、gather（多阶段 TC+EM）、cookie-audit（TC mount 自动+EM）、encoding（纯单值工具仅 copyText 修复，EM 不适用）。**副作用：批量清除未 await navigator.clipboard**。**TC 13→17/35**
- 批次3（v7.23 `b83eed6`）：5 面板补 EM——angular/react/svelte（detect 报告 EM+copyText）、jsarchive（JS 清单 EM）、sourcemap（API 端点 EM）。**EM 覆盖 →24/35**
- 批次4（v7.24 `ec4f27f`）：ruoyi（1086 行多工具复合）——接入 EM（敏感路由 json/csv/text）+ clipboard 修复；**刻意不接 TC**（3 独立扫描态 detecting/probing/marScanning，完整 TC 化需 3 controller 或大重构，风险/收益比不佳，marDictionaryScan 局部 cancelled 已够用）。**EM →25/35**

**最终覆盖**：TaskController **17/35** 面板（cookie-audit/cors/fuzz/gather/graphql/headers/jsarchive/jsctrl/leakscan/multiurl/redirect/sniff/sourcemap/storage-check/subdomain/waf/xss；剩余 18 为纯工具/CRUD/展示型，按设计不接）；ExportMenu **26/35** 面板（剩余 9 为单值工具/静态展示，EM 不适用）。

**明确不迁移（by design）**：vue(多工具非扫描)/spoof(配置)/tabsave(抓取)/payload(静态库)/asset/favicon(纯展示)/history/history-archive/report/links/hae(展示/CRUD)/encoding(单值)。

验证基线（全量推广后）：svelte-check 0 errors / 0 warnings；wxt build 1.34MB；vitest 642/642。

**待续（可选/持续）**：
- 方向1 进一步收尾：ResultToolbar/ExportMenu/DetailDrawer 推广到剩余 ~20 面板（按需，边际递减）
- TaskCenter 运行中实时聚合（独立大重构）
- handoff 与 pending-actions 合并
- 阶段 3/4 收尾：xss/sourcemap 完整 controller、retry('failed')、DetailDrawer（§5.3）、TaskCenter 实时聚合（controller 提升模块级）、handoff 与 pending-actions 合并、其余 30 面板 handoff/recent-targets 接入
- 阶段 5 持续：其余 30 面板 form/Field + ResponsiveTable 迁移、capabilities/supportsAutoRun 驱动 Popup 一键跑、视觉 token 全量迁移（Popup 完整暗色/btn/card/input 改语义变量）、视觉回归 + 核心 E2E（§1095，需 Playwright 基建）

实施计划全文见 `.claude/plans/snoopy-fluttering-sutherland.md`。后续仍按「先修反馈再调视觉、先做共享骨架试点再批量迁移」原则，避免一次铺开 35 面板。
