---
name: apple-design-polish
description: 灵眸 v6 已应用 Apple Design 精修；动效系统在 src/lib/ui/motion.ts，仅用临界阻尼
metadata: 
  node_type: memory
  type: project
  originSessionId: 42a36a8c-f51e-4b78-ad23-d9a12ca7de82
  modified: 2026-08-05T06:44:30.579Z
---

2026-08-05 对灵眸 v6（专业 Web 安全测试扩展）应用了 Apple Design 技能精修。

**关键约束（专业工具，不是消费应用）：** 动效只用**临界阻尼**（cubicOut / cubic-bezier(0.32,0.72,0,1) 近似），**不加弹性回弹**——服务清晰度，不花哨。这与 Apple 技能 §4 的「默认 damping 1.0」一致。

**新增的可复用子系统：**
- `src/lib/ui/motion.ts` — Svelte transition 构造器（`sheetTransition`/`popTransition`/`scrimFade`/`toastFly`）。Svelte 内置 transition 不自动响应 `prefers-reduced-motion`，此文件集中降级（duration:0）。**未来加 Svelte 动效优先复用这里，别再散写 CSS @keyframes。** 用 `transition:` 指令（非 `in:`/`out:`）以自动满足 §7 对称退出。
- 设计 token 在 `src/styles/shared.css` 的 `:root`/`.dark`：`--vk-ease`/`--vk-ease-out`/`--vk-dur*`（动效节奏）、`--vk-shadow-sm/md/lg/xl`（分层阴影）、`--vk-glass-highlight`（玻璃顶部受光边）。被三个入口共享 import。

**做了什么：** DetailDrawer/ConfirmDialog/Toast 从「只有进入动画、关闭瞬间消失」改为 Svelte transition 双向对称退出（§7）+ 物质化抵达（§12 分层阴影+高光边）；新增 `prefers-reduced-transparency`/`prefers-contrast: more` 降级（§14）；主题切换平滑过渡；`font-optical-sizing:auto` + `.vk-text-display` 排版（§15）。

**有意跳过（理由）：** ① 侧栏 header 下没做 scroll-edge 渐隐——header 是 stacked flex item，内容不在其下滚动，硬 border-b 才正确（技能 §12 自身限定「仅当浮层真的重叠内容时」）。② 35 个面板逐个精修、popup/options 整体重设计、抽屉拖拽+动量投射（§5/§6）均未做，列为后续。基线：`pnpm check` 0/0、856 测试、build 通过。关联 [[lingmou-ux-stage-progress]]。

**Phase II（2026-08-05，同日续）：35 面板（经共享层）+ popup/options 已完成。** 关键发现：35 面板本身极干净（仅 xss/ruoyi 有 `<style>`，且是导出报告模板非 UI），全部消费 `card`/`btn-*`/`input` 快捷方式 → **改快捷方式 + 共享组件即全升级，几乎不碰面板文件**。
- Phase 1 `uno.config.ts`：修主题色打架（danger/warning/success 对齐 `--vk-*`，保留 /opacity 故用 hex 不用 var）；btn 去彩色阴影；card 用 `shadow-[var(--vk-shadow-sm)]`；transition 用 `--vk-ease`/`--vk-dur`；新增 `result-row`/`panel-heading`/`btn-link`。`shared.css` 加 `.sr-only`、`vk-progress-slide` keyframe。
- Phase 2 共享组件：`severity.ts` 的 `SEVERITY_COLORS` 实心填充→**淡彩描边**（单源，全扫描器同步）；`ResponsiveTable` 粘性 thead 半透明+分层阴影；`ScanProgress` 不定态 `animate-pulse`→游动段；`EmptyState`/`ErrorState`/`PanelErrorState` emoji+淡彩圆底；`ExportMenu`（CSS 缩放展开）/`UrlInput`（`menuPop` transition）浮层升级；`FilterBar` 按压反馈。motion.ts 加 `menuPop`。
- Phase 3：cors/sqli/xss 结果行加 `vk-pop-in` 错峰入场（封顶 12 项）。
- Phase 4 popup：scoped style 全量改 `--vk-*` token（结构中性色，自动跟随主题，删掉冗余暗色覆盖）、transition/按压/阴影统一、`popup-title` 加显示字距。popup 是纯 scoped CSS + shared.css token，**不用 UnoCSS**。
- Phase 5：options 粘性 header 加分层阴影；`extracted-links/main.ts` 补 `shared.css` + uno import（**修 bug**：原缺 reset/token/焦点环/a11y 媒体查询）。
- 跳过：SearchField（已与 `input` 快捷方式一致，强改会破坏紧凑图标布局）、card 默认 padding、xss/ruoyi 报告模板、options 原生控件。基线仍 0/0 + 856 + build。

**Phase III（2026-08-05，同日续）：用户反馈「还是丑」。我此前是盲改（没看渲染），这次用 Playwright + 浏览器 API stub 把 `.output/chrome-mv3` 跑在本地 http server 上实际截图诊断。** 根因 = **彩色 emoji 图标**（侧栏/标题/popup 全用 emoji，卡通、平台不一、廉价感第一来源）+ 卡片阴影过弱（平面）。
- **Lucide 单线图标集替代 emoji**：装 `@iconify-json/lucide`（devDep，build 时内联为 CSS mask，无运行时网络，符合扩展 CSP）；`src/lib/panels/icons.ts` 映射 36 个 panel id→lucide 名（全名已用 node 校验存在）；`src/components/ui/PanelIcon.svelte` 渲染 `<span class="i-lucide-x">`（颜色随 currentColor，emoji 回退）；`uno.config.ts` 加 `safelist: PANEL_ICON_CLASSES`（动态拼接的 i-lucide-* 必须显式声明才生成）。接入 Sidebar/PanelHeader/popup。
- **popup 特殊**：原纯 scoped CSS、不加载 UnoCSS（WXT 仅给用 utility 的入口注入）。为用 i-lucide-*，popup/main.ts 加 `import 'virtual:uno.css'`。替换 emoji span 后记得删 scoped 死规则（.quick-icon/.recent-icon/.tool-icon），否则 svelte-check 报 unused selector 警告（破 0/0 基线）。
- **深度**：`--vk-shadow-sm/md` 亮色 alpha 从 .06 提到 .08 + 加 8px y，卡片明显浮起。
- 截图前后对比（经图像分析确认）：emoji→矢量图标 + 阴影 =「polished/Apple-like，no longer cheap」。**剩余**：部分面板（如 Encoding）自身密度紧/文字偏淡（text-xs、placeholder gray-400）= per-panel，未做。
- **预览技巧**：扩展 UI 截图难，用 `python3 -m http.server` 跑 `.output/chrome-mv3`，Playwright `addInitScript` 注入 `window.browser`/`chrome` stub（runtime/tabs/storage/sidePanel 等），再 goto side-panel.html/popup.html 即可渲染 shell 截图。基线仍 0/0 + 856 + build。

**Phase IV（2026-08-05，同日续）：高频/首屏面板精修。** 加了可复用分段控件快捷方式 `seg`/`seg-btn-active`/`seg-btn-inactive`（uno.config.ts）。
- **Encoding 面板（首屏，重点）**：根因是「toggle 汤＋平面」。改：视图切换(经典/JWT/加密)与 编码/解码 模式 → 分段控件；每个视图包进 `card p-3 space-y-3`（深度+分组）；内层 `card p-2` → `card-flat p-3`（避免 box-in-box）；标签 `text-gray-500`→`text-gray-600 dark:text-gray-300 font-medium`、占位 `text-gray-400`→`gray-500`。截图验证：卡片浮起、分段控件干净、标签清晰，「不再平/挤」。**这是「工具型」面板的精修样板**（Payload/spoof/jsctrl 等同类可照搬）。
- **CORS / leakscan（扫描器型）**：结构本就 card 化＋用共享组件（EmptyState 带 disc、SeverityBadge 淡彩描边、结果行错峰），共享升级已覆盖；只把 `text-gray-400` 提示提到 `gray-500 dark:gray-400`。诚实结论：扫描器面板共享同一 shape，分段控件模式不适用（它们用 checkbox 不是按钮 toggle），边际收益低。
- 经验：**分段控件/卡片包装只对「工具型」面板（多 toggle、平面）有效**；扫描器面板靠共享组件已够。基线仍 0/0 + 856 + build。

**Phase V（2026-08-05，同日续）：把分段控件模式扫到其余工具型面板。** grep `bg-primary text-white' : 'btn-ghost` 定位 toggle-soup（Asset 3 / Spoof 2 / Payload 1）。asset 引擎+mode、spoof tab+UA 类别 → 分段控件（去 emoji）；payload 删掉与顶部 badge 行重复的分类 tab 行，并修 `badge-primary` 不是真类导致激活态不可见的 bug。用 Playwright DOM 查询验证（`.seg` 组数 + 激活段 + 残留旧 toggle=0）。分支 `feat/apple-design-polish` 现有 4 个 commit，未推送。

**Phase VI（2026-08-05）：用户仍嫌丑 → 真因是「持续可见的侧栏」本身噪音过大。** 我前几轮一直在精修面板内容，却忽略侧栏这个**框住每个视图**的持续层。每条 36 项都带：发光彩色点（`box-shadow: 0 0 6px color`）、1–8 数字快捷键 badge、激活行的 glass+shadow+发光指示条——全部在抢注意力（违 §12「材质重量编码层级」）。改：去点/指示条发光（留平色）、删数字 badge（Alt+N 功能保留在 tooltip）、激活行 glass+shadow → 平淡填充（Apple 式选择态）、内容区 p-3.5→p-4。截图验证「明显更安静」。基线 0/0 + 856。现 5 commit。
- **教训**：盲改危险。每轮用 Playwright + `browser` stub 渲染 `.output/chrome-mv3` 截图、用图像分析/人眼诊断。`analyze_image` 有时返回过度正面的评价（不可全信），**用户的眼睛才是真相**。
- **诚实边界**：这是 36 工具的密集安全扩展，「能更安静/克制」但有密度下限；想更激进需产品级取舍（默认折叠分类、默认图标栏、进一步弱化分类色、更大字号间距——会牺牲信息密度）。

**Phase VII（2026-08-05）：确立共享控件词汇表 + 三个样板面板。** 用户点名要「编码 + 两个扫描器」做样板。编码已是样板。结论：**36 面板根容器其实一致（34/36 是 `space-y-3`）**，「不一致」在内部控件语言。故确立统一控件词汇（uno.config.ts 快捷方式）：
- `seg`/`seg-btn-active`/`seg-btn-inactive` = **互斥**切换（工具面板：encoding/asset/spoof/payload 的视图/模式）
- `chip`/`chip-active`/`chip-inactive` = **多选**（新）：描边胶囊、激活实心 primary。CORS 的 HTTP 方法 native checkbox → chip。
- 徽章统一**淡彩描边**（`bg-{c}-50 text-{c}-700 ring-1 ring-{c}-200` + dark），SeverityBadge 是单源；CORS 的「仅风险/安全」计数控件已对齐。
- **样板三件套**：Encoding（工具型）+ CORS（扫描器型，方法→chip、计数→淡彩描边）+ Headers（扫描器型，本身已精致：评分环+评级+统计，未改）。其余面板可照此词汇铺开。
- 侧栏降噪（前一轮）+ 收藏星标改 SVG（去 emoji-ish 突兀）+ 删分类彩色点（侧栏默认单色）。分支 `feat/apple-design-polish` 现 8 commit，未推送。

**Phase VIII（2026-08-05）：把词汇铺到全部剩余面板（3 个并行 agent）。** 给 agent 的精确 spec：A) `badge` 语境的实心 `bg-{c}-500 text-white` → 淡彩描边（含条件 pill 的激活/非激活两支）；B) 多选 checkbox 组（`bind:checked={STATE[k]}`）→ chip（`onclick={() => STATE[k]=!STATE[k]}`，保留 `$state` 表达式）；C) 互斥 `btn ... bg-primary:btn-ghost` 行 → seg。覆盖 13 面板（sqli/xss/graphql/redirect/subdomain/sourcemap/vue/ruoyi/hae/headers/cookie-audit/react/gather）。结果：**全应用 0 个实心 -500 badge、0 个旧 toggle 行残留**；多选组（xss 选项/subdomain 6 方法/cookie Secure+HttpOnly）→ chip；react/gather 视图行 → seg。基线 0/0 + 856。现 9 commit。
- **故意跳过（agent 守住了边界）**：orange/purple/gray-500（spec 无映射）、动态 `{colorClass()}` 徽章、报告模板字符串里的 HTML、单 checkbox 布尔、radio 组、`btn-primary` 子标签行。这些是边角，后续可补 orange/purple 淡彩映射。
- **并行铺开技巧**：词汇转换是 per-panel 独立活，适合拆 3 个 general-purpose agent 并行（按面板分组，互不冲突），用精确 spec + 「只改 badge 语境/保留 state 表达式/不动逻辑」守则；完后统一 build/check/lint/test 验证 + grep 验残留=0。

**Phase IX（2026-08-05）：用户「改好了但看着不舒服」→ 病根是「贫血式极简」。** 技能明确：克制需要**高对比 + 清晰焦点**（§12 vibrancy 别用扁平灰字、§16.6 用对比让重点显眼），不是单纯去色。我之前降噪时**删对了装饰噪音，却顺手削掉了功能性对比**（文字降到 gray-400/500 低于 WCAG AA、徽章全降饱和淡彩、无焦点锚）= §16.6 警告的 minimal（贫血）≠ simple（清晰）。修：
- A 文字对比：`--vk-text-muted`→gray-600；sweep 269 处 `text-gray-400`→`text-gray-500`（全部 ≥ AA）。
- B 焦点锚：**主操作按钮 btn-primary → 舒服近黑**（`--vk-btn` 亮 `#1d1d1f`/暗 `#f3f4f6`，macOS 式），弃蓝色渐变。**选择 chip/链接保留蓝**（黑=动作，蓝=选中）。token `--vk-btn`/`--vk-btn-fg` 在 shared.css，亮暗反转。
- C 去嗡嗡：SeverityBadge 去 `ring-1`（每行结果都重复，最大细线噪音源）→ 纯淡彩底（-100 更有存在感）。
- 验证：dark mode 实测按钮 `#f3f4f6` 底/`#1d1d1f` 字（反转正确）。基线 0/0 + 856。现 10 commit。
- **关键教训（重要）**：`analyze_image` 工具一贯**过度正面**（连用户嫌丑时它都说 polished）——**不可信，用户眼睛才是真相**。多次「盲改 + 信工具」是几轮没击中「不舒服」的原因。每轮应：实拍截图 + 人眼/用户判断为准。

**Phase X（2026-08-05）：用户「折叠 OK、展开不行」→ 展开侧栏病根 = CJK 强制宽字距。** 展开侧栏的分组标题用 `uppercase tracking-widest`，但标题是**中文**（侦察/扫描/…）：`uppercase` 对 CJK 无效，`tracking-widest` 把汉字撑开成别扭的稀疏节奏 = 阅读不适（折叠版只有图标所以没事）。修：分组/最近/收藏标题去 `uppercase tracking-widest` → `text-[11px] font-semibold text-gray-400`（正常 CJK 字距）；分类内行距 `space-y-0.5`→`space-y-1`。**教训：CJK 文本绝不要加 `tracking-widest`/大字距**。另：440px 视口会自动折叠侧栏（narrow<520），要看「展开」须 ≥520px 视口或手动展开——之前几轮截图都拍成了折叠态，漏看展开问题。现 11 commit。

**Phase XI/XII/XIII：收藏星标 + 暗色可读性。** ① 收藏星标从「每行常驻+预留槽+琥珀」改为**仅悬停浮现的浮层**（已收藏项在顶部「收藏」区聚合，行内不留星）。② 用户「白天 OK、晚上看不清」：comfort-pass 的 gray-400→500 对亮色对、对暗色错（gray-500 在深底仅 ~3:1）。修：shared.css `.dark .text-gray-500/600 { color:#9ca3af !important }`（gray-400，~7:1）；`!important` 因 UnoCSS 合并 dark 变体+flat 选择器且后加载、同特异性会赢。侧栏分组标题灰阶原本写反（gray-400/gray-500）→ 翻正 gray-500/dark:gray-400。实测暗色二级文字全 #9ca3af。

**状态：12 commit 已 fast-forward 合并到 `main`（本地 main 领先 origin/v7，未 push）。** 分支 `feat/apple-design-polish` 仍存（与 main 等齐）。整套 Apple Design 精修收口：基础层→矢量图标→侧栏降噪→统一控件词汇(seg/chip/淡彩描边)→黑锚+对比→CJK/暗色修正。基线全程 0/0 + 856 测试 + build 通过。









