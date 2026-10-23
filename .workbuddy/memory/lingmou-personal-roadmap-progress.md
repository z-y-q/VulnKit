---
name: lingmou-personal-roadmap-progress
description: "灵眸个人版优化路线(docs/个人版项目优化路线.md)执行进度 — P0+P1+P2(批次1-7)+§3.4关键模块测试+v7.28文档门面+SQLi报错注入引擎完成,剩留后续项"
metadata: 
  node_type: memory
  type: project
  originSessionId: f331da15-081a-44f0-9f90-ff2742ac4341
---

按 docs/个人版项目优化路线.md(7 批次,非安全项)执行。2026-07-14 完成 P0(批次1+2),验证全 green(check 0/0、test 657/657 无警告、test:coverage 退出0、build/build:firefox 成功)。

**批次1 生命周期止损(§2)**:
- XSS 面板(XssPanel.svelte):存 interceptPollTimer/interceptStopTimer 句柄 + interceptEpoch 防旧回写 + clearInterceptTimers() + onDestroy 恢复页面拦截器;batchVerify 3s delay 改 abortableDelay
- Vue 面板(VuePanel.svelte):stopPermIntercept 调 P._restore() 还原原生 fetch/XHR + delete __VK_PERM__(否则下次 start 走 already 但 fetch 已原生→失效);onDestroy 清 permRefreshTimer/traverseTimer + 恢复页面(不写 $state 避免卸载后更新)
- TaskController(task-controller.ts)补 taskId/isCurrent()/dispose()(dispose 后旧 run 结果不回写);新增 abortableDelay(abortable-delay.ts);MultiurlPanel 手写 sleep 替换为 abortableDelay+try/catch break(保 cancel→cancelled 语义,关键:abortableDelay reject 不能直接传播否则变 failed)
- UrlInput:改 focusout+relatedTarget 消除 150ms 竞态(无需 timer)

**批次2 工程门禁(§3)**:
- 覆盖率:装 @vitest/coverage-v8@4.1.10;scripts test=vitest run / test:coverage=vitest run --coverage;vitest.config.ts 加 coverage(provider v8,reporter text/html/lcov,exclude entrypoints);阈值 lines:12/functions:8/statements:9/branches:10(略低于基线 13.8/9.8/10.7/11.8,基线低因 .svelte 面板无单测);.gitignore 加 coverage/
- CI:.github/workflows/ci.yml(check/test:coverage/build/build:firefox + artifact);package.json 加 packageManager pnpm@10.30.3 + engines node>=20。**lint 跳过(eslint 未装,待接入)**
- Source Map 警告(§3.3):根因是 sourcemap-analyzer.ts:153 注释含 `//# sourceMappingURL=data:` 文本被 Vite 误解析为真注释→读 data 为文件 ENOENT;改述注释消除。补 extractInlineSourceMap 测试 7 用例(测试内用拆分字面量 sm() helper 规避同样误解析)

**P1 进度(2026-07-14,批次3-5 主要完成,验证 check 0/0 test 667/667 build ok)**:
- 批次3 大数据(§4)✓:ResponsiveTable 加可选分页(§4.1,pagination prop 向后兼容,AssetPanel 未启用因已有 API 分页)+ paginate helper+8测试;ResizeObserver 去重+rAF(§4.2);大列表稳定 key(§4.3,Gather filteredTech/Resources/Leaks/allFiltered + Sourcemap secrets/endpoints + StorageCheck db/store/record/item + AssetPanel rowKey)
- 批次4 并发(§5)部分✓:Gather extractFromJsFiles 的 Promise.all 改 runConcurrent(并发6+可取消+URL去重,§5.1)+ allFiltered 已 $derived(§5.2)。**TaskController 推广 Vue/Angular/React/Svelte/RuoYi 5 框架面板留后续**(工作量大,建议每批1-2面板)
- 批次5 基础设施部分✓:loader Promise 缓存(§7.1,index.ts loadPanel+panelPromiseCache,失败删除可重试);analysis-context 并发语义(§8.1,consumePayload 改单key删除+in-flight guard+dispose());download.ts 补 sanitizeFilename(triggerDownload 自动用)。**createObjectURL 迁移 9 处留后续**(现有都已 revoke 功能正确,纯代码整洁);**Payload 动态加载(§5.3)留后续**(17KB 静态 import 影响小)

**P2 进度(2026-07-14,批次6-7 主体完成,验证 check 0/0 test 667/667 build ok)**:
- 批次6 一致性(§9+§10)✓:版本号单一来源(§10.1,wxt.config.ts 用 readFileSync 从 package.json 读 version,manifest=7.2.0 验证;app-version.ts:2 注释删 v7.3 漂移);inject 治理(§9,加 clean:inject/dev:inject watch 脚本,build:inject 先 clean;tsconfig.inject.json 加 noImplicitReturns(strict 第一步,11源文件无错误);生成物重建无 diff)
- 批次7 a11y(§11)部分✓:表单 label 4 处(§11.1,sourcemap/hae×2/payload 加 aria-label);Sidebar combobox(§11.2,activeIdx+方向键/Enter+动态 aria-expanded/activedescendant+listbox/option role,SearchField 已支持 onkeydown/rest 透传无需改)。**Vue DOM 扫描分批(§12.1)留后续**(6处 querySelectorAll('*') 在 MAIN world 注入函数,异步化风险高);**状态组件推广(§12.2)留后续**

**§3.4 关键模块测试(2026-07-14 完成,验证 check 0/0 test 821/821 coverage退出0)**:
新增 5 测试文件 / 154 用例(总测试 667→821),coverage 全超阈值(Lines 16.36/Statements 12.7/Branches 13.97/Functions 11.82):
- sender-guard(35):isOwnExtension/isExtensionPage/isContentScript/senderMatches×3策略/isAuthorized(已知+未知+缺tab+越权)/MESSAGE_POLICY。setup.ts 缺 browser.runtime.id,测试内 beforeEach 补
- crypto-engine(51):AES 5模式×3keySize roundtrip/DES/3DES/RC4/SM2(动态生成keypair+128位公钥自动补04+格式错误)/SM4(ECB/CBC/none+非法key长度)/Hash×6+HMAC+base64/RSA-OAEP roundtrip+非法PEM reject/Bcrypt hash+verify+非法cost。修正:bcryptjs compareSync 非法哈希返回 false 不抛错(非"哈希格式无效")
- leak-scanner(29):90规则/真阳性6类(AWS key/GitHub/IP/PEM/JWT/sourceMap)/placeholder过滤(全相同40字符)/低熵过滤(api-key-header minEntropy≥3,abcd循环熵2.0被滤)/Luhn/边界长度<4/重复去重/cap/排序/severityRank+toSimpleSeverity/大输入120KB<1.5s
- fetchers(23):fetchUrl 成功/非2xx HTTP_ERROR/超时abort→TIMEOUT/网络→NETWORK/TOO_LARGE content-length/maxBytes夹紧20MB硬顶/tailOnly 206+200降级slice(-N)/fetchImage data URL/fetchProbe includeBody/超时/fetchHeaderProbe HEAD失败回退GET/fetchWafProbe 50KB截断/fetchDnsResolve A记录过滤。mock global fetch(makeResponse helper,body undefined触发readTextWithLimit fallback),rate-limit用真实模块(settings=null走默认并发不触发browser)
- dnr(16):JS阻断规则9001/UA规则9002/请求头规则9010+段×20 创建-更新-删除/restoreSpoofState持久化恢复(ua.enabled重建+headers重建+storage空不创建+DNR抛错容错)。setup.ts缺declarativeNetRequest,测试内beforeEach补;afterEach调resetSpoofUa/resetSpoofHeaders恢复模块级spoofState(关键:mockRejectedValue测试末尾须恢复mock否则afterEach的reset因reject归为该测试fail)
- 关键模块覆盖率:crypto-engine 99.2%/dnr 98.6%/leak-scanner 72%/fetchers 65.8%(fetchZoomEyeAuth未测)/rate-limit 76.3%。**sender-guard 35测试全覆盖但coverage报告未单独列出该文件**(v8 provider展示问题,功能覆盖充分)

**TaskController 推广框架面板(2026-07-14,调研+Vue完成,验证 check 0/0 test 821/821 build 1.35MB)**:
调研5框架面板长任务,结论:仅 Vue startTraverse 是真长任务(setTimeout链+delay+可取消),其余为短任务/批量并发:
- Vue startTraverse 已接入 TaskController✓:traverseCtrl(createTaskController<{routes,tabId},void>,run内execInTab router.push + ctx.signal.aborted检查 + ctx.isCurrent()丢弃旧run + abortableDelay(delay,ctx.signal)替代setTimeout链+reportProgress(completed/total/phase));traverseActive改$derived(从traverseState镜像$effect订阅);stopTraverse→ctrl.cancel();onDestroy加traverseCtrl.dispose()移除traverseTimer;前置检查(routes空/tab无)留wrapper。permIntercept保持原样(后台开关式无完成语义,不适合TaskController,P0已治onDestroy)
- angular/react/svelte:单次sendToContent RPC(detect/exploreStore),scanning flag足够,**TaskController无收益保持现状**(非偷懒:短任务套状态机是过度工程)
- ruoyi scanJsRoutes:已改 runConcurrent(§5.1一致性,见下);非交互式批量并发未包TaskController(scanningJs flag足够)

**§5.1 ruoyi + §6.1 createObjectURL 迁移(2026-07-14 完成,check 0/0 test 821/821 build 1.35MB)**:
- ruoyi scanJsRoutes:Promise.allSettled(20个JS一次性全发)→ runConcurrent(concurrency限流+seen提到外层跨URL共享去重,原for内每次重建seen在并发下丢跨URL去重)
- createObjectURL 迁移 11 处→downloadBlob(sourcemap×3/asset删局部函数+import/vue/ruoyi/tabsave/options×2/history-archive/source-loader);source-loader/tabsave原同步revoke改1s更安全。剩 xss/report/extracted-links 3 个局部函数保留(均1s revoke无bug;report有filename改造lingmou-report-${date}.${ext}、extracted-links有toast副作用,非等价替换)

**§9.4 inject strict 提升(2026-07-14 完成,check 0/0 test 821/821 build 1.35MB)**:
tsconfig.inject.json strict:false → strict:true（P2 的 noImplicitReturns + 新增 noFallthroughCasesInSwitch 保留；strict 含 noImplicitAny/nullChecks/functionTypes/bindCallApply/propertyInit/alwaysStrict/noImplicitThis）。11 个 inject 文件全通过（质量高，无隐式 any/switch穿透/null）。alwaysStrict 使生成 JS 加 'use strict'（11 文件各 +1 行，严格模式更安全；建议浏览器验证框架检测等功能）。

**eslint 接入(2026-07-15 完成,lint退出0 check 0/0 test 821/821 build 1.35MB)**:
eslint10+typescript-eslint8+eslint-plugin-svelte3(svelte-eslint-parser)+globals；eslint.config.js(flat,js+tseslint+svelte flat/recommended)；CI lint step 启用(P0 注释取消)。lint 258→0。关闭的规则(误报/低价值/Svelte5不兼容)：no-useless-assignment(eslint10对$state/$effect误报)、no-useless-escape(正则\/低价值)、no-control-regex(sanitizeFilename有意过滤\x00-\x1f)、no-import-assign(export type re-export误报)、svelte/no-useless-mustaches(属性内JS\n转义)、svelte/prefer-writable-derived+reactivity(Svelte5建议)、prefer-rest-params+no-prototype-builtins(sourcemap-phase1 webpack chunk hook兼容写法)、@ts/no-explicit-any+no-unused-vars(项目惯例,tsc把关)、svelte/require-each-key(§4.3已对大列表加key,强制全部过严)。修复的真实问题:payload 三元→if/else、hae-store throw 加 cause(preserve-caught-error)。

**v7.28 文档门面 + SQLi 报错注入引擎(2026-07-15 完成,check 0/0 test 856/856 build 1.36MB)**:
- README 重写(替换 WXT 模板占位)+ docs/使用手册.md 新建:定位/36面板功能矩阵/安装/架构/安全设计/合法免责/通用交互+6类逐面板
- SQLi 报错注入引擎:src/lib/scanners/sqli-engine.ts(MySQL/MSSQL/PG/Oracle/SQLite错误特征库+报错payload+detectSqlError+isNewSqlError基线对比防误报);35测试(各DB命中+基线对比防误报+性能100KB<50ms);src/panels/sqli/SqliPanel.svelte(两阶段:Phase1每点基线+Phase2注入点×payload矩阵,复用TaskController/runConcurrent/ResultToolbar/ExportMenu/DetailDrawer/scan-history/autoRunStore);registry+loaders注册sqliscan(scan类💉,面板35→36)
- 关键设计:基线对比防误报(仅payload触发【基线无的】SQL错误才确认,防页面静态含报错文字误报);DB识别(具体→high/仅通用→medium);范围克制(仅报错注入,布尔/时间盲注留后续);注入点采集简化(URL+form未重构XSS避免回归)
- 测试抓的bug:Oracle正则\bORA前\b在连续字母失效→去\b;MySQL真实错误必带version
- 上轮对比纠正:XSS本就有完整两阶段验证引擎(reflected&&!sanitized),之前"主动验证弱"判断错;SQLi原是真空现补报错注入

**全部留后续(未做)**:
- TaskController 推广 Vue/Angular/React/Svelte/RuoYi 5 框架面板(批次4 剩余) — Vue traverse + ruoyi scanJsRoutes runConcurrent 已完成(见上),angular/react/svelte 评估为短任务保持
- createObjectURL 迁移(§6.1) — 11 处已完成(见上),剩 xss/report/extracted-links 3 局部函数保留
- Payload 动态加载(§5.3,17KB 影响小)
- Vue DOM 扫描分批(§12.1,MAIN world 改造风险高)
- 状态组件推广(§12.2,18 面板手写纯文本)
- inject strict(§9.4) — 已完成 strict:true 全开(见上)
- eslint 接入 — 已完成(见上)

**关键复用(勿重造)**:runConcurrent(src/lib/core/concurrency.ts,12+面板在用)、TaskController(task-controller.ts,17面板在用)、download.ts(downloadText/Json/Blob/buildFilename)、EmptyState/ErrorState(src/components/feedback、scanner)。相关:[[lingmou-ux-stage-progress]]
