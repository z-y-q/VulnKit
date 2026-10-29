<h1 align="center">灵眸 · Lingmou</h1>

<p align="center">浏览器原生 Web 安全测试辅助套件 · Chrome / Firefox · MV3</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/z-y-q/VulnKit/main/package.json&query=$.version&label=version&color=blue">
  <img alt="wxt" src="https://img.shields.io/badge/WXT-0.20-purple">
  <img alt="svelte" src="https://img.shields.io/badge/Svelte-5-ff3e00">
  <img alt="ts" src="https://img.shields.io/badge/TypeScript-5.9-3178c6">
  <img alt="tests" src="https://img.shields.io/badge/tests-904-brightgreen">
  <img alt="ci" src="https://github.com/z-y-q/VulnKit/actions/workflows/ci.yml/badge.svg?branch=main">
</p>

---

## 这是什么

**灵眸** 是一款面向 Web 安全测试的浏览器综合辅助套件，把 **侦察 / 扫描 / 利用 / 框架分析 / 国产化能力** 聚合到 **36 个面板、一套统一交互** 里。

它不在流量层与 Burp Suite 竞争——而是利用浏览器扩展上下文（content script + MAIN world 注入 + `declarativeNetRequest`），做 **“页面侧”的深度感知**：框架运行时探测、JS 资产提取、敏感信息扫描、国密算法、国产后台框架专项。这些是 Burp 抓不到、单点插件做不深的事。

| 和谁比 | 关系 |
|---|---|
| 单点插件（HackBar / HackTools / FindSomething / Wappalyzer / ModHeader） | **直接竞争**：灵眸是它们的聚合 + 统一交互 + 深度页面感知 |
| 全流量代理（Burp Suite / ZAP / Caido） | **互补不替代**：Burp 管“流量改包重放”，灵眸管“页面侧分析” |
| CLI 扫描器（TruffleHog / Nuclei） | **部分重叠**：灵眸无 CI/批量编排，胜在浏览器内即开即用 |

> 适用人群：Web 安全研究员、白帽子、甲方安全测试人员。
>
> ⚠️ 本工具仅用于 **授权范围内的安全测试**，详见 [合法使用与免责](#-合法使用与免责)。

---

## 核心特性

- **🧭 36 面板一站式** — 6 大类（侦察 / 扫描 / 利用 / 框架 / 工具 / 报告），统一交互（任务控制 / 结果工具栏 / 导出菜单 / 详情抽屉 / 跨面板 handoff）
- **🔬 框架级页面感知** — Vue / React / Angular / Svelte / RuoYi 路由遍历 + 状态树探测，MAIN world 注入直达框架运行时
- **🧪 主动验证引擎** — XSS 两阶段验证（反射过滤 + Payload 矩阵 + 净化检测 + 上下文分级）+ SQLi 报错注入（基线对比防误报、识别 DB 类型），不止“发现可疑”，自动“证明可利用”
- **🇨🇳 国产生态** — SM2/SM4 国密算法、RuoYi（若依）后台框架专项检测、内置 SRC 脱敏规则
- **🏗️ 现代工程栈** — WXT + Svelte 5 runes + TypeScript，904 个单测 + 覆盖率门禁 + CI + ESLint + 任务状态机 + 并发池
- **🛡️ MV3 合规** — `declarativeNetRequest`（非已弃用的 webRequest），改 UA / 请求头 / 阻断 JS
- **🔒 默认安全** — 全量抓取走 background 代理 + `url-guard` SSRF 防护 + `sender-guard` 来源校验；无 `{@html}`，文本自动转义。详见 [权限矩阵](docs/权限矩阵.md)
- **⏸️ 可取消的批量任务** — 并发池（`runConcurrent`）+ 任务状态机（`TaskController`），支持限流 / 暂停 / 取消，符合“控制测试强度”的合规底线

---

## 功能总览

> 完整操作说明见 [docs/使用手册.md](docs/使用手册.md)。

### 🔵 侦察 Recon

| | 面板 | 能力 |
|---|---|---|
| 🖼️ | 图标识别 | favicon hash 指纹，反查同源资产 |
| 🔍 | 信息收集 | 从页面 / JS 提取技术栈、接口、敏感信息 |
| 🌐 | 子域名 | 子域名枚举（对接外部测绘 API） |
| 📍 | 资产测绘 | 对接 FOFA / ZoomEye / Quake 测绘平台 |

### 🔴 扫描 Scan

| | 面板 | 能力 |
|---|---|---|
| ⚡ | XSS 扫描 | 两阶段主动验证：反射过滤 + Payload 矩阵 + 净化检测 + 上下文分级 |
| 💉 | SQLi 扫描 | 报错注入：基线对比防误报 + DB 识别（MySQL/MSSQL/PostgreSQL/Oracle/SQLite） |
| 🔗 | CORS 检测 | 跨域配置错误检测 |
| 🛡️ | 安全头 | CSP / HSTS / X-Frame 等响应头审计 |
| 🔥 | WAF 指纹 | Web 应用防火墙识别 |
| ↗️ | 重定向 | 重定向链追踪 + 开放重定向 |
| 📂 | 目录扫描 | 目录 / 路径字典扫描（可取消、并发限流） |
| ◈ | GraphQL | 内省 / 端点探测 |
| 🍪 | Cookie 审计 | Secure / HttpOnly / SameSite 检查 |
| 👃 | 网站嗅探 | CMS / 技术栈指纹识别 |
| 🔓 | 泄露扫描 | 90 条规则敏感信息 / 密钥扫描 |
| 🎨 | HAE 规则 | 自定义正则规则高亮提取（YAML 管理） |

### 🟠 利用 Exploit

| | 面板 | 能力 |
|---|---|---|
| 🔤 | 编码工具 | Base64 / URL / Hex / HTML / JWT / Hash / 加密（含 AES/SM2/SM4/RSA/Bcrypt） |
| 💊 | Payload | XSS / SQLi / LFI / 反弹 Shell / Webshell / 命令参考库 |
| 🎭 | 请求伪造 | UA / XFF / Referer / 请求头伪造（DNR） |
| ⚙️ | JS 控制 | 拦截 / 阻断 / Hook 页面 JS |

### 🟢 框架 Framework

| | 面板 | 能力 |
|---|---|---|
| 🟢 | Vue 分析 | 路由遍历 + Vuex / Pinia store 探测 |
| ⚛️ | React 分析 | Redux / Zustand / Hooks store 探测 |
| 🅰️ | Angular 分析 | Service / 依赖注入 / Ngrx |
| 🔶 | Svelte 分析 | store / rune 状态 |
| 📁 | RuoYi 路由 | 若依框架路由枚举 + 越权探测 |
| 🗺️ | Source Map | 源码映射还原 |

### 🟣 工具 Tools

| | 面板 | 能力 |
|---|---|---|
| 🔗 | 链接提取 | 页面 / JS 内 URL 提取 |
| 📑 | URL 多开 | 批量打开 URL（可取消） |
| 📜 | 历史档案 | 扫描历史记录 + 跨面板回跳 |
| 🗂️ | Wayback | 网页历史存档查询 |
| 📑 | 标签保存 | 标签页会话保存 / 恢复 |
| 📷 | EXIF 查看 | 图片元数据 / GPS |
| 🗄️ | 存储检查 | localStorage / sessionStorage / IndexedDB / Cookie |
| 📦 | 源码加载 | 页面源码获取 |
| 🗜️ | JS 归档 | 页面 JS 打包下载（ZIP，带 MANIFEST） |

### ⚪ 报告 Report

| | 面板 | 能力 |
|---|---|---|
| 📊 | 统一报告 | 扫描结果汇总 + 导出（脱敏） |

---

## 快速上手

### 安装（开发者加载）

> 目前以源码方式加载。从源码构建：

```bash
git clone https://github.com/z-y-q/VulnKit.git
cd VulnKit
pnpm install          # 需 Node ≥ 20、pnpm 10
pnpm build            # Chrome → .output/chrome-mv3
pnpm build:firefox    # Firefox → .output/firefox-mv2
```

**Chrome**：访问 `chrome://extensions` → 打开“开发者模式” → “加载已解压的扩展程序” → 选 `.output/chrome-mv3`。

**Firefox**：访问 `about:debugging` → “此 Firefox” → “临时载入附加组件” → 选 `.output/firefox-mv2/manifest.json`。

### 基本工作流

1. **打开侧栏** — 点工具栏图标，侧栏（`side-panel`）展开；或用 Popup 快捷区
2. **选目标** — 顶部 `UrlInput` 自动带入当前标签页 URL，或手动输入 / 从最近目标选
3. **搜面板** — 侧栏搜索框支持中文、英文别名、关键词（如搜“跨域”命中 CORS，搜“cookie”命中 Cookie 审计）
4. **运行** — 支持取消 / 暂停的面板会接入 `TaskController`；批量任务走并发池 + 按 hostname 限流
5. **看结果** — 复制 / 导出（JSON/CSV/TXT）/ 详情抽屉 / 一键 handoff 到关联面板
6. **右键菜单** — 选中文本右键可快速编解码 / 哈希 / 扫描

---

## 📸 截图

<!-- TODO: 补充截图（侧栏主界面 / 框架分析 / 泄露扫描 / 统一报告） -->

---

## 技术架构

### 技术栈

| 层 | 选型 |
|---|---|
| 框架 | WXT 0.20（浏览器扩展） |
| UI | Svelte 5（runes：`$state` / `$derived` / `$effect`）+ UnoCSS |
| 语言 | TypeScript 5.9（含独立 `tsconfig.inject.json` 管 MAIN world 脚本） |
| 测试 | Vitest 4 + @vitest/coverage-v8（821 测试，覆盖率门禁） |
| 质量 | ESLint 10（flat config）+ svelte-check + GitHub Actions CI |
| 加密 | crypto-js（通用）+ sm-crypto（国密 SM2/SM4）+ bcryptjs |
| 其他 | fflate（ZIP 归档）、js-yaml（HAE 规则） |

### 架构

```
┌──────────────────────────────────────────────────────────┐
│  entrypoints                                             │
│  ├── background.ts        后台：代理抓取 / DNR / 右键 / 消息 │
│  ├── bridge.content.ts    content：token + origin 校验的回执桥 │
│  ├── side-panel           主交互入口（36 面板懒加载）        │
│  ├── popup                快捷区（轻量元数据，不加载组件）   │
│  ├── options              设置（API key / 限流 / 规则）     │
│  └── extracted-links      独立结果页                        │
├──────────────────────────────────────────────────────────┤
│  panels/ (35)  ←── registry.ts（单一数据源）+ loaders.ts    │
│  侦察 · 扫描 · 利用 · 框架 · 工具 · 报告                    │
├──────────────────────────────────────────────────────────┤
│  lib/        analyzers / scanners / crypto / tasks / core │
│  components/ scanner / feedback / results / form（共享）   │
│  stores/     配置 / 历史 / 分析上下文（跨面板 handoff）     │
│  inject/     MAIN world 脚本源（TS → public/inject/*.js）  │
└──────────────────────────────────────────────────────────┘
```

### 安全设计

- **单一抓取入口**：所有目标抓取经 `sendMessage → background`，面板无直接 `fetch`；`url-guard` 拦截 loopback / 私网 / 链路本地
- **来源校验**：`sender-guard` 按消息类型校验来源（扩展页 / content script）
- **响应预算**：单响应硬顶 20 MB（默认 5 MB），JS 归档另有 100 MB 累计预算
- **速率限制**：`rate-limit.ts` 按 hostname 限流
- **渲染安全**：审计确认 `src/**` 无 `{@html}`，全文本自动转义；注入回执经 token + origin/source 校验

> 每一项 manifest 权限都有功能与调用位置佐证，详见 [docs/权限矩阵.md](docs/权限矩阵.md)。

---

## 🛠️ 开发

```bash
pnpm install
pnpm dev              # 开发模式（Chrome，含 inject watch）
pnpm dev:firefox      # 开发模式（Firefox）

pnpm check            # svelte-check 类型检查（基线 0 errors / 0 warnings）
pnpm lint             # ESLint
pnpm test             # 单元测试
pnpm test:coverage    # + 覆盖率（退出码 0 为基线）
pnpm build            # 构建 Chrome
pnpm build:firefox    # 构建 Firefox
pnpm zip              # 打包上架 zip
```

MAIN world 注入脚本由 TS 源（`src/inject/*.ts`）经独立 `tsconfig.inject.json`（`strict: true`）编译到 `public/inject/*.js`；`build:inject` 会先清理再重建，保证生成物可复现。

---

## 📁 项目结构

```
src/
├── entrypoints/      扩展入口（background / content / side-panel / popup / options）
├── panels/           35 个功能面板（平铺，按 registry 的 category 分组）
│   ├── registry.ts   面板元数据（id / label / icon / category / aliases / capabilities）
│   ├── loaders.ts    动态加载器（import() 懒加载 + Promise 缓存）
│   └── index.ts      面板配置 = 元数据 + 加载器
├── components/       共享组件（scanner / feedback / results / form）
├── lib/
│   ├── analyzers/    分析器（sourcemap / sniff / leak-scanner / hae-engine ...）
│   ├── scanners/     扫描引擎（leak-scanner 90 规则）
│   ├── crypto/       加密引擎（AES / SM2 / SM4 / RSA / Hash / Bcrypt）
│   ├── tasks/        TaskController 状态机 + abortableDelay + 并发池
│   ├── core/         tabs / messaging / url-guard / app-version / concurrency
│   └── actions/      下载 helper（downloadBlob / buildFilename / sanitizeFilename）
├── stores/           Svelte stores（配置 / 历史 / analysisContextStore 跨面板 handoff）
└── inject/           MAIN world 注入脚本源（TS，strict 编译到 public/inject/）

docs/
├── 使用手册.md        功能手册（本 README 的详尽版）
├── 权限矩阵.md        每项 manifest 权限的佐证与风险评估
└── 个人版项目优化路线.md  工程优化路线（P0-P3）
```

---

## 📚 文档

- [docs/使用手册.md](docs/使用手册.md) — 36 面板的逐项操作说明
- [docs/权限矩阵.md](docs/权限矩阵.md) — manifest 权限的最小化与可审计性
- [docs/个人版项目优化路线.md](docs/个人版项目优化路线.md) — 工程优化路线与进度

---

## ⚖️ 合法使用与免责

本工具仅用于 **授权范围内的安全测试**（合法授权的渗透测试、漏洞赏金 / SRC 项目、自有资产评估、安全教学与CTF）。

使用前请确认：

- **仅在书面授权范围内测试**，不得对未授权目标进行任何形式的探测
- **遵守《网络安全法》《数据安全法》《个人信息保护法》及《刑法》第 285 / 286 条**
- **不得** 破坏系统数据、获取他人个人信息、造成拒绝服务、利用漏洞牟利
- **验证即止**，确认漏洞存在后及时报告，不深入利用、不扩展影响
- 报告中涉及的个人信息须 **严格脱敏**（工具内置脱敏规则，但最终责任在使用者）

作者不对本工具的任何滥用行为承担责任。**使用者自行承担一切法律后果。**

---

## 🙏 致谢

- [WXT](https://wxt.dev) · 现代 WebExtension 框架
- [Svelte 5](https://svelte.dev) · UI 框架
- [HaE](https://github.com/gh0stkey/HaE) · 信息提取规则设计灵感
- 所有开源依赖的贡献者
