# 灵眸 v6.0 使用说明

Chrome 渗透测试辅助工具包，集成 22 个功能模块，覆盖编码解码、加密解密、Payload 工具、信息收集、资产测绘、网站嗅探、Vue 权限绕过、XSS 扫描、Source Map 分析、RuoYi 路由检测、WAF/CORS/子域名扫描等常见安全测试场景。

---

## 目录

- [安装](#安装)
- [项目结构](#项目结构)
- [编码工具](#1-编码工具)
- [图标识别](#2-图标识别)
- [信息收集](#3-信息收集)
- [资产测绘](#4-资产测绘)
- [链接提取](#5-链接提取)
- [URL 多开](#6-url-多开)
- [历史档案](#7-历史档案)
- [EXIF 查看](#8-exif-查看)
- [请求伪造](#9-请求伪造)
- [Vue 分析（重点）](#10-vue-分析)
- [JS 控制](#11-js控制)
- [Payload 工具](#12-payload-工具)
- [XSS 扫描](#13-xss-扫描)
- [Source Map 分析](#14-source-map-分析)
- [RuoYi 路由](#15-ruoyi-路由)
- [WAF 检测](#16-waf-检测)
- [Cookie 审计](#17-cookie-审计)
- [CORS 检测](#18-cors-检测)
- [子域名枚举](#19-子域名枚举)
- [React/Angular 检测](#20-reactangular-检测)
- [Source Loader](#21-source-loader)
- [网站嗅探](#22-网站嗅探)
- [权限说明](#权限说明)
- [常见问题](#常见问题)

---

## 项目结构

```
src/
├── manifest.json
├── background/
│   └── background.js              # Service Worker，消息中转、请求头注入、Cookie 代理
├── content/
│   └── vk-content.js              # Content Script，右键菜单处理、API 流量拦截
├── inject/                        # MAIN world 注入脚本（自包含 IIFE）
│   ├── vue-detect.js              # Vue 实例检测 + 路由/Store/守卫读取
│   ├── vue-store-explorer.js      # Pinia/Vuex Store 遍历导出
│   ├── ruoyi-route-hook.js        # RuoYi 动态路由拦截
│   ├── react-detect.js            # React 实例检测
│   ├── angular-detect.js          # Angular 实例检测
│   ├── sourcemap-detect.js        # Source Map 文件探测 + 下载
│   └── page-inspect.js            # 页面结构检测辅助
├── popup/
│   ├── popup.html                 # Shell：头部 + 标签栏 + 状态栏，面板由 JS 加载
│   ├── panel-loader.js            # 并行加载 22 个面板 HTML 片段到 #app-main
│   ├── panels/                    # 面板 HTML 片段（22 个文件）
│   │   ├── encoding.html          # 编码工具 + 加密解密
│   │   ├── favicon-gather.html    # 图标识别 + 信息收集 + HaE 规则
│   │   ├── rules-modal.html       # HaE 规则弹窗
│   │   ├── asset.html             # 资产测绘
│   │   ├── links-multiurl.html    # 链接提取 + URL 多开
│   │   ├── history.html           # 历史档案
│   │   ├── exif.html              # EXIF 查看
│   │   ├── spoof.html             # 请求伪造
│   │   ├── vue.html               # Vue 分析
│   │   ├── jsctrl.html            # JS 控制
│   │   ├── payload.html           # Payload 工具
│   │   ├── xssscan.html           # XSS 扫描
│   │   ├── sourcemap.html         # Source Map 分析
│   │   ├── ruoyi.html             # RuoYi 路由
│   │   ├── waf.html               # WAF 检测
│   │   ├── cors.html              # CORS 检测
│   │   ├── subdomain.html         # 子域名枚举
│   │   ├── cookie-audit.html      # Cookie 审计
│   │   ├── react.html             # React 检测
│   │   ├── angular.html           # Angular 检测
│   │   ├── source-loader.html     # Source Loader
│   │   └── sniff.html             # 网站嗅探（技术指纹 + 泄露扫描）
│   │
│   ├── vk-namespace.js            # ES module 入口：全局工具函数 + utilsProxy
│   ├── vk-init.js                 # 应用入口，加载设置并调用初始化函数
│   ├── vk-init-panels.js          # 面板初始化（编码/资产/收集/EXIF/伪造/Payload/SourceMap/状态栏）
│   ├── vk-init-detectors.js       # 检测器初始化（Vue/JS控制/安全检测/网络工具/嗅探/状态恢复）
│   │
│   ├── vk-encoding.js             # 编码/解码
│   ├── vk-jwt.js                  # JWT 解析
│   ├── vk-crypto.js               # 加密解密（AES/DES/RC4/SM2/SM4/RSA/Bcrypt）
│   ├── vk-favicon.js              # 图标识别 + MurmurHash3
│   ├── vk-hae-rules.js            # HaE 安全规则管理
│   ├── vk-hae-default-rules.js    # HaE 默认规则数据（6 组 53 条）
│   ├── vk-gather.js               # 信息收集（API/域名/敏感信息/IP/注释）
│   ├── vk-asset.js                # 资产测绘（FOFA/ZoomEye/Shodan）
│   ├── vk-links.js                # 链接提取
│   ├── vk-multiurl.js             # URL 批量多开
│   ├── vk-tabsave.js              # 标签页保存
│   ├── vk-exif.js                 # EXIF 元数据查看
│   ├── vk-history.js              # Wayback Machine 历史快照
│   ├── vk-spoof.js                # 请求伪造（UA/Cookie/Header）
│   ├── vk-jsctrl.js               # JS 控制（开关/反调试/复制限制解除）
│   │
│   ├── vk-payload.js              # Payload 工具（XSS/SQLi/LFI/反弹Shell/WebShell/命令参考）
│   ├── vk-xss.js                  # XSS 扫描主模块（拦截/DOM Sink/反射验证）
│   ├── vk-xss-data.js             # XSS 扫描载荷、Sink 模式、严重性配置
│   ├── vk-xss-sinks.js            # DOM Sink 分析（document.write/innerHTML/src 等）
│   │
│   ├── vk-leak-rules.js           # 泄露扫描规则库（81 条源码规则 + 5 条 DOM 规则）
│   ├── vk-leakscan-scanner.js     # 泄露扫描引擎（validate 验证 + 上下文分析）
│   ├── vk-leak-render.js          # 泄露扫描结果渲染
│   ├── vk-sniff.js                # 网站嗅探 barrel（统一导出）
│   ├── vk-sniff-state.js          # 嗅探指纹数据库（97 项技术 / 19 个分类）
│   ├── vk-sniff-scanner.js        # 嗅探扫描引擎（DOM + Runtime + Header 信号采集）
│   ├── vk-sniff-render.js         # 嗅探结果渲染
│   │
│   ├── vk-sourcemap.js            # Source Map barrel（统一导出）
│   ├── vk-sourcemap-state.js      # Source Map 共享状态
│   ├── vk-sourcemap-phase1.js     # Phase 1: MAIN world Webpack 运行时检测
│   ├── vk-sourcemap-scanner.js    # Source Map 扫描主流程
│   ├── vk-sourcemap-render.js     # Source Map 模块列表渲染
│   ├── vk-sourcemap-utils.js      # Source Map 文件下载/解析工具
│   ├── vk-sourcemap-analysis.js   # Source Map API 端点/依赖分析
│   ├── vk-sourcemap-actions.js    # Source Map 批量操作（导出/下载/DevTools）
│   │
│   ├── vk-vue.js                  # Vue barrel（统一导出）
│   ├── vk-vue-state.js            # Vue 共享状态 + sub-tab 切换
│   ├── vk-vue-detect.js           # Vue 框架检测 + 路由守卫绕过 + 备份恢复 + 智能跳转
│   ├── vk-vue-perm.js             # Vue 权限菜单拦截 + 管理员提权
│   ├── vk-vue-perm-inject.js      # 权限菜单注入序列化函数
│   ├── vk-vue-compare.js          # 路由与菜单对比 + 隐藏路由发现
│   ├── vk-vue-jssearch.js         # JS 关键词搜索
│   ├── vk-vue-store.js            # Pinia/Vuex Store 探索器
│   │
│   ├── vk-ruoyi.js                # RuoYi barrel + 批量探测/路由管理
│   ├── vk-ruoyi-common.js         # RuoYi 公共工具
│   ├── vk-ruoyi-detect.js         # RuoYi 框架检测 + 自动捕获
│   ├── vk-ruoyi-hook.js           # RuoYi 路由钩子拦截 + API 流量
│   ├── vk-ruoyi-mar.js            # RuoYi MaR 动态路由发现
│   ├── vk-ruoyi-cve-db.js         # RuoYi CVE 数据库
│   │
│   ├── vk-waf.js                  # WAF 检测（特征识别 + 指纹匹配）
│   ├── vk-cors.js                 # CORS 配置扫描
│   ├── vk-subdomain.js            # 子域名枚举（页面提取/CRT/DNS 暴力枚举）
│   ├── vk-cookie-audit.js         # Cookie 安全审计
│   ├── vk-react.js                # React 框架检测
│   ├── vk-angular.js              # Angular 框架检测
│   ├── vk-source-loader.js        # Source Loader（源码加载到 DevTools Sources）
│   └── lib/                       # 第三方库（crypto-js, jsrsasign, sm2, sm4, bcrypt, exifr）
├── styles/
│   ├── popup/                     # Popup 样式（21 个文件，按模块拆分）
│   │   ├── base.css               # 全局样式、暗色变量、Toast、确认弹窗、无障碍
│   │   ├── favicon.css            # 图标识别
│   │   ├── info-gather.css        # 信息收集
│   │   ├── link-extract.css       # 链接提取
│   │   ├── asset-shodan.css       # 资产测绘
│   │   ├── history.css            # 历史档案
│   │   ├── ruoyi.css              # RuoYi 路由
│   │   ├── exif.css               # EXIF 查看
│   │   ├── request-spoofing.css   # 请求伪造
│   │   ├── vue-js-perm.css        # Vue 分析 + JS 控制
│   │   ├── perm-search-compare.css # 权限菜单 + 搜索 + 路由对比
│   │   ├── payload-xss.css        # Payload + XSS 扫描
│   │   ├── sourcemap-vue-store.css # Source Map + HaE + Vue Store
│   │   ├── waf.css                # WAF 检测
│   │   ├── cors.css               # CORS 检测
│   │   ├── subdomain.css          # 子域名枚举
│   │   ├── cookie-audit.css       # Cookie 审计
│   │   ├── react.css              # React 检测
│   │   ├── angular.css            # Angular 检测
│   │   ├── source-loader.css      # Source Loader
│   │   └── sniff.css              # 网站嗅探 + 泄露扫描
│   └── options.css                # 选项页样式
└── options/
    ├── options.html               # 选项页
    └── options.js                 # 选项页逻辑
```

---

## 安装

1. 打开 Chrome，地址栏输入 `chrome://extensions/`
2. 右上角开启「开发者模式」
3. 点击「加载已解压的扩展程序」，选择本项目目录
4. 安装完成后，点击浏览器右上角扩展图标即可使用

---

## 1. 编码工具

常用的编解码工具，支持 4 种格式：

| 格式 | 编码方向 | 解码方向 | 适用场景 |
|------|---------|---------|---------|
| Base64 | 文本 → Base64 字符串 | Base64 → 原始文本 | 解码 JWT、解码隐藏参数 |
| URL | 特殊字符 → `%XX` 编码 | `%XX` → 原始字符 | 构造/解码 URL 参数 |
| HTML | `<>&"'` → 实体编码 | 实体 → 原始字符 | XSS 测试时编解码 |
| Hex | 文本 → 十六进制 | 十六进制 → 文本 | 分析二进制数据、颜色值 |

### 加密解密

在编码工具中新增「加密解密」子标签，支持 7 种加密算法：

| 算法 | 类型 | 模式/参数 | 特点 |
|------|------|-----------|------|
| AES | 对称加密 | CBC/ECB/CTR/OFB/CFB，密钥 128/192/256 位，Pkcs7 填充 | 最常用对称加密 |
| DES | 对称加密 | CBC/ECB/CTR/OFB/CFB，密钥 8 字节 | 经典对称加密 |
| RC4 | 流密码 | 仅需密钥 | 简单流加密 |
| SM2 | 非对称（国密） | C1C3C2/C1C2C3 密文模式，支持生成密钥对 | 国密非对称加密 |
| SM4 | 对称加密（国密） | ECB/CBC，PKCS5 填充 | 国密对称加密 |
| RSA | 非对称加密 | RSA-OAEP，密钥 1024/2048/4096 位 | 标准非对称加密，异步生成密钥对不阻塞 UI |
| Bcrypt | 哈希（不可逆） | Cost factor 4-12 轮 | 密码哈希，不可解密，支持验证 |

**使用方法：**
1. 选择「加密解密」子标签
2. 在上方选择算法（AES / DES / RC4 / SM2 / SM4 / RSA / Bcrypt）
3. 根据算法填写密钥、IV 等参数
4. 在输入框输入明文/密文，点击「加密」或「解密」
5. 部分算法（SM2、RSA）需先「生成密钥对」

**依赖库：** crypto-js、sm-crypto、bcryptjs、jsrsasign（均已内置）

---

## 2. 图标识别

提取网站 Favicon 图标并计算 MurmurHash3 哈希值，一键在各大资产测绘平台搜索关联资产。

**使用方法：**
1. 输入目标网站 URL（或自动获取当前页面）
2. 点击识别，自动提取 Favicon 并计算 `icon_hash`
3. 显示 5 个平台的搜索链接，点击即可跳转：
   - **FOFA** — `icon_hash="-xxx"`
   - **ZoomEye** — `iconhash:"-xxx"`
   - **Shodan** — `http.favicon.hash:xxx`
   - **Censys** — 资产搜索
   - **Hunter** — 资产搜索

**用途：** 通过 Favicon 哈希快速找到使用相同框架/模板的其他站点，扩大攻击面。

---

## 3. 信息收集

一键提取当前页面源码中的敏感信息，分为 5 个类别：

| 类别 | 提取内容 |
|------|---------|
| API 接口 | 源码中 `/api/`、`/v1/`、`/v2/` 等接口路径 |
| 域名 | 页面中引用的所有外部域名 |
| 敏感信息 | 手机号、邮箱、身份证号、内网 IP |
| IP 地址 | 公网 IP 和内网 IP（10.x / 172.16-31.x / 192.168.x） |
| 注释内容 | HTML 注释 `<!-- -->` 中的开发者备注、TODO、敏感信息 |

### HaE 安全规则

集成 HaE（Hunt Executive）安全分析规则引擎，支持自定义规则管理和导入。

**内置规则（6 组 53 条）：**

| 分组 | 规则数 | 说明 |
|------|--------|------|
| Fingerprint | 7 | Shiro、JWT、Swagger UI、Ueditor、Druid、PDF.js、Vite DevMode |
| Maybe Vulnerability | 7 | Java 反序列化、调试参数、URL As Value、上传表单、DoS 参数、敏感文件 |
| Basic Information | 5 | 邮箱、身份证、手机号、内网 IP、MAC 地址 |
| Sensitive Information | 10 | 云厂商 Key、Windows 路径、密码字段、企微 Key、JDBC 连接、Authorization 头 |
| JS Sensitive Info | 15 | AWS/GitHub/Slack/Stripe/Google/Twilio/Azure 密钥、私钥、硬编码密码、JWT |
| Other | 8 | Linkfinder、Source Map、Router Push、所有 URL、302 Location、S3 密钥 |

- **规则管理** — 按分组启用/禁用规则，支持导入/导出/恢复默认
- **流量分析** — 实时拦截 XHR/Fetch 请求，匹配 HaE 规则高亮显示

---

## 4. 资产测绘

集成 FOFA、ZoomEye、Shodan 三大资产测绘平台，在插件内直接搜索。

**使用方法：**
1. 切换到对应平台标签（FOFA / ZoomEye / Shodan）
2. 输入你的 API Key（首次使用需要填入，自动保存）
3. 输入搜索语法（如 `domain="example.com"`）
4. 点击搜索，结果以表格形式展示（IP、端口、标题、协议等）

**提示：** 各平台 API Key 注册账号后在个人中心获取。

---

## 5. 链接提取

提取当前页面中所有链接资源，支持分类筛选。

**提取范围：**
- `<a href>` — 超链接
- `<script src>` — JS 文件
- `<link href>` — CSS/图标
- `<img src>` — 图片
- `<iframe src>` — 内嵌页面

**使用方法：**
1. 打开目标页面后点击插件
2. 选择要提取的链接类型
3. 支持关键词过滤和去重
4. 一键复制所有提取结果

---

## 6. URL 多开

批量打开 URL 列表，适合批量访问测试。

**功能：**
- **批量打开** — 文本框中粘贴 URL 列表（每行一个），一键在新标签页打开
- **去重** — 自动去除重复 URL
- **保存标签页** — 一键获取当前所有浏览器标签页 URL，支持复制和导出为 .txt 文件

**注意：** Chrome 可能会拦截批量弹窗，请在地址栏右侧允许弹窗。

---

## 7. 历史档案

查询目标网站在 Wayback Machine（Web Archive）中的历史快照。

**使用方法：**
1. 输入目标域名
2. 可设置匹配方式（域名+子域名 / 前缀匹配 / 精确匹配）
3. 可设置时间范围、输出格式、返回字段
4. 可按文件类型筛选（html / js / css / pdf 等）
5. 查询结果显示快照时间、URL、状态码、MIME 类型
6. 支持复制查询 URL 在浏览器直接打开

**用途：** 查看网站历史版本，发现已下线的敏感页面、旧版接口、泄露信息等。

---

## 8. EXIF 查看

查看图片的 EXIF 元数据，包括 GPS 定位、相机信息等。

**三种使用方式：**
- **输入 URL** — 输入图片地址直接查看
- **页面扫描** — 自动扫描当前页面所有 `<img>` 标签
- **拖拽上传** — 拖拽本地图片文件到面板

**显示的元数据：**

| 分组 | 字段 |
|------|------|
| 基本信息 | 文件名、大小、类型、宽、高 |
| 相机信息 | 品牌、型号、镜头、焦距、光圈、快门、ISO |
| GPS 信息 | 经纬度、海拔、Google Maps 链接 |

**用途：** 从上传的图片中提取 GPS 信息，定位拍摄地点。

---

## 9. 请求伪造

包含 3 个子功能：UA 切换、Cookie 管理、Header 伪造。

### 9.1 UA 切换

伪装浏览器的 User-Agent 标识。

**内置 19 种预设 UA：**
- Chrome / Firefox / Safari / Edge（Windows / Mac / Linux / Android / iOS）
- 搜索引擎爬虫：Googlebot、Bingbot
- 自定义 UA：手动输入任意 UA 字符串
- 恢复默认：一键还原浏览器原始 UA

**使用方法：** 在下拉列表选择预设 UA，或输入自定义 UA，点击应用即可。设置后所有请求都会携带新的 UA。

### 9.2 Cookie 管理

查看、编辑、删除当前站点的 Cookie。

**功能：**
- 列表显示所有 Cookie（名称、值、域名、路径、Secure、HttpOnly）
- 添加/编辑单个 Cookie
- 删除单个或全部 Cookie
- 导出 Cookie 为 JSON / 从 JSON 导入

### 9.3 Header 伪造

伪造 HTTP 请求头，绕过基于请求头做鉴权的服务端校验。

**常用伪造头：**
- `X-Forwarded-For` — 伪造来源 IP
- `X-Real-IP` — 伪造真实 IP
- `Referer` — 伪造来源页面
- `Client-IP` — 伪造客户端 IP

**使用方法：** 输入 Header 名称和值，点击添加。所有后续请求都会自动携带伪造的头。

---

## 10. Vue 分析

> **这是插件的核心功能**，专为渗透测试 Vue.js 管理后台设计，可以检测 Vue 应用、拦截权限菜单、发现隐藏路由、绕过权限控制。

### 整体思路

很多后台管理系统使用 Vue + 路由守卫控制菜单显示。前端路由表中定义了所有页面路径，但后端只返回当前用户有权限看到的菜单项。通过以下步骤可以发现并访问没有权限的页面：

```
检测 Vue → 拦截菜单 API → 分析权限数据 → 对比路由差异 → 修改菜单数据 → 访问隐藏页面
```

### 10.1 基础检测

检测当前页面是否为 Vue 应用，获取框架版本和核心实例信息。

**检测内容：**
- **Vue 版本** — 自动识别 Vue 2 或 Vue 3
- **Router 实例** — 是否使用了 Vue Router，获取路由表
- **Store 实例** — 是否使用了 Vuex 或 Pinia 状态管理
- **路由列表** — 导出所有路由路径（包括动态添加的 `router.addRoute()` 路由）
- **路由元信息** — 显示 `meta.roles`、`meta.permissions`、`meta.hidden` 等权限相关字段
- **守卫统计** — 显示 `beforeGuards`、`afterGuards`、`beforeResolveGuards` 各自数量（Vue 2/3 双适配）
- **权限标记** — 每条路由标注认证要求（`requiresAuth` 等正则匹配 17 种 key）、`beforeEnter` 钩子、敏感路径

**相关按钮：**

| 按钮 | 功能 |
|------|------|
| **检测 Vue** | 执行检测 |
| **导出路由** | 复制所有路由路径到剪贴板 |
| **绕过路由守卫** | 清除全局导航守卫（操作前自动备份） |
| **关闭 Auth** | 将所有路由的认证标记设为 `false`（操作前自动备份） |
| **恢复备份** | 一键还原守卫和认证标记到备份状态 |
| **路由搜索** | 实时搜索过滤路由树（按 path/name 匹配，200ms 防抖） |
| **一键跳转** | 临时绕过守卫 + 关闭 Auth → router.push 导航 → 3 秒后自动恢复 |

### 10.2 权限菜单（核心功能）

拦截页面中权限/菜单相关的 API 响应，分析并修改菜单数据，实现「上帝视角」。

#### 第一步：拦截 API

**使用方法：**
1. 切换到「权限菜单」标签
2. 点击「开始拦截」
3. **刷新目标页面**（拦截器需要在页面加载时注入才能捕获 API 响应）
4. 页面加载完成后，捕获到的菜单/权限 API 会自动显示在列表中

#### 第二步：分析数据

**自动分类：**
- **全开放** — 所有菜单项都已返回，无隐藏
- **半开放** — 部分菜单可见，部分被隐藏
- **特殊0开放** — 返回空数组 `[]`，但路由中实际定义了页面
- **其他** — 非菜单类响应

#### 第三步：修改数据

| 按钮 | 功能 | 适用场景 |
|------|------|---------|
| **全部显示** | 将所有 `hidden: true` 改为 `false` | 菜单数据中所有项都存在但有隐藏标记 |
| **提权至管理员** | 将 `isAdmin`/`role` 等字段改为管理员值 | 响应中包含角色/管理员字段 |
| **展开 menuIds** | 收集所有菜单 ID 并展开为完整 ID 列表 | 使用数字 ID 控制菜单权限的系统 |
| **应用修改** | 将修改后的数据注入到页面（Vuex/Pinia + localStorage） | 所有修改完成后点击此按钮生效 |

#### 第四步：应用修改

点击「应用修改」后，插件会将修改后的菜单数据写入 Vuex/Pinia Store 并同步更新 localStorage。

### 10.3 JS 搜索

在页面的所有 JS 文件（包括内联和外部引用）中搜索关键词。

**预设关键词：** `menu`、`permission`、`menuList`、`routes`、`isAdmin`、`role`、`menuIds`

### 10.4 路由对比

对比 Vue Router 中定义的路由和实际显示的菜单，发现隐藏路由。

- **复制隐藏路由** — 将所有隐藏路由路径复制到剪贴板
- **一键补全到菜单** — 自动将所有隐藏路由注入到菜单数据中

#### 自动遍历（配合 Burpsuite 抓包）

自动逐个通过 `$router.push()` 访问路由，配合 Burpsuite 抓包检测未授权访问。对参数化路由（`:id`）自动生成探测 URL。

### 10.5 Store 探索器

探测并展示 Vue 应用中 Pinia/Vuex Store 的数据结构。

**功能：**
- 自动发现所有 Store 模块
- 展示每个模块的 State 数据
- 复制完整 Store JSON

---

## 11. JS 控制

### 11.1 JS 开关

禁用/恢复页面的 JavaScript 执行。

### 11.2 反调试绕过

检测页面是否使用了反调试技术，并提供一键绕过。

| 反调试技术 | 检测方式 |
|-----------|---------|
| 无限 `debugger` | 扫描 JS 中的 `debugger` 语句和定时器 |
| 控制台劫持 | 检测 `console.log` 等方法是否被覆盖 |
| 时间差检测 | 检测 `Date.now()` / `performance.now()` 定时检测 |
| DevTools 检测 | 检测基于窗口大小差的开发者工具检测 |

### 11.3 复制限制解除

一键解除网页中的复制、选中文本、右键菜单等限制。

| 防护类型 | 处理方式 |
|---------|---------|
| `user-select: none` | 移除所有元素的 CSS 属性 |
| `oncopy / oncut / onpaste` | 移除内联事件拦截 |
| `oncontextmenu` | 注册 capture 拦截器阻止默认行为 |
| `onselectstart` | 注册 capture 拦截器阻止默认行为 |
| `pointer-events: none` 遮罩层 | 隐藏透明遮罩层 |
| `-webkit-user-drag: none` | 解除拖拽限制 |

---

## 12. Payload 工具

渗透测试常用 Payload 和命令速查工具，包含 6 个分类，参考 HackTools 项目。

### 12.1 XSS Payloads

6 个分类，共 31 个 Payload，点击即可复制：

| 分类 | Payload 数 | 说明 |
|------|----------|------|
| Cookie 窃取 | 4 | 通过 Image/Audio/fetch 窃取 Cookie 到攻击者服务器 |
| 基础 XSS | 4 | `<script>` / `<img onerror>` / `<svg onload>` 等 |
| Img 标签 | 8 | 基于 `<img>` 的多种 XSS 向量 |
| Markdown 注入 | 4 | Markdown 语法中的 XSS 注入 |
| SVG 注入 | 4 | 基于 `<svg>` 的 XSS 向量 |
| 绕过黑名单 | 7 | Base64 编码、字符串拼接等方式绕过关键字过滤 |

### 12.2 SQL 注入

9 个分类，支持自定义列数和表名：

| 分类 | 说明 |
|------|------|
| 列数探测 | `ORDER BY N` 逐步探测列数 |
| 版本枚举 | `@@version`、`version()` |
| 表名枚举 | `information_schema.tables` |
| 列名枚举 | `information_schema.columns` |
| 数据提取 | `GROUP_CONCAT` 提取数据 |
| 报错注入 | `EXTRACTVALUE`、`UPDATEXML`、`CAST` |
| 延时注入 | `SLEEP(5)`、`WAITFOR DELAY` |
| 认证绕过 | `OR 1=1`、`admin'--` |

### 12.3 LFI / RFI

目录遍历、PHP Wrapper、常用敏感文件路径：

- **目录遍历** — `../../../../etc/passwd`
- **PHP Wrapper** — `php://filter`、`php://input`、`data://` 协议
- **Linux 敏感文件** — `/etc/passwd`、`/etc/shadow`、SSH 密钥、K8s Token
- **Apache 配置** — 配置文件、访问/错误日志
- **Windows 敏感文件** — `boot.ini`、`hosts`、`SAM`

### 12.4 反弹 Shell

支持 19 种语言的反弹 Shell 模板，可自定义 IP 和端口：

Bash、Netcat、Ncat、Python、Python3、Perl、PHP、Ruby、PowerShell、PowerShell TLS、Node.js、Java、Socat、Telnet、Zsh、Lua、Golang、Awk、Dart

**使用方法：**
1. 选择 Shell 类型
2. 输入监听 IP 和端口
3. 点击「生成命令」，一键复制生成的命令

### 12.5 Web Shell

PHP 一句话木马和混淆 WebShell：

- **基础一句话** — `@eval`、`system`、`passthru`、`shell_exec`
- **混淆一句话** — 短标签调用、变量拼接、`assert`
- **图片马** — GIF 头 + PHP 代码
- **绕过 disable_functions** — LD_PRELOAD + mail 技术

### 12.6 常用命令

| 分类 | 命令数 |
|------|--------|
| Linux SUID 提权 | 4 |
| 系统版本信息 | 5 |
| 环境变量 | 5 |
| Cron 任务 | 6 |
| 端口转发 | 5 |
| TTY Shell 升级 | 7 |
| PowerShell 系统枚举 | 5 |
| PowerShell 补丁/网络/下载/WLAN | 16 |
| 通配符提权 | 2 |

---

## 13. XSS 扫描

自动化 XSS 漏洞检测工具，支持反射型 XSS 发现和 DOM Sink 分析。

### 13.1 反射型 XSS 检测

**工作流程：**
1. **参数采集** — 从 DOM（链接/表单/URL 参数）+ AJAX 拦截（XHR/Fetch Hook，30 秒倒计时）收集输入点
2. **载荷注入** — 选择载荷后对每个输入点注入
3. **反射验证** — 逐个注入载荷并检查是否在响应中反射，分析反射上下文（script 标签 / HTML 属性 / 标签注入 / 纯文本）
4. **结果筛选** — 支持按来源（link/form/url/ajax）和关键词过滤

**功能：**
- **DOM 采集** — 提取页面中所有链接参数、表单字段、URL Query String
- **AJAX 拦截** — Hook XHR.open/send 和 window.fetch，捕获动态提交的参数（JSON body 自动提取 `parent.child` 格式）
- **批量验证** — 逐个发送载荷并检测反射，自动分析反射上下文
- **批量打开** — GET 参数新标签页打开，POST 参数自动创建隐藏表单提交
- **载荷编码** — 支持原始 / URL 编码 / HTML 实体 / Base64 四种编码方式
- **导出** — 导出检测结果为 CSV

### 13.2 DOM Sink 分析

分析页面中危险的 DOM Sink 点，发现潜在的 DOM XSS。

**检测范围：**
- 内联 `<script>` 标签
- 外部 JS 文件
- 事件处理器属性（`onclick`、`onerror`、`onload` 等）
- `javascript:` 伪协议链接

**检测的 Sink 类型：**

| Sink | 危险等级 | 说明 |
|------|---------|------|
| `document.write()` | 高 | 直接写入 HTML |
| `innerHTML` | 高 | 解析 HTML 内容 |
| `outerHTML` | 高 | 替换元素 HTML |
| `eval()` | 高 | 执行任意代码 |
| `setTimeout(string)` | 高 | 延迟执行代码 |
| `setInterval(string)` | 高 | 定时执行代码 |
| `Function()` | 高 | 动态创建函数 |
| `location` 赋值 | 中 | URL 跳转 |
| `src`/`href` 赋值 | 中 | 资源加载 |

**评分机制：** 每个 Sink 根据来源（内联/外部/事件处理器）和是否存在安全过滤（DOMPurify、escape 等）计算风险分值（1-10），自动降分已知净化器。

**使用方法：** 点击「分析 DOM 汇点」扫描当前页面中的所有危险 Sink。

---

## 14. Source Map 分析

分析 Webpack 打包的前端应用，提取源码映射、模块列表和 API 端点。

### 14.1 Webpack 模块扫描

**扫描流程：**
1. **Phase 1** — 在 MAIN world 检测 Webpack 运行时，捕获模块缓存
2. **Phase 2** — 尝试获取各模块的源代码
3. **Phase 3** — 尝试加载 `.map` 文件获取原始源码

**检测结果：**
- 模块 ID 和路径
- 模块依赖关系
- 模块源代码（如果可获取）
- Source Map 状态

### 14.2 API 端点发现

从模块源码中自动提取 API 端点路径。

**提取规则：**
- `fetch('/api/...')` 调用
- `axios.get/post/put/delete('/api/...')` 调用
- `request({ url: '/api/...' })` 调用
- 字符串中的 URL 模式

### 14.3 安全发现

基于泄露规则库扫描模块源码，发现硬编码密钥、加密漏洞、PII 泄露等问题（复用泄露扫描的 81 条规则）。

### 14.4 批量操作

- **复制路径** — 复制所有模块路径
- **生成树** — 生成模块依赖树
- **加载到 DevTools** — 将源码加载到 Chrome DevTools Sources 面板
- **下载全部** — 批量下载所有模块源码
- **导出 JSON/CSV** — 导出模块列表

---

## 15. RuoYi 路由

RuoYi 后台管理系统的路由分析与权限测试工具。发现被权限系统隐藏的菜单和接口。

### 15.1 框架检测

检测当前页面是否使用 RuoYi 框架，识别版本号和变体。

**识别的 RuoYi 变体：**

| 变体 | 特征 |
|------|------|
| Vue2 前后端分离 | Element UI + Vue Router + Vuex |
| Vue3 | Element Plus + Vue 3 + Pinia |
| Thymeleaf 模板 | jQuery + Bootstrap + 服务端渲染 |
| 微服务 | Spring Cloud + Gateway + Nacos |
| App | uni-app 移动端 |

**检测特征：**
- 脚本文件名（request.js、auth.js、permission.js）
- 页面布局结构（sidebar-container、app-container）
- 全局对象（`__CONFIG__`、`__APP_BASE_API__`）
- Cookie Token（Admin-Token）
- Element UI/Plus 版本
- 云原生组件（Gateway、Nacos、Sentinel）

### 15.2 路由钩子拦截

注入路由钩子到目标页面，拦截动态路由加载过程。

**工作流程：**
1. 点击「安装钩子」注入拦截脚本
2. 刷新页面，拦截器自动捕获 `router.addRoutes()` 调用
3. 捕获的路由数据实时显示在面板中
4. 可查看每个路由的完整路径、组件、权限配置

**增强模式：**
- **标准模式** — 仅捕获路由数据
- **增强模式** — 额外拦截 API 请求，捕获更多路由信息

### 15.3 动态路由发现

通过分析 JS 文件发现可能存在的动态路由。

**功能：**
- **JS 分析** — 扫描页面 JS 文件中的路由定义模式
- **应用路由** — 将发现的路由添加到路由表中
- **全选/复制** — 批量选择和复制路由路径

### 15.4 批量探测

对发现的路由进行批量 HTTP 请求探测。

**功能：**
- **自定义并发数** — 控制同时发送的请求数量
- **HTTP 方法选择** — GET / POST / PUT / DELETE
- **状态码过滤** — 按响应状态码筛选结果
- **导出** — 导出探测结果（cURL 命令 / HTML 报告）

### 15.5 API 流量查看

查看 RuoYi 钩子拦截到的 API 流量。

### 15.6 CVE 查询

内置 RuoYi 相关 CVE 漏洞数据库，支持按版本号查询。

---

## 16. WAF 检测

检测目标网站是否部署了 Web 应用防火墙（WAF）。

**检测原理：** 发送带有特定攻击特征的请求，根据响应状态码、响应体特征判断 WAF 类型。

**支持的 WAF 指纹：**

| WAF | 厂商 |
|-----|------|
| 云 WAF | 阿里云 WAF、腾讯云 WAF、华为云 WAF |
| 国外 WAF | Cloudflare、AWS WAF、Akamai |
| 硬件 WAF | Imperva、F5 BIG-IP |
| 开源 WAF | ModSecurity、NAXSI |

**功能：**
- 一键扫描
- 按状态筛选（已识别/未拦截/异常）
- 搜索结果
- 复制/导出结果

---

## 17. Cookie 审计

审计当前网站 Cookie 的安全性。

**检查项：**

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| `Secure` 缺失 | Cookie 可通过 HTTP 传输 | 高 |
| `HttpOnly` 缺失 | Cookie 可被 JavaScript 读取（XSS 窃取） | 高 |
| `SameSite` 缺失/宽松 | Cookie 可在跨站请求中发送（CSRF） | 中 |
| `Path` 过宽 | Cookie 在过多路径下可访问 | 低 |
| `Domain` 过宽 | Cookie 在子域名间共享 | 低 |
| 敏感名称 | Session ID / Token 等敏感 Cookie 未充分保护 | 高 |

**功能：**
- 一键审计
- 按严重程度筛选
- 搜索结果
- 复制/导出结果

---

## 18. CORS 检测

扫描目标网站 API 的 CORS（跨域资源共享）配置。

**检测内容：**
- `Access-Control-Allow-Origin` — 允许的源
- `Access-Control-Allow-Credentials` — 是否允许携带凭证
- `Access-Control-Allow-Methods` — 允许的方法
- `Access-Control-Allow-Headers` — 允许的请求头

**安全风险：**
- `Allow-Origin: *` + `Allow-Credentials: true` — 高危配置
- `Allow-Origin` 包含不可信源 — 可能导致数据泄露
- `Reflect Origin` — 反射任意 Origin

**功能：**
- 一键扫描当前页面引用的 API
- 按严重程度筛选
- 搜索结果
- 导出 JSON

---

## 19. 子域名枚举

收集目标域名的子域名信息。

**收集方式：**

| 方式 | 说明 |
|------|------|
| 页面提取 | 从当前页面源码中提取域名和链接 |
| CRT 证书 | 查询证书透明度日志 |
| DNS 暴力枚举 | 尝试常见子域名前缀 |

**功能：**
- 按来源筛选
- 搜索结果
- 复制/导出结果

---

## 20. React/Angular 检测

检测目标页面是否使用 React 或 Angular 框架。

### React 检测

- **框架版本** — 识别 React 版本号
- **构建工具** — 识别 Create React App / Next.js / Vite 等
- **路由信息** — 如果使用 React Router，提取路由配置
- **Store 信息** — 如果使用 Redux/Context，展示 Store 结构

### Angular 检测

- **框架版本** — 识别 Angular 版本号
- **组件信息** — 提取页面中的 Angular 组件
- **路由信息** — 提取路由配置
- **Service 信息** — 发现注入的 Service

**功能：** 检测、复制结果、导出 JSON

---

## 21. Source Loader

将外部 JS 源码加载到 Chrome DevTools Sources 面板，方便调试和分析。

**使用方法：**
1. 在输入框中粘贴 JS 文件的 URL 列表
2. 点击「加载」，文件会出现在 DevTools Sources 面板的特殊目录中
3. 在 DevTools 中可直接设置断点调试

**用途：** 分析混淆的 JS 代码、调试第三方库、查看动态加载的脚本。

---

## 22. 网站嗅探

识别网站技术栈和敏感信息泄露，分为 2 个子标签。

### 22.1 技术指纹

识别网站使用的全部技术栈，覆盖 19 个分类、97 项技术。

**信号采集：**
- **DOM 信号** — meta 标签、body HTML、script src 属性
- **Runtime 信号** — JS 全局变量、版本号、Cookie、CSS 类名、元素 ID
- **Header 信号** — HTTP 响应头（通过 Background Service Worker 获取）

**技术分类：**

| 分类 | 示例技术 |
|------|---------|
| CMS | WordPress、Drupal、Joomla、DedeCMS |
| Web 服务器 | Nginx、Apache、IIS、OpenResty |
| 框架 | Laravel、Django、Express、Spring Boot |
| CDN | Cloudflare、阿里云 CDN、腾讯云 CDN、Fastly |
| JS 框架 | Vue、React、Angular、Svelte、jQuery |
| JS 库 | Bootstrap、Tailwind、Lodash、Axios、Chart.js |
| UI 框架 | Element UI/Plus、Ant Design、Vuetify |
| 分析 | 百度统计、Google Analytics、CNZZ |
| 地图 | 高德地图、百度地图、腾讯地图、Google Maps |
| 富文本编辑器 | TinyMCE、CKEditor、Quill、WangEditor |
| 图表库 | ECharts、Chart.js、D3.js、AntV |
| 加密库 | CryptoJS、jsrsasign、sm-crypto |
| 监控 | Sentry、Datadog、New Relic |
| 构建工具 | Vite、Webpack、Rollup |
| 社交 SDK | 微信 JS-SDK、支付宝 JSAPI、Facebook SDK |
| 移动框架 | uni-app、Capacitor、Cordova |
| 云服务 | 阿里云 OSS/COS、腾讯云 COS、AWS S3 |
| 安全头 | CSP、X-Frame-Options、HSTS |
| 其他 | Shiro、Swagger UI、Druid、PDF.js |

**功能：**
- 分类过滤按钮，快速定位
- 点击技术标签展开查看证据详情（来源 + 匹配文本）
- 一键复制/导出 JSON

### 22.2 泄露扫描

深度扫描页面 JS 源码和 DOM，发现敏感信息泄露。基于 AegisScope 规则库，共 86 条规则。

**规则分类：**

| 分类 | 规则数 | 检测内容 |
|------|--------|---------|
| 密钥凭证 (secret) | ~48 | AWS/GCP/Azure/Stripe/Slack/Twilio/Google 等云平台 API Key、JWT、PEM 私钥、Session Token、数据库连接串 |
| 加密漏洞 (crypto-vuln) | ~11 | AES ECB 模式、硬编码密钥/IV、MD5/SHA1 弱哈希、DES/RC4 弱算法、RSA PKCS#1v15、Math.random 不安全随机、alg=none |
| 硬编码凭证 (hardcode) | 2 | 硬编码管理员账号、硬编码密码 |
| 个人信息 (pii) | 3 | 中国身份证号、银行卡号（含 Luhn 校验）、手机号 |
| 信息暴露 (exposure) | ~17 | 内网 IP、内网域名、Source Map 引用、.git 暴露、debugger 残留、console.log 残留、CORS 通配符、CSP unsafe、eval/innerHTML、localStorage 密钥、Swagger 端点、Spring Actuator、备份文件、环境变量引用 |

**规则特性：**
- **Shannon 熵分析** — 检测 Base64 字符串是否为真实密钥而非占位符
- **上下文感知验证** — 检测密钥附近 ±300 字符是否出现加密 API 调用（`crypto`、`createCipher` 等），减少误报
- **动态严重性调整** — validate 函数可根据上下文提升/降低严重性和置信度
- **DOM 规则** — 额外 5 条 DOM 检测规则（HTML 注释中的密钥、邮箱泄露、隐藏表单字段、data-* 属性、srcdoc）

**功能：**
- 一键深度扫描
- 严重性摘要（严重/高危/中危/低危/信息统计）
- 按分类过滤
- 展开查看详情（描述、利用方式、修复建议、完整值）
- 一键复制/导出 JSON

---

## 权限说明

| 权限 | 用途 |
|------|------|
| activeTab | 访问当前标签页内容 |
| storage | 保存用户配置和缓存数据 |
| scripting | 注入脚本到页面（Vue 分析、JS 控制、Source Map 等核心功能） |
| contextMenus | 右键菜单快捷操作 |
| declarativeNetRequestWithHostAccess | 修改请求头（UA / Referer / 自定义 Header） |
| cookies | 读取和修改 Cookie |
| downloads | 下载文件（Source Map 源码、导出报告等） |
| host_permissions: `<all_urls>` | 访问所有网站的内容（嗅探、检测、注入等） |

---

## 常见问题

**Q: 插件安装后点击图标没有反应？**
A: 请确认已开启「开发者模式」，并且选择的目录包含 `manifest.json` 文件。

**Q: Vue 分析检测不到 Vue？**
A: 确保目标页面确实是 Vue 应用（查看页面源码是否有 `__vue__` 或 `data-v-` 属性）。部分 SPA 应用需要在页面完全加载后再检测。

**Q: 权限菜单拦截不到数据？**
A: 必须在点击「开始拦截」后 **刷新页面**，拦截器需要在页面加载时注入才能捕获初始化时的 API 请求。

**Q: 应用修改后页面没有变化？**
A: 尝试手动刷新页面。如果仍然无效，可能是应用使用了不同的状态管理方式，可在 JS 搜索中搜索 `store` 或 `commit` 了解应用的 Store 结构。

**Q: 自动遍历时页面跳转报错？**
A: 部分路由可能需要特定参数（如 `/user/:id`），这类动态路由会自动生成探测 URL（`:id` → `1`），属于正常现象。

**Q: 「一键跳转」没有反应？**
A: 确保目标页面是 Vue 应用且 Router 已初始化。跳转操作会临时绕过守卫并在 3 秒后自动恢复，如果路由路径不存在会 fallback 到 URL 跳转。

**Q: RSA 生成密钥对时卡住？**
A: RSA 使用浏览器原生 `crypto.subtle` API（异步），不会阻塞 UI。生成大位数密钥（4096 位）可能需要几秒钟，按钮会显示「生成中...」。

**Q: Burpsuite 如何配合自动遍历？**
A: 先在 Burpsuite 中配置好代理，浏览器通过代理访问目标站点。点击「自动遍历」后，所有路由请求都会经过 Burpsuite，在 HTTP History 中逐条检查响应内容即可。

**Q: RuoYi 检测出错？**
A: 确保当前标签页是普通 HTTP/HTTPS 网页。Chrome 内置页面（`chrome://`、`chrome-extension://`）不允许注入脚本。

**Q: Source Map 扫描不到模块？**
A: 部分应用可能不使用 Webpack，或使用了自定义的模块加载方式。Vue CLI / Create React App 等脚手架项目通常有 Source Map。

**Q: WAF 检测结果不准确？**
A: WAF 检测基于特征匹配，可能存在误报。建议结合 Burpsuite 手动验证。

**Q: 泄露扫描误报太多？**
A: 泄露扫描已内置 Shannon 熵分析和上下文验证来减少误报。对于特定的误报项，可以点击展开查看详情判断。规则库持续优化中。

**Q: 网站嗅探检测不到某些技术？**
A: 嗅探依赖页面可见的 DOM 信号、全局变量和 HTTP 响应头。某些技术可能在后端渲染、CDN 层面实现，前端无法直接检测。
