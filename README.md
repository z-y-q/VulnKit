# VulnKit

Chrome 渗透测试辅助工具包，集成常见安全测试功能于一体。

## 功能

- **编码工具** — Base64 / URL / HTML / Hex 编解码，SHA-256 / SHA-1 / SHA-512 / MD5 哈希生成
- **Favicon 识别** — 提取网站图标并计算 Favicon Hash，用于资产测绘关联
- **信息收集** — 一键提取当前页面的接口地址、域名、敏感信息（Token/邮箱/Cookie）、内网 IP
- **资产测绘** — 集成 FOFA / ZoomEye / Shodan 进行子域名和资产搜索
- **链接提取** — 提取页面中所有链接、图片、脚本地址，支持关键词筛选
- **URL 多开** — 批量打开 URL 列表，支持前缀/后缀追加
- **EXIF 查看** — 查看图片 EXIF 元数据（GPS/相机/时间等）
- **Cookie 管理** — 查看、编辑、删除当前站点 Cookie
- **安全头分析** — 检测响应头安全配置（CSP / HSTS / X-Frame 等）
- **历史档案** — 查询站点在 Web Archive 的历史快照
- **Vue 分析** — 检测 Vue 应用、导出路由、绕过路由守卫、拦截权限菜单、JS 关键字搜索、路由对比
- **JS 控制** — 禁用/恢复页面 JavaScript
- **UA 伪装** — 自定义 User-Agent 请求头
- **Header 伪造** — 伪造 X-Forwarded-For / Referer / Client-IP 等请求头
- **反调试检测** — 检测页面反调试手段并提供绕过方案

## 安装

1. 打开 Chrome，进入 `chrome://extensions/`
2. 开启「开发者模式」
3. 点击「加载已解压的扩展程序」，选择本项目目录

## 权限说明

| 权限 | 用途 |
|------|------|
| activeTab | 访问当前标签页内容 |
| storage | 保存用户配置和缓存数据 |
| scripting | 注入脚本到页面 |
| contextMenus | 右键菜单 |
| declarativeNetRequest | 修改请求头（UA/Referer 等） |
| cookies | 读取和修改 Cookie |
