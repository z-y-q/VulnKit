import { defineConfig } from 'wxt';
import { readFileSync } from 'node:fs';

// 版本号单一来源（§10.1）：从 package.json 读取，避免 manifest 与 package 两处人工同步
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as { version: string };

// See https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-svelte', '@wxt-dev/unocss'],
  manifest: {
    name: '灵眸',
    description: '灵眸 - 编码解码、图标识别、资产测绘、信息收集、权限分析',
    version: pkg.version,
    // 权限矩阵详见 docs/权限矩阵.md；每项权限必须有功能与调用位置佐证。
    // 历史曾含 'downloads'，但所有下载均走 <a download> + blob URL（无需该权限），已移除。
    permissions: [
      'activeTab',
      'tabs',
      'storage',
      'scripting',
      'contextMenus',
      'declarativeNetRequestWithHostAccess',
      'cookies',
      'sidePanel',
    ],
    // host_permissions: 工具需对用户当前任意目标站点读写（content script 注入、cookies、DNR 改写）。
    // activeTab 仅覆盖「点扩展后的当前 tab」；cookie 审计/JS 归档/框架分析需在用户未点图标时
    // 也能访问页面，故保留 <all_urls>。详见 docs/权限矩阵.md。
    host_permissions: ['<all_urls>'],
    action: {
      default_title: '灵眸 - 漏洞工具包',
    },
    side_panel: {
      default_path: 'side-panel.html',
    },
    // MAIN world 注入脚本需对页面可访问（由 src/inject/*.ts 转译至 public/inject/*.js）。
    // matches 必须为 <all_urls>：注入脚本要在用户分析的任意目标页加载，
    // 且已通过 token + origin/source 校验限制可接收的回执（见 bridge.content.ts）。
    web_accessible_resources: [
      {
        resources: ['inject/*.js'],
        matches: ['<all_urls>'],
      },
    ],
    // connect-src *：面板不直接 fetch 目标（全部走 background 代理 + url-guard SSRF 防护），
    // 此宽放仅为兼容资产测绘/外链平台等少量直接打开的外部资源；后续可按需收紧到具体域集合。
    content_security_policy: {
      extension_pages: "script-src 'self'; connect-src *; object-src 'self';",
    },
  },
});
