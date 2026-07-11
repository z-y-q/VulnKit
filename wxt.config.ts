import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-svelte', '@wxt-dev/unocss'],
  manifest: {
    name: '灵眸',
    description: '灵眸 - 编码解码、图标识别、资产测绘、信息收集、权限分析',
    version: '6.0.0',
    permissions: [
      'activeTab',
      'storage',
      'scripting',
      'contextMenus',
      'declarativeNetRequestWithHostAccess',
      'cookies',
      'downloads',
      'sidePanel',
    ],
    host_permissions: ['<all_urls>'],
    action: {
      default_title: '灵眸 - 漏洞工具包',
    },
    side_panel: {
      default_path: 'side-panel.html',
    },
    // MAIN world 注入脚本需对页面可访问（由 src/inject/*.ts 转译至 public/inject/*.js）
    web_accessible_resources: [
      {
        resources: ['inject/*.js'],
        matches: ['<all_urls>'],
      },
    ],
    content_security_policy: {
      extension_pages: "script-src 'self'; connect-src *; object-src 'self';",
    },
  },
});
