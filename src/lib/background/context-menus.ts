// 灵眸 v6.0 — 右键菜单
// 页面/选区/链接三类上下文菜单，选区支持编解码与哈希（结果复制到剪贴板并 toast）。

import { md5String } from '@/lib/core/md5';
import type { Browser } from 'wxt/browser';

interface MenuSpec {
  id: string;
  title: string;
  contexts: string[];
  parentId?: string;
}

const PAGE_PARENT = 'vulnkit-page';
const SELECTION_PARENT = 'vulnkit-selection';
const LINK_PARENT = 'vulnkit-link';

const MENUS: MenuSpec[] = [
  // 页面上下文
  { id: PAGE_PARENT, title: '灵眸', contexts: ['page'] },
  { id: 'vulnkit-extract-links', parentId: PAGE_PARENT, title: '提取链接', contexts: ['page'] },
  { id: 'vulnkit-cors-scan', parentId: PAGE_PARENT, title: 'CORS 检测', contexts: ['page'] },
  { id: 'vulnkit-waf-scan', parentId: PAGE_PARENT, title: 'WAF 指纹', contexts: ['page'] },
  { id: 'vulnkit-headers-scan', parentId: PAGE_PARENT, title: '安全头分析', contexts: ['page'] },
  { id: 'vulnkit-subdomain-scan', parentId: PAGE_PARENT, title: '子域名收集', contexts: ['page'] },
  // 选区上下文
  { id: SELECTION_PARENT, title: '灵眸', contexts: ['selection'] },
  { id: 'vulnkit-encode', parentId: SELECTION_PARENT, title: 'URL 编码', contexts: ['selection'] },
  { id: 'vulnkit-decode', parentId: SELECTION_PARENT, title: 'URL 解码', contexts: ['selection'] },
  { id: 'vulnkit-base64-encode', parentId: SELECTION_PARENT, title: 'Base64 编码', contexts: ['selection'] },
  { id: 'vulnkit-base64-decode', parentId: SELECTION_PARENT, title: 'Base64 解码', contexts: ['selection'] },
  { id: 'vulnkit-md5-hash', parentId: SELECTION_PARENT, title: 'MD5 哈希', contexts: ['selection'] },
  { id: 'vulnkit-sha256-hash', parentId: SELECTION_PARENT, title: 'SHA256 哈希', contexts: ['selection'] },
  // 链接上下文
  { id: LINK_PARENT, title: '灵眸', contexts: ['link'] },
  { id: 'vulnkit-link-cors', parentId: LINK_PARENT, title: '发送到 CORS 检测', contexts: ['link'] },
  { id: 'vulnkit-link-headers', parentId: LINK_PARENT, title: '发送到安全头分析', contexts: ['link'] },
  { id: 'vulnkit-link-redirect', parentId: LINK_PARENT, title: '发送到重定向检测', contexts: ['link'] },
];

/** 根据设置创建全部右键菜单（enableContextMenu !== false 时启用）。 */
export async function createContextMenus(): Promise<void> {
  const result = await browser.storage.local.get(['pentestSettings']);
  const settings = (result.pentestSettings || {}) as { enableContextMenu?: boolean };
  await browser.contextMenus.removeAll().catch(() => {});
  if (settings.enableContextMenu === false) return;
  for (const m of MENUS) {
    browser.contextMenus.create({
      id: m.id,
      parentId: m.parentId,
      title: m.title,
      contexts: m.contexts as any,
    });
  }
}

// ====== 页面 toast（注入到目标 tab）======
async function showToast(tabId: number, message: string, ok: boolean): Promise<void> {
  const bg = ok ? '#4CAF50' : '#F44336';
  await browser.scripting
    .executeScript({
      target: { tabId },
      func: (msg: string, color: string) => {
        const el = document.createElement('div');
        el.textContent = msg;
        el.style.cssText = `position:fixed;top:12px;right:12px;z-index:999999;background:${color};color:#fff;padding:8px 16px;border-radius:6px;font-size:13px;opacity:0;transition:opacity .3s`;
        document.body.appendChild(el);
        requestAnimationFrame(() => {
          el.style.opacity = '1';
        });
        setTimeout(() => {
          el.style.opacity = '0';
          setTimeout(() => el.remove(), 300);
        }, 1500);
      },
      args: [message, bg],
    })
    .catch(() => {});
}

async function copyAndToast(tabId: number, text: string, message: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    await showToast(tabId, message, true);
  } catch {
    /* 剪贴板不可用 */
  }
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

const SCAN_MODULE_MAP: Record<string, string> = {
  'vulnkit-cors-scan': 'cors',
  'vulnkit-waf-scan': 'waf',
  'vulnkit-headers-scan': 'headers',
  'vulnkit-subdomain-scan': 'subdomain',
};

const LINK_MODULE_MAP: Record<string, string> = {
  'vulnkit-link-cors': 'cors',
  'vulnkit-link-headers': 'headers',
  'vulnkit-link-redirect': 'redirect',
};

/** 处理右键菜单点击。返回 true 表示已处理（caller 无需额外动作）。 */
export async function handleMenuClick(
  info: Browser.contextMenus.OnClickData,
  tab: Browser.tabs.Tab,
): Promise<void> {
  if (!tab?.id) return;
  const id = info.menuItemId as string;

  // 提取链接
  if (id === 'vulnkit-extract-links') {
    browser.tabs.sendMessage(tab.id, { type: 'CONTEXT_EXTRACT_LINKS' }).catch(() => {});
    // TODO(Phase 5): 提取链接结果页将迁移为 side panel 内的面板
    setTimeout(() => {
      browser.tabs.create({
        url: browser.runtime.getURL('src/extracted-links/extracted-links.html' as any),
      });
    }, 500);
    return;
  }

  // 页面扫描菜单 → 写入 contextScan，打开 popup
  if (SCAN_MODULE_MAP[id]) {
    await browser.storage.local.set({ contextScan: { module: SCAN_MODULE_MAP[id], url: tab.url } });
    browser.action.setBadgeText({ text: 'S' });
    browser.action.setBadgeBackgroundColor({ color: '#2196F3' });
    tryOpenPopup(tab);
    return;
  }

  // 选区编解码（打开 popup）
  if (id === 'vulnkit-encode' || id === 'vulnkit-decode') {
    if (!info.selectionText) return;
    await browser.storage.local.set({
      contextSelection: info.selectionText,
      contextAction: id === 'vulnkit-encode' ? 'encode' : 'decode',
    });
    browser.action.setBadgeText({ text: '↑' });
    browser.action.setBadgeBackgroundColor({ color: '#4CAF50' });
    tryOpenPopup(tab);
    return;
  }

  // Base64 编码
  if (id === 'vulnkit-base64-encode' && info.selectionText) {
    try {
      const encoded = btoa(unescape(encodeURIComponent(info.selectionText)));
      await copyAndToast(tab.id, encoded, '灵眸: Base64 编码已复制');
    } catch {
      /* ignore */
    }
    return;
  }

  // Base64 解码
  if (id === 'vulnkit-base64-decode' && info.selectionText) {
    try {
      const decoded = decodeURIComponent(escape(atob(info.selectionText.trim())));
      await copyAndToast(tab.id, decoded, '灵眸: Base64 解码已复制');
    } catch {
      await showToast(tab.id, '灵眸: Base64 解码失败（无效输入）', false);
    }
    return;
  }

  // 哈希
  if (id === 'vulnkit-md5-hash' && info.selectionText) {
    await copyAndToast(tab.id, md5String(info.selectionText), '灵眸: MD5 哈希已复制');
    return;
  }
  if (id === 'vulnkit-sha256-hash' && info.selectionText) {
    try {
      await copyAndToast(tab.id, await sha256Hex(info.selectionText), '灵眸: SHA256 哈希已复制');
    } catch {
      /* ignore */
    }
    return;
  }

  // 链接扫描菜单
  if (LINK_MODULE_MAP[id]) {
    const linkUrl = info.linkUrl || tab.url || '';
    await browser.storage.local.set({ contextScan: { module: LINK_MODULE_MAP[id], url: linkUrl } });
    browser.action.setBadgeText({ text: 'S' });
    browser.action.setBadgeBackgroundColor({ color: '#2196F3' });
    tryOpenPopup(tab);
    return;
  }
}

function tryOpenPopup(tab: Browser.tabs.Tab): void {
  if (typeof browser.action.openPopup === 'function') {
    try {
      browser.action.openPopup({ windowId: tab.windowId });
    } catch {
      /* openPopup 在某些场景不可用 */
    }
  }
}
