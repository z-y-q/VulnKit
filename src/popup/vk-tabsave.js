// 灵眸 - Tab Save
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let savedTabUrls = [];

async function grabAllTabs() {
  const grabBtn = utils.get('tabsave-grab-btn');
  const copyBtn = utils.get('tabsave-copy-btn');
  const exportBtn = utils.get('tabsave-export-btn');
  if (grabBtn) grabBtn.disabled = true;
  utils.setStatus('tabsave-status', '正在获取...');

  try {
    const tabs = await chrome.tabs.query({});
    savedTabUrls = tabs
      .map(function (t) {
        try {
          const u = new URL(t.url);
          if (
            u.protocol === 'chrome:' ||
            u.protocol === 'chrome-extension:' ||
            u.protocol === 'about:' ||
            u.protocol === 'edge:'
          )
            return null;
          return { url: t.url, title: t.title || '', id: t.id };
        } catch (e) {
          return null;
        }
      })
      .filter(Boolean);

    // Dedup by url
    const seen = {};
    savedTabUrls = savedTabUrls.filter(function (t) {
      if (seen[t.url]) return false;
      seen[t.url] = true;
      return true;
    });

    utils.setStatus('tabsave-status', `已获取 ${savedTabUrls.length} 个标签页（已去重）`);
    if (copyBtn) copyBtn.disabled = false;
    if (exportBtn) exportBtn.disabled = false;
    utils.showToast(`已获取 ${savedTabUrls.length} 个标签页`, 'success');
  } catch (e) {
    utils.setStatus('tabsave-status', '获取失败');
    utils.showToast(`获取失败: ${e.message}`, 'error');
  }
  if (grabBtn) grabBtn.disabled = false;
}

function copySavedTabUrls() {
  if (savedTabUrls.length === 0) {
    utils.showToast('请先获取标签页', 'warning');
    return;
  }
  let text = savedTabUrls
    .map(function (t) {
      return t.url;
    })
    .join('\n');
  utils.copyAndToast(text, `已复制 ${savedTabUrls.length} 个 URL`);
}

function exportSavedTabUrls() {
  if (savedTabUrls.length === 0) {
    utils.showToast('请先获取标签页', 'warning');
    return;
  }
  const lines = savedTabUrls.map(function (t) {
    return `${t.title}\n${t.url}`;
  });
  const text = lines.join('\n\n');
  const now = new Date();
  const ts = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
  const filename = `tabs_${ts}.txt`;
  utils.downloadBlob(text, filename, 'text/plain;charset=utf-8', `已导出 ${filename}`);
}

export {
  grabAllTabs,
  copySavedTabUrls,
  exportSavedTabUrls,
};
