// 灵眸 - Source Loader
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastResults = [];

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function extractFilename(url) {
  try {
    const pathname = new URL(url).pathname;
    const parts = pathname.split('/');
    return parts[parts.length - 1] || 'unknown';
  } catch (e) {
    return 'unknown';
  }
}

function getFileExtension(filename) {
  let idx = filename.lastIndexOf('.');
  if (idx === -1) return '';
  return filename.slice(idx).toLowerCase();
}

async function loadToSources() {
  const urlsEl = utils.get('source-loader-urls');
  const statusEl = utils.get('source-loader-status');
  let resultsEl = utils.get('source-loader-results');
  const copyBtn = utils.get('source-loader-copy-btn');

  const raw = urlsEl ? urlsEl.value.trim() : '';
  if (!raw) {
    utils.showToast('请输入至少一个 URL', 'warning');
    return;
  }

  const urls = raw
    .split('\n')
    .map(function (u) {
      return u.trim();
    })
    .filter(function (u) {
      return u.length > 0;
    });

  if (urls.length === 0) {
    utils.showToast('请输入至少一个 URL', 'warning');
    return;
  }

  const tab = await utils.requireTabId();
  if (!tab) {
    if (statusEl) statusEl.textContent = '无法获取当前标签页';
    return;
  }

  lastResults = [];
  if (resultsEl) resultsEl.innerHTML = '';
  if (statusEl) statusEl.textContent = '加载中...';

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    const filename = extractFilename(url);
    let ext = getFileExtension(filename);
    const item = { url: url, filename: filename, status: 'loading', size: 0 };

    if (statusEl) statusEl.textContent = `加载中... (${i + 1}/${urls.length})`;
    renderResults(lastResults.concat(item));

    try {
      const resp = await utils.fetchWithTimeout(url, 30000);
      if (!resp || resp.error) {
        item.status = 'error';
        item.error = resp && resp.error ? resp.error : '请求失败或超时';
      } else if (!resp.data) {
        item.status = 'error';
        item.error = '返回内容为空';
      } else {
        const code = resp.data;
        item.size = new Blob([code]).size;

        if (ext === '.css') {
          await injectCss(tab.id, code, url);
        } else {
          await injectJs(tab.id, code, url);
        }
        item.status = 'success';
      }
    } catch (e) {
      item.status = 'error';
      item.error = e.message || '注入失败';
    }

    lastResults.push(item);
  }

  if (statusEl) {
    const ok = lastResults.filter(function (r) {
      return r.status === 'success';
    }).length;
    const fail = lastResults.filter(function (r) {
      return r.status === 'error';
    }).length;
    let msg = `完成: ${ok} 成功`;
    if (fail > 0) msg += `, ${fail} 失败`;
    statusEl.textContent = msg;
  }

  renderResults(lastResults);
  if (copyBtn) copyBtn.style.display = '';
  utils.showToast(`已加载 ${lastResults.length} 个资源，请打开 DevTools → Sources 查看`, 'success');
}

function injectJs(tabId, code, sourceUrl) {
  return new Promise(function (resolve, reject) {
    chrome.scripting.executeScript(
      {
        target: { tabId: tabId },
        world: 'MAIN',
        func: function injectScript(scriptCode, scriptSourceUrl) {
          const script = document.createElement('script');
          script.textContent = scriptCode + `\n//# sourceURL=${scriptSourceUrl}`;
          document.head.appendChild(script);
          script.remove();
        },
        args: [code, sourceUrl],
      },
      function () {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve();
        }
      }
    );
  });
}

function injectCss(tabId, code, sourceUrl) {
  return new Promise(function (resolve, reject) {
    chrome.scripting.executeScript(
      {
        target: { tabId: tabId },
        world: 'MAIN',
        func: function injectStyle(cssCode, cssSourceUrl) {
          const style = document.createElement('style');
          style.textContent = cssCode + `\n/*# sourceURL=${cssSourceUrl} */`;
          document.head.appendChild(style);
        },
        args: [code, sourceUrl],
      },
      function () {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve();
        }
      }
    );
  });
}

function renderResults(results) {
  let resultsEl = utils.get('source-loader-results');
  if (!resultsEl) return;

  if (results.length === 0) {
    resultsEl.innerHTML =
      '<div class="empty-state">输入远程资源 URL，点击「加载到 Sources」注入到页面</div>';
    return;
  }

  let html = '';
  results.forEach(function (item) {
    let sizeHtml =
      item.size > 0 ? `<span class="source-loader-item-size">${formatSize(item.size)}</span>` : '';
    let statusHtml;
    if (item.status === 'success') {
      statusHtml = '<span class="source-loader-badge success">成功</span>';
    } else if (item.status === 'error') {
      statusHtml = `<span class="source-loader-badge error" title="${utils.escapeHtml(item.error || '')}">失败</span>`;
    } else {
      statusHtml = '<span class="source-loader-badge loading">加载中</span>';
    }
    html += `<div class="source-loader-item"><span class="source-loader-item-url" title="${utils.escapeHtml(item.url)}">${utils.escapeHtml(item.url)}</span><div class="source-loader-item-right">${sizeHtml}${statusHtml}</div></div>`;
  });
  resultsEl.innerHTML = html;
}

function copyResults() {
  if (lastResults.length === 0) {
    utils.showToast('没有结果', 'warning');
    return;
  }
  const text = lastResults
    .map(function (r) {
      return r.url;
    })
    .join('\n');
  utils.copyAndToast(text, `已复制 ${lastResults.length} 个 URL`);
}

function clearResults() {
  const urlsEl = utils.get('source-loader-urls');
  const statusEl = utils.get('source-loader-status');
  const resultsEl = utils.get('source-loader-results');
  const copyBtn = utils.get('source-loader-copy-btn');

  if (urlsEl) urlsEl.value = '';
  if (statusEl) statusEl.textContent = '';
  if (copyBtn) copyBtn.style.display = 'none';
  lastResults = [];
  renderResults([]);
}

function setSourceUrls(urls) {
  const urlsEl = utils.get('source-loader-urls');
  if (!urlsEl) return;
  urlsEl.value = urls.join('\n');
}

export { loadToSources, copyResults, clearResults, setSourceUrls };
