window.VulnKitTabSave = (function () {
  'use strict';

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
      return u[method].apply(u, arguments);
    };
  });

  // ====== Tab Save ======
  var savedTabUrls = [];

  // ====== Tab Save ======
  var savedTabUrls = [];

  async function grabAllTabs() {
    var grabBtn = utils.get('tabsave-grab-btn');
    var copyBtn = utils.get('tabsave-copy-btn');
    var exportBtn = utils.get('tabsave-export-btn');
    var statusEl = utils.get('tabsave-status');
    if (grabBtn) grabBtn.disabled = true;
    if (statusEl) statusEl.textContent = '正在获取...';

    try {
      var tabs = await chrome.tabs.query({});
      savedTabUrls = tabs
        .map(function (t) {
          try {
            var u = new URL(t.url);
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
      var seen = {};
      savedTabUrls = savedTabUrls.filter(function (t) {
        if (seen[t.url]) return false;
        seen[t.url] = true;
        return true;
      });

      if (statusEl) statusEl.textContent = '已获取 ' + savedTabUrls.length + ' 个标签页（已去重）';
      if (copyBtn) copyBtn.disabled = false;
      if (exportBtn) exportBtn.disabled = false;
      utils.showToast('已获取 ' + savedTabUrls.length + ' 个标签页', 'success');
    } catch (e) {
      if (statusEl) statusEl.textContent = '获取失败';
      utils.showToast('获取失败: ' + e.message, 'error');
    }
    if (grabBtn) grabBtn.disabled = false;
  }

  function copySavedTabUrls() {
    if (savedTabUrls.length === 0) {
      utils.showToast('请先获取标签页', 'warning');
      return;
    }
    var text = savedTabUrls
      .map(function (t) {
        return t.url;
      })
      .join('\n');
    utils.copyText(text);
    utils.showToast('已复制 ' + savedTabUrls.length + ' 个 URL', 'success');
  }

  function exportSavedTabUrls() {
    if (savedTabUrls.length === 0) {
      utils.showToast('请先获取标签页', 'warning');
      return;
    }
    var lines = savedTabUrls.map(function (t) {
      return t.title + '\n' + t.url;
    });
    var text = lines.join('\n\n');
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    var now = new Date();
    var ts =
      now.getFullYear() +
      '-' +
      String(now.getMonth() + 1).padStart(2, '0') +
      '-' +
      String(now.getDate()).padStart(2, '0') +
      '_' +
      String(now.getHours()).padStart(2, '0') +
      String(now.getMinutes()).padStart(2, '0');
    a.download = 'tabs_' + ts + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    utils.showToast('已导出 tabs_' + ts + '.txt', 'success');
  }

  return {
    grabAllTabs,
    copySavedTabUrls,
    exportSavedTabUrls,
  };
})();
