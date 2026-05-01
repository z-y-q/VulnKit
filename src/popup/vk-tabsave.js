window.VulnKitTabSave = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  // ====== Tab Save ======
  var savedTabUrls = [];

  async function grabAllTabs() {
    var grabBtn = utils.get('tabsave-grab-btn');
    var copyBtn = utils.get('tabsave-copy-btn');
    var exportBtn = utils.get('tabsave-export-btn');
    if (grabBtn) grabBtn.disabled = true;
    utils.setStatus('tabsave-status', '正在获取...');

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

      utils.setStatus('tabsave-status', '已获取 ' + savedTabUrls.length + ' 个标签页（已去重）');
      if (copyBtn) copyBtn.disabled = false;
      if (exportBtn) exportBtn.disabled = false;
      utils.showToast('已获取 ' + savedTabUrls.length + ' 个标签页', 'success');
    } catch (e) {
      utils.setStatus('tabsave-status', '获取失败');
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
    utils.copyAndToast(text, '已复制 ' + savedTabUrls.length + ' 个 URL');
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
    var filename = 'tabs_' + ts + '.txt';
    utils.downloadBlob(text, filename, 'text/plain;charset=utf-8', '已导出 ' + filename);
  }

  return {
    grabAllTabs,
    copySavedTabUrls,
    exportSavedTabUrls,
  };
})();
