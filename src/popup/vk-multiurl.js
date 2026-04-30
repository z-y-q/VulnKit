// VulnKit - URL Multi-Open
window.VulnKitMultiUrl = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  function parseUrls() {
    const el = utils.get('multiurl-input');
    if (!el) return [];
    const text = el.value;
    return text
      .split(/[\n\r]+/)
      .map(line => {
        let url = line.trim();
        if (!url) return null;
        if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
        return url;
      })
      .filter(Boolean);
  }

  function updateMultiurlInfo(count) {
    const el = utils.get('multiurl-info');
    if (el) el.textContent = count > 0 ? '已识别 ' + count + ' 个 URL' : '';
  }

  function handleMultiurlOpen() {
    const urls = parseUrls();
    if (urls.length === 0) {
      utils.showToast('请输入URL', 'warning');
      return;
    }
    if (urls.length > 50) {
      utils.showToast('一次最多打开 50 个', 'warning');
      return;
    }
    urls.forEach(url => chrome.tabs.create({ url, active: false }));
    utils.showToast('已打开 ' + urls.length + ' 个标签页', 'success');
  }

  function handleMultiurlDedup() {
    const urls = parseUrls();
    const unique = [...new Set(urls)];
    if (unique.length === urls.length) {
      utils.showToast('没有重复URL', 'info');
      return;
    }
    const inputEl = utils.get('multiurl-input');
    if (inputEl) inputEl.value = unique.join('\n');
    updateMultiurlInfo(unique.length);
    utils.showToast('去重完成，移除 ' + (urls.length - unique.length) + ' 个重复', 'success');
  }

  function copyAllUrls() {
    var urls = parseUrls();
    if (urls.length === 0) {
      utils.showToast('没有可复制的URL', 'warning');
      return;
    }
    utils.copyText(urls.join('\n'));
    utils.showToast('已复制 ' + urls.length + ' 个URL', 'success');
  }

  return {
    parseUrls,
    updateMultiurlInfo,
    handleMultiurlOpen,
    handleMultiurlDedup,
    copyAllUrls,
  };
})();
