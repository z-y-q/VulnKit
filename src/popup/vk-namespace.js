// VulnKit v5.0
(function () {
  'use strict';

  const utils = {
    cache: new Map(),
    get(id) {
      if (!this.cache.has(id)) {
        this.cache.set(id, document.getElementById(id));
      }
      return this.cache.get(id);
    },
    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },
    copyText(text) {
      navigator.clipboard.writeText(text).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    },
    showToast: (() => {
      let current = null;
      const types = ['success', 'error', 'warning', 'info'];
      return function (message, type, duration) {
        if (current && current.parentNode) current.parentNode.removeChild(current);
        current = document.createElement('div');
        current.className = 'toast toast-' + (types.includes(type) ? type : 'info');
        current.textContent = message;
        document.body.appendChild(current);
        requestAnimationFrame(() => {
          if (current) current.classList.add('toast-show');
        });
        setTimeout(() => {
          if (current) {
            current.classList.remove('toast-show');
            setTimeout(() => {
              if (current && current.parentNode) {
                current.parentNode.removeChild(current);
                current = null;
              }
            }, 200);
          }
        }, duration || 2000);
      };
    })(),
  };

  window.VulnKitUtils = utils;

  utils.getActiveTab = async function () {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  };

  utils.getCurrentDomain = async function () {
    var tab = await utils.getActiveTab();
    if (!tab || !tab.url) return '';
    try {
      return new URL(tab.url).hostname;
    } catch (e) {
      return '';
    }
  };

  utils.copyAndToast = function (text, msg, type, duration) {
    utils.copyText(text);
    utils.showToast(msg || '已复制', type || 'success', duration);
  };

  utils.downloadCsv = function (csv, filename) {
    var blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    chrome.downloads.download({ url: url, filename: filename, saveAs: true }, function () {
      URL.revokeObjectURL(url);
      if (chrome.runtime.lastError) {
        utils.showToast('导出失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      utils.showToast('导出成功', 'success');
    });
  };

  var utilsProxy = {};
  [
    'get',
    'escapeHtml',
    'copyText',
    'showToast',
    'copyAndToast',
    'downloadCsv',
    'getActiveTab',
    'getCurrentDomain',
  ].forEach(function (method) {
    utilsProxy[method] = function () {
      return utils[method].apply(utils, arguments);
    };
  });
  utils.utilsProxy = utilsProxy;
})();
