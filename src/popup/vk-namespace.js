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

  utils.bindClick = function (id, handler) {
    var el = utils.get(id);
    if (el) el.addEventListener('click', handler);
    return el;
  };

  utils.on = function (id, event, handler) {
    var el = utils.get(id);
    if (el) el.addEventListener(event, handler);
    return el;
  };

  utils.emptyHtml = function (msg) {
    return '<div class="empty-state">' + utils.escapeHtml(msg) + '</div>';
  };

  utils.execInTab = async function (tabId, inject, options) {
    var opts = { target: { tabId: tabId } };
    if (typeof inject === 'function') {
      opts.func = inject;
    } else if (Array.isArray(inject)) {
      opts.files = inject;
    }
    if (options) {
      if (options.world) opts.world = options.world;
      if (options.args) opts.args = options.args;
    } else {
      opts.world = 'MAIN';
    }
    return chrome.scripting.executeScript(opts);
  };

  utils.execResult = function (results) {
    return results && results[0] && results[0].result;
  };

  utils.switchSubTabs = function (btnClass, dataAttr, panelPrefix, tab) {
    document.querySelectorAll('.' + btnClass).forEach(function (b) {
      b.classList.toggle('active', b.dataset[dataAttr] === tab);
    });
    document.querySelectorAll('.' + panelPrefix + '-subpanel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = document.getElementById(panelPrefix + '-' + tab);
    if (target) target.classList.add('active');
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
    'bindClick',
    'on',
    'emptyHtml',
    'switchSubTabs',
    'execInTab',
    'execResult',
    'getActiveTab',
    'getCurrentDomain',
  ].forEach(function (method) {
    utilsProxy[method] = function () {
      return utils[method].apply(utils, arguments);
    };
  });
  utils.utilsProxy = utilsProxy;
})();
