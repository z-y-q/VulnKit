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

  utils.execInTabData = async function (tabId, fn, opts, defaultVal) {
    var results = await utils.execInTab(tabId, fn, opts);
    var data = utils.execResult(results);
    return data !== undefined ? data : defaultVal !== undefined ? defaultVal : null;
  };

  utils.csvField = function (val) {
    return '"' + (val || '').replace(/"/g, '""') + '"';
  };

  utils.requireTabId = async function () {
    try {
      var tab = await this.getActiveTab();
      if (!tab || !tab.id) return null;
      return tab;
    } catch (e) {
      return null;
    }
  };

  utils.requireInput = function (val, msg) {
    if (!val) {
      this.showToast(msg || '请输入内容', 'warning');
      return null;
    }
    return val;
  };

  utils.withTab = async function (handler) {
    var tab = await this.requireTabId();
    if (!tab) return undefined;
    return handler(tab);
  };

  utils.setStatus = function (id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  utils.setEmpty = function (id, msg) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = this.emptyHtml(msg);
  };

  utils.updateIndicator = function (dotId, labelId, state, text, buttons) {
    var dot = utils.get(dotId),
      label = utils.get(labelId);
    if (dot && label) {
      var cls = 'js-toggle-dot js-toggle-dot-';
      dot.className =
        cls + (state === 'on' ? 'on' : state === 'warn' || state === 'danger' ? 'warn' : 'off');
      label.textContent = text;
    }
    if (buttons) {
      buttons.forEach(function (b) {
        var el = utils.get(b.id);
        if (el) el.disabled = b.disabled;
      });
    }
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

  utils.downloadBlob = function (data, filename, mimeType, successMsg) {
    var blob = new Blob([data], { type: mimeType || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    chrome.downloads.download({ url: url, filename: filename, saveAs: true }, function () {
      URL.revokeObjectURL(url);
      if (chrome.runtime.lastError) {
        utils.showToast('导出失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      utils.showToast(successMsg || '导出成功', 'success');
    });
  };

  utils.downloadCsv = function (csv, filename) {
    utils.downloadBlob('﻿' + csv, filename, 'text/csv;charset=utf-8', '导出成功');
  };

  utils.buildCsv = function (headers, rows, filename) {
    if (!rows || rows.length === 0) {
      this.showToast('没有可导出的数据', 'warning');
      return;
    }
    var lines = [headers.join(',')];
    rows.forEach(function (row) {
      lines.push(
        row
          .map(function (cell) {
            return utils.csvField(String(cell == null ? '' : cell));
          })
          .join(',')
      );
    });
    utils.downloadCsv(lines.join('\n'), filename);
  };

  utils.toggleBtnPair = function (startId, stopId, running) {
    var s = utils.get(startId),
      e = utils.get(stopId);
    if (s) s.disabled = running;
    if (e) e.disabled = !running;
  };

  utils.bindTabSwitch = function (tabClass, dataAttr, handler) {
    document.querySelectorAll('.' + tabClass).forEach(function (b) {
      if (b.dataset[dataAttr])
        b.addEventListener('click', function () {
          handler(b.dataset[dataAttr]);
        });
    });
  };

  utils.filterByQuery = function (items, query, fields) {
    if (!query) return items;
    var lower = query.toLowerCase();
    return items.filter(function (item) {
      for (var i = 0; i < fields.length; i++) {
        var val = item[fields[i]];
        if (val && String(val).toLowerCase().indexOf(lower) !== -1) return true;
      }
      return false;
    });
  };

  utils.bindEnterKey = function (id, callback) {
    utils.on(id, 'keydown', function (e) {
      if (e.key === 'Enter') callback(e);
    });
  };

  utils.fetchUrlJson = function (options) {
    return utils.fetchUrl(options).then(function (result) {
      if (!result) return null;
      if (!result.success) return { success: false, error: result.error };
      try {
        return { success: true, data: JSON.parse(result.data) };
      } catch (e) {
        return { success: false, error: 'JSON 解析失败' };
      }
    });
  };

  utils.fetchUrl = function (options) {
    var msg = { type: options.type || 'FETCH_URL', url: options.url };
    if (options.tailOnly !== undefined) msg.tailOnly = options.tailOnly;
    if (options.key) msg.key = options.key;
    if (options.provider) msg.provider = options.provider;
    return new Promise(function (resolve) {
      var timer;
      if (options.timeout) {
        timer = setTimeout(function () {
          resolve(null);
        }, options.timeout);
      }
      chrome.runtime.sendMessage(msg, function (resp) {
        if (timer) clearTimeout(timer);
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        if (!resp) {
          resolve({ success: false, error: '无响应' });
          return;
        }
        if (resp.error) {
          resolve({ success: false, error: resp.error });
          return;
        }
        resolve({ success: true, data: resp.data });
      });
    });
  };

  utils.batchFetch = async function (urls, options) {
    var opts = options || {};
    var concurrency = opts.concurrency || 5;
    var results = [];
    for (var i = 0; i < urls.length; i += concurrency) {
      var batch = urls.slice(i, i + concurrency);
      var batchResults = await Promise.all(
        batch.map(function (url) {
          var msg = { type: 'FETCH_URL', url: url };
          if (opts.tailOnly) msg.tailOnly = true;
          return chrome.runtime
            .sendMessage(msg)
            .then(function (r) {
              return r && !r.error ? r.data : null;
            })
            .catch(function () {
              return null;
            });
        })
      );
      results = results.concat(batchResults);
      if (
        opts.onProgress &&
        opts.onProgress(results, Math.min(i + concurrency, urls.length), urls.length) === false
      )
        break;
    }
    return results;
  };

  var utilsProxy = {};
  [
    'get',
    'escapeHtml',
    'copyText',
    'showToast',
    'copyAndToast',
    'downloadCsv',
    'downloadBlob',
    'buildCsv',
    'bindClick',
    'on',
    'emptyHtml',
    'setStatus',
    'setEmpty',
    'switchSubTabs',
    'execInTab',
    'execInTabData',
    'execResult',
    'csvField',
    'requireTabId',
    'requireInput',
    'withTab',
    'getActiveTab',
    'getCurrentDomain',
    'toggleBtnPair',
    'bindTabSwitch',
    'fetchUrl',
    'fetchUrlJson',
    'batchFetch',
    'updateIndicator',
    'filterByQuery',
    'bindEnterKey',
  ].forEach(function (method) {
    utilsProxy[method] = function () {
      return utils[method].apply(utils, arguments);
    };
  });
  utils.utilsProxy = utilsProxy;
})();
