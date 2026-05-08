// 灵眸 v5.0
'use strict';

// Settings cache — declared before utils so showToast closure can reference it
let _settingsCache = null;
let _settingsPromise = null;

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
    const queue = [];
    let showing = false;
    const types = ['success', 'error', 'warning', 'info'];
    function processQueue() {
      if (showing || queue.length === 0) return;
      showing = true;
      const item = queue.shift();
      let el = document.createElement('div');
      el.className = `toast toast-${types.includes(item.type) ? item.type : 'info'}`;
      el.textContent = item.message;
      el.addEventListener('click', function () {
        clearTimeout(timer);
        dismiss();
      });
      document.body.appendChild(el);
      requestAnimationFrame(function () {
        el.classList.add('toast-show');
      });
      const timer = setTimeout(function () {
        dismiss();
      }, item.duration || 2000);
      function dismiss() {
        el.classList.remove('toast-show');
        setTimeout(function () {
          if (el.parentNode) el.parentNode.removeChild(el);
          showing = false;
          processQueue();
        }, 200);
      }
    }
    return function (message, type, duration) {
      if (_settingsCache && _settingsCache.enableNotifications === false) return;
      queue.push({ message: message, type: type, duration: duration });
      processQueue();
    };
  })(),
};

utils.loadSettings = function () {
  if (_settingsCache) return Promise.resolve(_settingsCache);
  if (!_settingsPromise) {
    _settingsPromise = new Promise(function (resolve) {
      chrome.storage.local.get(['pentestSettings'], function (result) {
        _settingsCache = result.pentestSettings || {};
        resolve(_settingsCache);
      });
    });
  }
  return _settingsPromise;
};
utils.getSetting = function (key, defaultVal) {
  if (!_settingsCache) return defaultVal;
  const val = _settingsCache[key];
  return val !== undefined && val !== null ? val : defaultVal;
};

// Invalidate cache when settings change (e.g. options page modified while popup is open)
chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === 'local' && changes.pentestSettings) {
    _settingsCache = null;
    _settingsPromise = null;
  }
});

utils.getActiveTab = async function () {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
};

utils.getCurrentDomain = async function () {
  let tab = await utils.getActiveTab();
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
  let el = utils.get(id);
  if (el) el.addEventListener('click', handler);
  return el;
};

utils.on = function (id, event, handler) {
  let el = utils.get(id);
  if (el) el.addEventListener(event, handler);
  return el;
};

utils.emptyHtml = function (msg) {
  return `<div class="empty-state">${utils.escapeHtml(msg)}</div>`;
};

utils.h = function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [key, val] of Object.entries(attrs)) {
      if (val == null || val === false) continue;
      if (key === 'className') {
        el.className = val;
        continue;
      }
      if (key === 'style' && typeof val === 'object') {
        Object.assign(el.style, val);
        continue;
      }
      if (key.startsWith('on') && typeof val === 'function') {
        el.addEventListener(key.slice(2).toLowerCase(), val);
        continue;
      }
      if (key === 'textContent') {
        el.textContent = String(val);
        continue;
      }
      if (key === 'innerHTML') {
        el.innerHTML = val;
        continue;
      }
      if (key.startsWith('data-')) {
        el.dataset[key.slice(5)] = val;
        continue;
      }
      el.setAttribute(key, String(val));
    }
  }
  const append = (parent, child) => {
    if (child == null || child === false) return;
    if (typeof child === 'function') return append(parent, child());
    if (Array.isArray(child)) return child.forEach(c => append(parent, c));
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  };
  children.forEach(c => append(el, c));
  return el;
};

utils.execInTab = async function (tabId, inject, options) {
  const opts = { target: { tabId: tabId } };
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
  const results = await utils.execInTab(tabId, fn, opts);
  const data = utils.execResult(results);
  return data !== undefined ? data : defaultVal !== undefined ? defaultVal : null;
};

utils.csvField = function (val) {
  return `"${(val || '').replace(/"/g, '""')}"`;
};

utils.confirmDanger = function (message) {
  return new Promise(function (resolve) {
    const overlay = document.createElement('div');
    overlay.className = 'confirm-overlay';
    overlay.innerHTML = `<div class="confirm-dialog"><p>${utils.escapeHtml(message)}</p><div class="confirm-buttons"><button class="confirm-cancel" data-action="cancel">取消</button><button class="confirm-ok" data-action="ok">确认执行</button></div></div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('[data-action="cancel"]').addEventListener('click', function () {
      overlay.remove();
      resolve(false);
    });
    overlay.querySelector('[data-action="ok"]').addEventListener('click', function () {
      overlay.remove();
      resolve(true);
    });
  });
};

utils.requireTabId = async function () {
  try {
    let tab = await this.getActiveTab();
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
  const tab = await this.requireTabId();
  if (!tab) return undefined;
  return handler(tab);
};

utils.setStatus = function (id, text) {
  let el = document.getElementById(id);
  if (el) el.textContent = text;
};

utils.setEmpty = function (id, msg) {
  let el = document.getElementById(id);
  if (el) el.innerHTML = this.emptyHtml(msg);
};

utils.updateIndicator = function (dotId, labelId, state, text, buttons) {
  const dot = utils.get(dotId),
    label = utils.get(labelId);
  if (dot && label) {
    const cls = 'js-toggle-dot js-toggle-dot-';
    dot.className = `${cls}${state === 'on' ? 'on' : state === 'warn' || state === 'danger' ? 'warn' : 'off'}`;
    label.textContent = text;
  }
  if (buttons) {
    buttons.forEach(function (b) {
      const el = utils.get(b.id);
      if (el) el.disabled = b.disabled;
    });
  }
};

utils.switchSubTabs = function (btnClass, dataAttr, panelPrefix, tab) {
  document.querySelectorAll(`.${btnClass}`).forEach(function (b) {
    b.classList.toggle('active', b.dataset[dataAttr] === tab);
  });
  document.querySelectorAll(`.${panelPrefix}-subpanel`).forEach(function (p) {
    p.classList.remove('active');
  });
  const target = document.getElementById(`${panelPrefix}-${tab}`);
  if (target) target.classList.add('active');
};

utils.downloadBlob = function (data, filename, mimeType, successMsg) {
  const blob = new Blob([data], { type: mimeType || 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({ url: url, filename: filename, saveAs: true }, function () {
    URL.revokeObjectURL(url);
    if (chrome.runtime.lastError) {
      utils.showToast(`导出失败: ${chrome.runtime.lastError.message}`, 'error');
      return;
    }
    utils.showToast(successMsg || '导出成功', 'success');
  });
};

utils.downloadCsv = function (csv, filename) {
  utils.downloadBlob(`﻿${csv}`, filename, 'text/csv;charset=utf-8', '导出成功');
};

utils.buildCsv = function (headers, rows, filename) {
  if (!rows || rows.length === 0) {
    this.showToast('没有可导出的数据', 'warning');
    return;
  }
  const lines = [headers.join(',')];
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
  const s = utils.get(startId),
    e = utils.get(stopId);
  if (s) s.disabled = running;
  if (e) e.disabled = !running;
};

utils.bindTabSwitch = function (tabClass, dataAttr, handler) {
  document.querySelectorAll(`.${tabClass}`).forEach(function (b) {
    if (b.dataset[dataAttr])
      b.addEventListener('click', function () {
        handler(b.dataset[dataAttr]);
      });
  });
};

utils.filterByQuery = function (items, query, fields) {
  if (!query) return items;
  const lower = query.toLowerCase();
  return items.filter(function (item) {
    for (let i = 0; i < fields.length; i++) {
      let val = item[fields[i]];
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
  let msg = { type: options.type || 'FETCH_URL', url: options.url };
  if (options.tailOnly !== undefined) msg.tailOnly = options.tailOnly;
  if (options.key) msg.key = options.key;
  if (options.provider) msg.provider = options.provider;
  return new Promise(function (resolve) {
    let timer;
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
  const opts = options || {};
  const concurrency = opts.concurrency || 5;
  let results = [];
  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(function (url) {
        const msg = { type: 'FETCH_URL', url: url };
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

const UI_STATE_KEY = 'pentest_ui_state';
let _uiStateCache = null;

utils.saveUIState = function (id, value) {
  if (!_uiStateCache) _uiStateCache = {};
  _uiStateCache[id] = value;
  chrome.storage.local.set({ pentest_ui_state: _uiStateCache });
};

utils.restoreUIState = function () {
  return new Promise(function (resolve) {
    chrome.storage.local.get([UI_STATE_KEY], function (result) {
      _uiStateCache = result[UI_STATE_KEY] || {};
      Object.keys(_uiStateCache).forEach(function (id) {
        if (id === 'asset-source') return;
        let el = utils.get(id);
        if (!el) return;
        const val = _uiStateCache[id];
        if (el.tagName === 'SELECT' || el.tagName === 'INPUT') {
          el.value = val;
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
      resolve(_uiStateCache);
    });
  });
};

utils.bindPersist = function (id) {
  const el = utils.get(id);
  if (!el) return;
  el.addEventListener('change', function () {
    utils.saveUIState(id, el.value);
  });
};

utils.loadLibs = function (srcs) {
  const key = srcs.join('|');
  if (utils.loadLibs._loaded && utils.loadLibs._loaded[key]) {
    return Promise.resolve();
  }
  return new Promise(function (resolve, reject) {
    const remaining = srcs.filter(function (src) {
      return !utils.loadLibs._pending || !utils.loadLibs._pending[src];
    });
    if (remaining.length === 0) {
      if (!utils.loadLibs._loaded) utils.loadLibs._loaded = {};
      utils.loadLibs._loaded[key] = true;
      resolve();
      return;
    }
    if (!utils.loadLibs._pending) utils.loadLibs._pending = {};
    let count = remaining.length;
    let failed = false;
    remaining.forEach(function (src) {
      utils.loadLibs._pending[src] = true;
      const s = document.createElement('script');
      s.src = src;
      s.onload = function () {
        delete utils.loadLibs._pending[src];
        if (!failed) {
          count--;
          if (count === 0) {
            if (!utils.loadLibs._loaded) utils.loadLibs._loaded = {};
            utils.loadLibs._loaded[key] = true;
            resolve();
          }
        }
      };
      s.onerror = function () {
        delete utils.loadLibs._pending[src];
        failed = true;
        reject(new Error(`加载失败: ${src}`));
      };
      (document.head || document.documentElement).appendChild(s);
    });
  });
};

utils.fetchWithTimeout = function (url, timeoutMs) {
  return new Promise(function (resolve) {
    const timer = setTimeout(function () {
      resolve(null);
    }, timeoutMs || 15000);
    chrome.runtime.sendMessage(
      { type: 'FETCH_URL', url: url, timeout: timeoutMs },
      function (resp) {
        clearTimeout(timer);
        resolve(resp || null);
      }
    );
  });
};

const utilsProxy = {};
Object.keys(utils)
  .filter(function (k) {
    return typeof utils[k] === 'function';
  })
  .forEach(function (method) {
    utilsProxy[method] = function () {
      return utils[method].apply(utils, arguments);
    };
  });

export { utils, utilsProxy };
