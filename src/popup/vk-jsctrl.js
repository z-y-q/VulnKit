/**
 * vk-jsctrl.js - JS Control Module (灵眸)
 *
 * Extracted from inline-optimized.js lines 3082-3725.
 * Provides JavaScript toggle, anti-debug scanning/bypass, and copy-restriction removal.
 */
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

// ====== JS Control ======
let currentJsCtrlTab = 'jstoggle';
let jsBlocked = false;
let antiDebugBypassActive = false;
let antiDebugScanned = false;

function switchJsCtrlTab(tab) {
  currentJsCtrlTab = tab;
  utils.switchSubTabs('jsctrl-tab', 'ctrl', 'jsctrl', tab);
}

function updateJsToggleStatus() {
  utils.updateIndicator(
    'js-toggle-dot',
    'js-toggle-label',
    jsBlocked ? 'off' : 'on',
    jsBlocked ? 'JavaScript 已禁用（请刷新页面生效）' : 'JavaScript 正常运行',
    [
      { id: 'js-disable-btn', disabled: jsBlocked },
      { id: 'js-enable-btn', disabled: !jsBlocked },
    ]
  );
}

function updateAntidebugIndicator(state, text) {
  utils.updateIndicator(
    'antidebug-indicator-dot',
    'antidebug-indicator-label',
    state === 'danger' ? 'warn' : state,
    text,
    [
      { id: 'antidebug-bypass-btn', disabled: !antiDebugScanned },
      { id: 'antidebug-clear-btn', disabled: !antiDebugBypassActive },
    ]
  );
}

async function toggleJs(enable) {
  let btnId = enable ? 'js-enable-btn' : 'js-disable-btn';
  let btn = utils.get(btnId);
  if (btn) btn.disabled = true;
  let dot = utils.get('js-toggle-dot');
  let label = utils.get('js-toggle-label');
  if (dot && label) {
    dot.className = 'js-toggle-dot js-toggle-dot-warn';
    label.textContent = enable ? '正在启用...' : '正在禁用...';
  }

  let tab = await utils.requireTabId();
  if (!tab) {
    updateJsToggleStatus();
    utils.showToast('无法获取当前标签页', 'error');
    return;
  }

  try {
    let response = await chrome.runtime.sendMessage({
      type: 'TOGGLE_JS',
      tabId: tab.id,
      url: tab.url,
      enable: enable,
    });
    if (response && response.success) {
      jsBlocked = !enable;
      if (enable) chrome.storage.local.remove('js_blocked_tabId');
      else chrome.storage.local.set({ js_blocked_tabId: tab.id });
      updateJsToggleStatus();
      utils.showToast(`${enable ? '已启用' : '已禁用'} JavaScript，请刷新页面`, 'success');
    } else {
      updateJsToggleStatus();
      utils.showToast(
        `${enable ? '启用' : '禁用'}失败: ${response && response.error ? response.error : '未知错误'}`,
        'error'
      );
    }
  } catch (e) {
    updateJsToggleStatus();
    utils.showToast(`${enable ? '启用' : '禁用'}失败: ${e.message}`, 'error');
  }
}

async function scanAntiDebug() {
  let statusEl = utils.get('antidebug-status');
  let resultsEl = utils.get('antidebug-results');
  if (!statusEl || !resultsEl) return;

  antiDebugScanned = false;
  antiDebugBypassActive = false;
  statusEl.textContent = '扫描中（内联脚本 + 外部 JS）...';
  updateAntidebugIndicator('warn', '正在扫描...');

  try {
    return utils.withTab(async function (tab) {
      // Phase 1: inline script scan (MAIN world)
      let inline = (await utils.execInTabData(tab.id, function () {
        let detections = [];
        let isNative = function (fn) {
          return /\[native code\]/.test(Function.prototype.toString.call(fn));
        };

        if (!isNative(Function.prototype.constructor))
          detections.push({
            type: 'Function劫持',
            desc: 'Function.prototype.constructor 已被重写',
          });
        if (!isNative(setInterval))
          detections.push({ type: '定时器劫持', desc: 'setInterval 已被重写，可能用于反调试' });
        if (!isNative(setTimeout))
          detections.push({ type: '定时器劫持', desc: 'setTimeout 已被重写，可能用于反调试' });
        if (!isNative(console.log))
          detections.push({ type: 'Console劫持', desc: 'console.log 已被重写' });

        let inlinePats = [
          [/debugger/, 'debugger语句', '检测到 inline script 中的 debugger 语句'],
          [/outerWidth\s*-\s*innerWidth\s*>\s*\d+/, 'DevTools检测', '通过窗口尺寸差检测开发者工具'],
          [/Firebug|firebug|chrome\.devtools/, 'DevTools检测', '检测到 Firebug/DevTools 探测代码'],
          [/new\s+Image.*onerror.*devtools/i, 'DevTools检测', '通过 Image.onerror 检测开发者工具'],
        ];
        let foundPat = {};
        let scripts = document.querySelectorAll('script');
        let externalUrls = [];
        for (let i = 0; i < scripts.length; i++) {
          if (scripts[i].src) externalUrls.push(scripts[i].src);
          let text = scripts[i].textContent || '';
          if (!text) continue;
          for (let p = 0; p < inlinePats.length; p++) {
            if (!foundPat[p] && inlinePats[p][0].test(text)) {
              detections.push({ type: inlinePats[p][1], desc: inlinePats[p][2] });
              foundPat[p] = true;
            }
          }
        }
        return { detections: detections, externalUrls: externalUrls };
      })) || {
        detections: [],
        externalUrls: [],
      };
      let detections = inline.detections || [];

      // Phase 2: scan external JS files via background fetch
      let externalUrls = inline.externalUrls || [];
      let scannedCount = 0;
      let maxScan = 10;
      let antiDebugPatterns = [
        { regex: /\bdebugger\b/, type: 'debugger语句', desc: '外部 JS 中包含 debugger 语句' },
        {
          regex: /outerWidth\s*-\s*innerWidth\s*>\s*\d+/,
          type: 'DevTools检测',
          desc: '外部 JS 通过窗口尺寸差检测 DevTools',
        },
        {
          regex: /Firebug|firebug|chrome\.devtools/i,
          type: 'DevTools检测',
          desc: '外部 JS 包含 Firebug/DevTools 探测',
        },
        {
          regex: /new\s+Image.*onerror.*devtools/i,
          type: 'DevTools检测',
          desc: '外部 JS 通过 Image.onerror 检测 DevTools',
        },
        {
          regex: /setInterval\s*\(\s*function\s*\([^)]*\)\s*\{[^}]*debugger/,
          type: 'debugger循环',
          desc: '外部 JS 包含 setInterval + debugger 循环',
        },
        {
          regex: /constructor\s*=\s*function/,
          type: 'Function劫持',
          desc: '外部 JS 包含 constructor 重写代码',
        },
      ];

      let seenTypes = {};
      for (let d = 0; d < detections.length; d++) seenTypes[detections[d].type] = true;

      for (let u = 0; u < externalUrls.length && scannedCount < maxScan; u++) {
        try {
          let fetchResult = await utils.fetchUrl({ url: externalUrls[u], timeout: 12000 });
          if (
            fetchResult &&
            fetchResult.success &&
            fetchResult.data &&
            fetchResult.data.length > 0
          ) {
            scannedCount++;
            let code = fetchResult.data;
            for (let p = 0; p < antiDebugPatterns.length; p++) {
              let pattern = antiDebugPatterns[p];
              if (pattern.regex.test(code) && !seenTypes[pattern.type]) {
                seenTypes[pattern.type] = true;
                detections.push({ type: pattern.type, desc: pattern.desc });
              }
            }
          }
        } catch (e) {
          // Skip failed fetches
        }
      }

      if (detections.length === 0) {
        antiDebugScanned = true;
        antiDebugBypassActive = false;
        statusEl.textContent = '';
        resultsEl.innerHTML = utils.emptyHtml(
          `未发现常见的反调试手段（已扫描 ${scannedCount} 个外部 JS）`
        );
        updateAntidebugIndicator('on', '扫描完成 — 未检测到反调试');
      } else {
        antiDebugScanned = true;
        antiDebugBypassActive = false;
        statusEl.textContent = `检测到 ${detections.length} 项反调试`;
        let html = '';
        detections.forEach(function (det) {
          html +=
            '<div class="antidebug-item">' +
            `<span class="antidebug-type">${utils.escapeHtml(det.type)}</span>` +
            `<span class="antidebug-desc">${utils.escapeHtml(det.desc)}</span>` +
            '</div>';
        });
        if (scannedCount > 0) {
          html += `<div class="antidebug-item"><span class="antidebug-desc">已扫描 ${scannedCount} 个外部 JS 文件</span></div>`;
        }
        resultsEl.innerHTML = html;
        updateAntidebugIndicator('danger', `检测到 ${detections.length} 项反调试 — 可点击绕过`);
      }
    });
  } catch (e) {
    antiDebugScanned = false;
    statusEl.textContent = '扫描失败';
    resultsEl.innerHTML = utils.emptyHtml(e.message);
    updateAntidebugIndicator('off', '扫描失败');
  }
}

async function bypassAntiDebug() {
  let ok = await utils.confirmDanger(
    '即将重写 Function.prototype 并覆盖 console 方法绕过反调试，是否继续？'
  );
  if (!ok) return;
  return utils.withTab(async function (tab) {
    try {
      await utils.execInTab(tab.id, function () {
        // Save native references before any overrides
        let nativeConsoleLog = (function () {
          let iframe = document.createElement('iframe');
          iframe.style.display = 'none';
          document.head.appendChild(iframe);
          let log = iframe.contentWindow.console.log;
          document.head.removeChild(iframe);
          return log;
        })();

        // Override Function constructor to strip debugger
        let OriginalFunction = Function.prototype.constructor;
        Function.prototype.constructor = function () {
          let args = Array.prototype.slice.call(arguments);
          if (args.length > 0 && typeof args[0] === 'string') {
            args[0] = args[0].replace(/debugger/g, '');
            if (/^\s*$/.test(args[0])) return function () {};
          }
          return new (Function.prototype.bind.apply(OriginalFunction, [null].concat(args)))();
        };

        // Override eval to strip debugger
        let originalEval = window.eval;
        window.eval = function (code) {
          if (typeof code === 'string') {
            code = code.replace(/debugger/g, '');
          }
          return originalEval.call(window, code);
        };

        // Override setInterval/setTimeout to neutralize debugger callbacks
        let originalSetInterval = window.setInterval;
        let originalSetTimeout = window.setTimeout;

        function cleanCallback(fn) {
          if (typeof fn === 'string') {
            return fn.replace(/debugger/g, '');
          }
          if (typeof fn === 'function') {
            let fnStr = fn.toString();
            if (fnStr.includes('debugger')) {
              try {
                let cleaned = fnStr.replace(/debugger/g, '');
                return new Function(
                  cleaned.replace(/^function\s*\w*\s*\([^)]*\)\s*\{/, '').replace(/\}$/, '')
                );
              } catch (e) {
                return function () {};
              }
            }
          }
          return fn;
        }

        window.setInterval = function (fn, delay) {
          let args = Array.prototype.slice.call(arguments, 2);
          return originalSetInterval.apply(window, [cleanCallback(fn), delay].concat(args));
        };

        window.setTimeout = function (fn, delay) {
          let args = Array.prototype.slice.call(arguments, 2);
          return originalSetTimeout.apply(window, [cleanCallback(fn), delay].concat(args));
        };

        // Restore console if overridden
        if (!console.log.restore) {
          console.log = nativeConsoleLog;
          console.log.restore = true;
        }

        return true;
      });

      antiDebugBypassActive = true;
      updateAntidebugIndicator('on', '反调试绕过已生效（刷新页面后失效）');
      utils.showToast('反调试绕过已注入，对当前页面立即生效（刷新后会丢失）', 'success');
    } catch (e) {
      antiDebugBypassActive = false;
      updateAntidebugIndicator('off', '绕过注入失败');
      utils.showToast(`注入失败: ${e.message}`, 'error');
    }
  });
}

async function clearScriptBlock() {
  return utils.withTab(async function (tab) {
    try {
      await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      jsBlocked = false;
      antiDebugBypassActive = false;
      antiDebugScanned = false;
      chrome.storage.local.remove('js_blocked_tabId');
      updateJsToggleStatus();
      updateAntidebugIndicator('on', '未检测 / 未绕过');
      utils.setStatus('antidebug-status', '');
      let resultsEl = utils.get('antidebug-results');
      if (resultsEl) {
        resultsEl.innerHTML = utils.emptyHtml('点击「扫描反调试」检测页面中的反调试手段');
      }
      utils.showToast('已清除所有脚本拦截规则', 'success');
    } catch (e) {
      utils.showToast(`操作失败: ${e.message}`, 'error');
    }
  });
}

// ====== Remove Copy Restrictions ======
let uncopyActive = false;

function updateUncopyIndicator(state, text) {
  utils.updateIndicator('uncopy-indicator-dot', 'uncopy-indicator-label', state, text);
}

async function removeCopyRestrictions() {
  let btn = utils.get('uncopy-btn');
  if (btn) btn.disabled = true;
  updateUncopyIndicator('warn', '正在解除...');

  let tab = await utils.requireTabId();
  if (!tab) {
    updateUncopyIndicator('off', '无法获取当前标签页');
    if (btn) btn.disabled = false;
    return;
  }

  try {
    // Inject CSS via extension API (bypasses page CSP)
    await chrome.scripting.insertCSS({
      target: { tabId: tab.id },
      css: [
        '*, *::before, *::after {',
        '  -webkit-user-select: auto !important;',
        '  user-select: auto !important;',
        '  -webkit-user-drag: auto !important;',
        '}',
        '.__vk-hidden { display: none !important; }',
      ].join('\n'),
    });

    let log = await utils.execInTabData(tab.id, function () {
      let log = {};

      // 1. Count elements with user-select: none (now overridden by injected CSS)
      let allEls = document.querySelectorAll('*');
      let userSelectCount = 0;
      for (let i = 0; i < allEls.length; i++) {
        let style = window.getComputedStyle(allEls[i]);
        let us = style.getPropertyValue('user-select') || style.webkitUserSelect;
        if (us === 'none' || us === '-webkit-none') {
          userSelectCount++;
        }
      }
      log.userSelect = userSelectCount;

      // 2. Remove inline oncopy/oncut/onpaste/onselectstart/oncontextmenu/ondragstart
      let eventAttrs = [
        'oncopy',
        'oncut',
        'onpaste',
        'onselectstart',
        'oncontextmenu',
        'ondragstart',
        'onbeforecopy',
        'onbeforecut',
        'onbeforepaste',
      ];
      let inlineAttrCount = 0;
      for (let j = 0; j < allEls.length; j++) {
        for (let a = 0; a < eventAttrs.length; a++) {
          if (allEls[j].hasAttribute(eventAttrs[a])) {
            allEls[j].removeAttribute(eventAttrs[a]);
            inlineAttrCount++;
          }
        }
      }
      log.inlineAttrs = inlineAttrCount;

      // 3. Remove body-level event listeners via addEventListener capture override
      let blockEvents = ['copy', 'cut', 'paste', 'selectstart', 'contextmenu', 'dragstart'];
      let listenerCount = 0;
      blockEvents.forEach(function (evt) {
        document.addEventListener(
          evt,
          function (e) {
            e.stopImmediatePropagation();
          },
          true
        );
        document.body.addEventListener(
          evt,
          function (e) {
            e.stopImmediatePropagation();
          },
          true
        );
        listenerCount++;
      });
      log.captureListeners = blockEvents.length;

      log.preventOverride = true;

      // 5. Count pointer-events: none overlays (CSS injected separately handles this)
      let pointerCount = 0;
      for (let k = 0; k < allEls.length; k++) {
        let s = window.getComputedStyle(allEls[k]);
        if (s.getPropertyValue('pointer-events') === 'none') {
          let tag = allEls[k].tagName.toLowerCase();
          let isTransparent =
            s.getPropertyValue('opacity') === '0' ||
            s.getPropertyValue('background') === 'rgba(0, 0, 0, 0)' ||
            s.backgroundColor === 'transparent';
          if (isTransparent && (tag === 'div' || tag === 'span' || tag === 'a' || tag === 'img')) {
            allEls[k].classList.add('__vk-hidden');
            pointerCount++;
          }
        }
      }
      log.pointerOverlays = pointerCount;

      // 6. Count -webkit-user-drag: none (now overridden by injected CSS)
      let dragCount = 0;
      for (let m = 0; m < allEls.length; m++) {
        if (allEls[m].style.webkitUserDrag === 'none') {
          dragCount++;
        }
      }
      log.dragRestrictions = dragCount;

      return log;
    });
    if (!log) {
      updateUncopyIndicator('off', '注入失败');
      if (btn) btn.disabled = false;
      return;
    }

    // Render log
    let logEl = utils.get('uncopy-log');
    if (logEl) {
      let html = '';
      if (log.userSelect > 0)
        html += `<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">${log.userSelect}</span> 个元素的 user-select: none</div>`;
      if (log.inlineAttrs > 0)
        html += `<div class="uncopy-log-entry"><span class="log-ok">+</span> 移除 <span class="log-count">${log.inlineAttrs}</span> 个内联事件拦截</div>`;
      if (log.pointerOverlays > 0)
        html += `<div class="uncopy-log-entry"><span class="log-ok">+</span> 隐藏 <span class="log-count">${log.pointerOverlays}</span> 个透明遮罩层</div>`;
      if (log.dragRestrictions > 0)
        html += `<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">${log.dragRestrictions}</span> 个拖拽限制</div>`;
      if (log.captureListeners)
        html += `<div class="uncopy-log-entry"><span class="log-ok">+</span> 注册 <span class="log-count">${log.captureListeners}</span> 种 capture 事件拦截</div>`;
      if (log.preventOverride)
        html +=
          '<div class="uncopy-log-entry"><span class="log-ok">+</span> 覆写 preventDefault 拦截</div>';
      if (!html) html = '<div class="uncopy-log-entry">页面无复制限制</div>';
      logEl.innerHTML = html;
    }

    uncopyActive = true;
    if (btn) btn.disabled = false;
    updateUncopyIndicator('on', '复制限制已解除');
    utils.showToast('复制限制已解除', 'success');
  } catch (e) {
    uncopyActive = false;
    updateUncopyIndicator('off', '操作失败');
    utils.showToast(`操作失败: ${e.message}`, 'error');
  }
}

function setJsBlocked(v) {
  jsBlocked = v;
}

export {
  switchJsCtrlTab,
  updateJsToggleStatus,
  updateAntidebugIndicator,
  toggleJs,
  function disableJs() { return toggleJs(false); },
  function enableJs() { return toggleJs(true); },
  scanAntiDebug,
  bypassAntiDebug,
  clearScriptBlock,
  removeCopyRestrictions,
  updateUncopyIndicator,
  setJsBlocked,
};
