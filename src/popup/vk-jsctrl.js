/**
 * vk-jsctrl.js - JS Control Module (VulnKit)
 *
 * Extracted from inline-optimized.js lines 3082-3725.
 * Provides JavaScript toggle, anti-debug scanning/bypass, and copy-restriction removal.
 */
window.VulnKitJsCtrl = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  // ====== JS Control ======
  var currentJsCtrlTab = 'jstoggle';
  var jsBlocked = false;
  var antiDebugBypassActive = false;
  var antiDebugScanned = false;

  function switchJsCtrlTab(tab) {
    currentJsCtrlTab = tab;
    document.querySelectorAll('.jsctrl-tab').forEach(function (b) {
      return b.classList.toggle('active', b.dataset.ctrl === tab);
    });
    document.querySelectorAll('.jsctrl-panel').forEach(function (p) {
      return p.classList.remove('active');
    });
    var target = document.getElementById('jsctrl-' + tab);
    if (target) target.classList.add('active');
  }

  function updateJsToggleStatus() {
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    var disableBtn = utils.get('js-disable-btn');
    var enableBtn = utils.get('js-enable-btn');
    if (dot && label) {
      if (jsBlocked) {
        dot.className = 'js-toggle-dot js-toggle-dot-off';
        label.textContent = 'JavaScript 已禁用（请刷新页面生效）';
      } else {
        dot.className = 'js-toggle-dot js-toggle-dot-on';
        label.textContent = 'JavaScript 正常运行';
      }
    }
    if (disableBtn) disableBtn.disabled = jsBlocked;
    if (enableBtn) enableBtn.disabled = !jsBlocked;
  }

  function updateAntidebugIndicator(state, text) {
    var dot = utils.get('antidebug-indicator-dot');
    var label = utils.get('antidebug-indicator-label');
    var bypassBtn = utils.get('antidebug-bypass-btn');
    var clearBtn = utils.get('antidebug-clear-btn');
    if (dot && label) {
      if (state === 'danger') {
        dot.className = 'js-toggle-dot js-toggle-dot-warn';
      } else if (state === 'off') {
        dot.className = 'js-toggle-dot js-toggle-dot-off';
      } else {
        dot.className = 'js-toggle-dot js-toggle-dot-on';
      }
      label.textContent = text;
    }
    if (bypassBtn) bypassBtn.disabled = !antiDebugScanned;
    if (clearBtn) clearBtn.disabled = !antiDebugBypassActive;
  }

  async function disableJs() {
    var disableBtn = utils.get('js-disable-btn');
    if (disableBtn) disableBtn.disabled = true;
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    if (dot && label) {
      dot.className = 'js-toggle-dot js-toggle-dot-warn';
      label.textContent = '正在禁用...';
    }

    var tab;
    try {
      tab = await utils.getActiveTab();
    } catch (e) {}
    if (!tab || !tab.id) {
      updateJsToggleStatus();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    try {
      var response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: false,
      });
      if (response && response.success) {
        jsBlocked = true;
        chrome.storage.local.set({ js_blocked_tabId: tab.id });
        updateJsToggleStatus();
        utils.showToast('已禁用 JavaScript，请刷新页面', 'success');
      } else {
        updateJsToggleStatus();
        utils.showToast(
          '禁用失败: ' + (response && response.error ? response.error : '未知错误'),
          'error'
        );
      }
    } catch (e) {
      updateJsToggleStatus();
      utils.showToast('禁用失败: ' + e.message, 'error');
    }
  }

  async function enableJs() {
    var enableBtn = utils.get('js-enable-btn');
    if (enableBtn) enableBtn.disabled = true;
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    if (dot && label) {
      dot.className = 'js-toggle-dot js-toggle-dot-warn';
      label.textContent = '正在启用...';
    }

    var tab;
    try {
      tab = await utils.getActiveTab();
    } catch (e) {}
    if (!tab || !tab.id) {
      updateJsToggleStatus();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    try {
      var response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      if (response && response.success) {
        jsBlocked = false;
        chrome.storage.local.remove('js_blocked_tabId');
        updateJsToggleStatus();
        utils.showToast('已启用 JavaScript，请刷新页面', 'success');
      } else {
        updateJsToggleStatus();
        utils.showToast(
          '启用失败: ' + (response && response.error ? response.error : '未知错误'),
          'error'
        );
      }
    } catch (e) {
      updateJsToggleStatus();
      utils.showToast('启用失败: ' + e.message, 'error');
    }
  }

  async function scanAntiDebug() {
    var statusEl = utils.get('antidebug-status');
    var resultsEl = utils.get('antidebug-results');
    if (!statusEl || !resultsEl) return;

    antiDebugScanned = false;
    antiDebugBypassActive = false;
    statusEl.textContent = '扫描中（内联脚本 + 外部 JS）...';
    updateAntidebugIndicator('warn', '正在扫描...');

    try {
      var tab = await utils.getActiveTab();
      if (!tab || !tab.id) return;

      // Phase 1: inline script scan (MAIN world)
      var inlineResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var detections = [];
          var isNative = function (fn) {
            return /\[native code\]/.test(Function.prototype.toString.call(fn));
          };

          // Check for debugger statement in inline scripts
          var scripts = document.querySelectorAll('script');
          for (var i = 0; i < scripts.length; i++) {
            if (scripts[i].textContent && scripts[i].textContent.indexOf('debugger') !== -1) {
              detections.push({
                type: 'debugger语句',
                desc: '检测到 inline script 中的 debugger 语句',
              });
              break;
            }
          }

          // Check for Function constructor abuse
          if (!isNative(Function.prototype.constructor)) {
            detections.push({
              type: 'Function劫持',
              desc: 'Function.prototype.constructor 已被重写',
            });
          }

          // Check for setInterval/setTimeout debugger loops
          if (!isNative(setInterval)) {
            detections.push({ type: '定时器劫持', desc: 'setInterval 已被重写，可能用于反调试' });
          }
          if (!isNative(setTimeout)) {
            detections.push({ type: '定时器劫持', desc: 'setTimeout 已被重写，可能用于反调试' });
          }

          // Check for console overrides
          if (!isNative(console.log)) {
            detections.push({ type: 'Console劫持', desc: 'console.log 已被重写' });
          }

          // Check for devtools detection in inline scripts
          for (var j = 0; j < scripts.length; j++) {
            var text = scripts[j].textContent || '';
            if (/outerWidth\s*-\s*innerWidth\s*>\s*\d+/.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '通过窗口尺寸差检测开发者工具' });
              break;
            }
            if (/Firebug|firebug|chrome\.devtools/.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '检测到 Firebug/DevTools 探测代码' });
              break;
            }
            if (/new\s+Image.*onerror.*devtools/i.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '通过 Image.onerror 检测开发者工具' });
              break;
            }
          }

          // Collect external JS URLs for phase 2
          var externalUrls = [];
          for (var k = 0; k < scripts.length; k++) {
            if (scripts[k].src) externalUrls.push(scripts[k].src);
          }
          return { detections: detections, externalUrls: externalUrls };
        },
      });

      var inline = (inlineResults && inlineResults[0] && inlineResults[0].result) || {
        detections: [],
        externalUrls: [],
      };
      var detections = inline.detections || [];

      // Phase 2: scan external JS files via background fetch
      var externalUrls = inline.externalUrls || [];
      var scannedCount = 0;
      var maxScan = 10;
      var antiDebugPatterns = [
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

      var seenTypes = {};
      for (var d = 0; d < detections.length; d++) seenTypes[detections[d].type] = true;

      for (var u = 0; u < externalUrls.length && scannedCount < maxScan; u++) {
        try {
          var fetchResult = await new Promise(function (resolve) {
            var timer = setTimeout(function () {
              resolve(null);
            }, 12000);
            chrome.runtime.sendMessage(
              { type: 'FETCH_URL', url: externalUrls[u] },
              function (resp) {
                clearTimeout(timer);
                if (chrome.runtime.lastError) {
                  resolve(null);
                  return;
                }
                resolve(resp);
              }
            );
          });
          if (fetchResult && fetchResult.data && fetchResult.data.length > 0) {
            scannedCount++;
            var code = fetchResult.data;
            for (var p = 0; p < antiDebugPatterns.length; p++) {
              var pattern = antiDebugPatterns[p];
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
          '未发现常见的反调试手段（已扫描 ' + scannedCount + ' 个外部 JS）'
        );
        updateAntidebugIndicator('on', '扫描完成 — 未检测到反调试');
      } else {
        antiDebugScanned = true;
        antiDebugBypassActive = false;
        statusEl.textContent = '检测到 ' + detections.length + ' 项反调试';
        var html = '';
        detections.forEach(function (det) {
          html += '<div class="antidebug-item">';
          html += '<span class="antidebug-type">' + utils.escapeHtml(det.type) + '</span>';
          html += '<span class="antidebug-desc">' + utils.escapeHtml(det.desc) + '</span>';
          html += '</div>';
        });
        if (scannedCount > 0) {
          html +=
            '<div class="antidebug-item"><span class="antidebug-desc">已扫描 ' +
            scannedCount +
            ' 个外部 JS 文件</span></div>';
        }
        resultsEl.innerHTML = html;
        updateAntidebugIndicator(
          'danger',
          '检测到 ' + detections.length + ' 项反调试 — 可点击绕过'
        );
      }
    } catch (e) {
      antiDebugScanned = false;
      statusEl.textContent = '扫描失败';
      resultsEl.innerHTML = utils.emptyHtml(e.message);
      updateAntidebugIndicator('off', '扫描失败');
    }
  }

  async function bypassAntiDebug() {
    var tab = await utils.getActiveTab();
    if (!tab || !tab.id) return;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          // Save native references before any overrides
          var nativeConsoleLog = (function () {
            var iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            document.head.appendChild(iframe);
            var log = iframe.contentWindow.console.log;
            document.head.removeChild(iframe);
            return log;
          })();

          // Override Function constructor to strip debugger
          var OriginalFunction = Function.prototype.constructor;
          Function.prototype.constructor = function () {
            var args = Array.prototype.slice.call(arguments);
            if (args.length > 0 && typeof args[0] === 'string') {
              args[0] = args[0].replace(/debugger/g, '');
              if (/^\s*$/.test(args[0])) return function () {};
            }
            return new (Function.prototype.bind.apply(OriginalFunction, [null].concat(args)))();
          };

          // Override eval to strip debugger
          var originalEval = window.eval;
          window.eval = function (code) {
            if (typeof code === 'string') {
              code = code.replace(/debugger/g, '');
            }
            return originalEval.call(window, code);
          };

          // Override setInterval/setTimeout to neutralize debugger callbacks
          var originalSetInterval = window.setInterval;
          var originalSetTimeout = window.setTimeout;

          function cleanCallback(fn) {
            if (typeof fn === 'string') {
              return fn.replace(/debugger/g, '');
            }
            if (typeof fn === 'function') {
              var fnStr = fn.toString();
              if (fnStr.includes('debugger')) {
                try {
                  var cleaned = fnStr.replace(/debugger/g, '');
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
            var args = Array.prototype.slice.call(arguments, 2);
            return originalSetInterval.apply(window, [cleanCallback(fn), delay].concat(args));
          };

          window.setTimeout = function (fn, delay) {
            var args = Array.prototype.slice.call(arguments, 2);
            return originalSetTimeout.apply(window, [cleanCallback(fn), delay].concat(args));
          };

          // Restore console if overridden
          if (!console.log.restore) {
            console.log = nativeConsoleLog;
            console.log.restore = true;
          }

          return true;
        },
      });

      antiDebugBypassActive = true;
      updateAntidebugIndicator('on', '反调试绕过已生效（刷新页面后失效）');
      utils.showToast('反调试绕过已注入，对当前页面立即生效（刷新后会丢失）', 'success');
    } catch (e) {
      antiDebugBypassActive = false;
      updateAntidebugIndicator('off', '绕过注入失败');
      utils.showToast('注入失败: ' + e.message, 'error');
    }
  }

  async function clearScriptBlock() {
    var tab = await utils.getActiveTab();
    if (!tab || !tab.id) return;

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
      var statusEl = utils.get('antidebug-status');
      if (statusEl) statusEl.textContent = '';
      var resultsEl = utils.get('antidebug-results');
      if (resultsEl) {
        resultsEl.innerHTML = utils.emptyHtml('点击「扫描反调试」检测页面中的反调试手段');
      }
      utils.showToast('已清除所有脚本拦截规则', 'success');
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Remove Copy Restrictions ======
  var uncopyActive = false;

  function updateUncopyIndicator(state, text) {
    var dot = utils.get('uncopy-indicator-dot');
    var label = utils.get('uncopy-indicator-label');
    if (dot && label) {
      if (state === 'warn') dot.className = 'js-toggle-dot js-toggle-dot-warn';
      else if (state === 'off') dot.className = 'js-toggle-dot js-toggle-dot-off';
      else dot.className = 'js-toggle-dot js-toggle-dot-on';
      label.textContent = text;
    }
  }

  async function removeCopyRestrictions() {
    var btn = utils.get('uncopy-btn');
    if (btn) btn.disabled = true;
    updateUncopyIndicator('warn', '正在解除...');

    var tab;
    try {
      tab = await utils.getActiveTab();
    } catch (e) {}
    if (!tab || !tab.id) {
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

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var log = {};

          // 1. Count elements with user-select: none (now overridden by injected CSS)
          var allEls = document.querySelectorAll('*');
          var userSelectCount = 0;
          for (var i = 0; i < allEls.length; i++) {
            var style = window.getComputedStyle(allEls[i]);
            var us = style.getPropertyValue('user-select') || style.webkitUserSelect;
            if (us === 'none' || us === '-webkit-none') {
              userSelectCount++;
            }
          }
          log.userSelect = userSelectCount;

          // 2. Remove inline oncopy/oncut/onpaste/onselectstart/oncontextmenu/ondragstart
          var eventAttrs = [
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
          var inlineAttrCount = 0;
          for (var j = 0; j < allEls.length; j++) {
            for (var a = 0; a < eventAttrs.length; a++) {
              if (allEls[j].hasAttribute(eventAttrs[a])) {
                allEls[j].removeAttribute(eventAttrs[a]);
                inlineAttrCount++;
              }
            }
          }
          log.inlineAttrs = inlineAttrCount;

          // 3. Remove body-level event listeners via addEventListener capture override
          var blockEvents = ['copy', 'cut', 'paste', 'selectstart', 'contextmenu', 'dragstart'];
          var listenerCount = 0;
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
          var pointerCount = 0;
          for (var k = 0; k < allEls.length; k++) {
            var s = window.getComputedStyle(allEls[k]);
            if (s.getPropertyValue('pointer-events') === 'none') {
              var tag = allEls[k].tagName.toLowerCase();
              var isTransparent =
                s.getPropertyValue('opacity') === '0' ||
                s.getPropertyValue('background') === 'rgba(0, 0, 0, 0)' ||
                s.backgroundColor === 'transparent';
              if (
                isTransparent &&
                (tag === 'div' || tag === 'span' || tag === 'a' || tag === 'img')
              ) {
                allEls[k].classList.add('__vk-hidden');
                pointerCount++;
              }
            }
          }
          log.pointerOverlays = pointerCount;

          // 6. Count -webkit-user-drag: none (now overridden by injected CSS)
          var dragCount = 0;
          for (var m = 0; m < allEls.length; m++) {
            if (allEls[m].style.webkitUserDrag === 'none') {
              dragCount++;
            }
          }
          log.dragRestrictions = dragCount;

          return log;
        },
      });

      var log = (results && results[0] && results[0].result) || null;
      if (!log) {
        updateUncopyIndicator('off', '注入失败');
        if (btn) btn.disabled = false;
        return;
      }

      // Render log
      var logEl = utils.get('uncopy-log');
      if (logEl) {
        var html = '';
        if (log.userSelect > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">' +
            log.userSelect +
            '</span> 个元素的 user-select: none</div>';
        if (log.inlineAttrs > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 移除 <span class="log-count">' +
            log.inlineAttrs +
            '</span> 个内联事件拦截</div>';
        if (log.pointerOverlays > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 隐藏 <span class="log-count">' +
            log.pointerOverlays +
            '</span> 个透明遮罩层</div>';
        if (log.dragRestrictions > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">' +
            log.dragRestrictions +
            '</span> 个拖拽限制</div>';
        if (log.captureListeners)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 注册 <span class="log-count">' +
            log.captureListeners +
            '</span> 种 capture 事件拦截</div>';
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
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  return {
    // Public API - functions
    switchJsCtrlTab: switchJsCtrlTab,
    updateJsToggleStatus: updateJsToggleStatus,
    updateAntidebugIndicator: updateAntidebugIndicator,
    disableJs: disableJs,
    enableJs: enableJs,
    scanAntiDebug: scanAntiDebug,
    bypassAntiDebug: bypassAntiDebug,
    clearScriptBlock: clearScriptBlock,
    removeCopyRestrictions: removeCopyRestrictions,
    updateUncopyIndicator: updateUncopyIndicator,
    // State accessors
    get jsBlocked() {
      return jsBlocked;
    },
    set jsBlocked(v) {
      jsBlocked = v;
    },
  };
})();
