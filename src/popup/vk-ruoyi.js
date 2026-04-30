// VulnKit - RuoYi Dynamic Route Module
window.VulnKitRuoYi = (function () {
  'use strict';

  function getUtils() {
    return window.VulnKitUtils || null;
  }
  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
      if (!u || typeof u[method] !== 'function') return undefined;
      return u[method].apply(u, arguments);
    };
  });

  var ruoyiHookActive = false;
  var ruoyiTabId = null;
  var capturedRouterData = null;
  var discoveredRoutes = [];
  var extraRoutes = [];
  var hookStatus = 'idle';
  var augmentMode = 'auto';

  async function getActiveTab() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  }

  // ====== HTML Helpers (avoid duplication) ======

  function buildEvidenceList(evidence) {
    if (!Array.isArray(evidence)) return '';
    return (
      '<div class="ruoyi-evidence-list">' +
      evidence
        .map(function (e) {
          return '<span class="ruoyi-evidence-item">' + utils.escapeHtml(e) + '</span>';
        })
        .join('') +
      '</div>'
    );
  }

  function buildDetectHtml(badge, label, evidence) {
    return (
      '<div class="ruoyi-detect-info">' +
      '<div class="ruoyi-detect-badge ' +
      badge +
      '">' +
      utils.escapeHtml(label) +
      '</div>' +
      buildEvidenceList(evidence) +
      '</div>'
    );
  }

  // ====== Framework Detection ======

  async function detectRuoYi() {
    var statusEl = utils.get('ruoyi-status');
    var resultsEl = utils.get('ruoyi-results');
    if (statusEl) statusEl.textContent = '检测中...';
    if (resultsEl) resultsEl.innerHTML = '';

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var evidence = [];
          var variant = null;
          var version = null;

          // --- Script filenames ---
          var scripts = document.querySelectorAll('script[src]');
          var scriptSrcs = [];
          scripts.forEach(function (s) {
            var src = s.src || '';
            scriptSrcs.push(src);
            if (/\/request\.js/i.test(src)) evidence.push('script:request.js');
            if (/\/auth\.js/i.test(src)) evidence.push('script:auth.js');
            if (/\/permission\.js/i.test(src)) evidence.push('script:permission.js');
            if (/\/validate\.js/i.test(src)) evidence.push('script:validate.js');
            if (/\/ruoyi/i.test(src)) evidence.push('script:ruoyi');
            if (/\/router\/index\.js/i.test(src)) evidence.push('script:router/index.js');
            if (/\/store\/modules\/(user|permission|app)\.js/i.test(src))
              evidence.push('script:store');
            // RuoYi-Cloud gateway patterns
            if (/\/gateway\/js\//i.test(src)) {
              variant = variant || 'cloud';
              evidence.push('script:gateway');
            }
            // RuoYi-App / uni-app patterns
            if (/\/uni\.js|\/manifest\.js/i.test(src)) {
              variant = variant || 'app';
              evidence.push('script:uni-app');
            }
          });

          // --- Layout ---
          if (
            document.querySelector('.app-container') &&
            document.querySelector('.sidebar-container')
          ) {
            evidence.push('layout:ruoyi-sidebar');
          }
          if (
            document.querySelector('.fixed-header') &&
            document.querySelector('.sidebar-logo-container')
          ) {
            variant = variant || 'vue';
            evidence.push('layout:ruoyi-vue');
          }

          // --- Title ---
          var title = document.title || '';
          if (/若依|RuoYi|管理系统/i.test(title)) evidence.push('title:若依/RuoYi');

          // --- UI Framework ---
          var hasEl =
            !!window.ELEMENT || !!window.ElPlus || document.querySelector('[class*="el-"]');
          if (hasEl) evidence.push('ui:element');

          // --- Version detection ---
          if (window.ELEMENT) {
            version = (window.ELEMENT.version || '').replace(/^[^0-9]*/, '') || null;
            if (version) evidence.push('version:element-ui-' + version);
          }
          if (window.ElPlus) {
            version = (window.ElPlus.version || '').replace(/^[^0-9]*/, '') || null;
            if (version) evidence.push('version:element-plus-' + version);
          }

          // Check Vue version for variant identification
          if (window.Vue) {
            var vv = window.Vue.version;
            if (vv) evidence.push('version:vue-' + vv);
            if (/^3\./.test(vv)) variant = variant || 'vue3';
            else if (/^2\./.test(vv)) variant = variant || 'vue';
          } else if (hasEl) {
            // Production Vue builds don't expose window.Vue.
            // Detect via DOM markers and webpack chunk patterns.
            var vueEl = document.querySelector('#app[data-v-app], #app.__vue_app__');
            if (vueEl || document.querySelector('#app')) {
              // Check for Vue 2 vs Vue 3 markers on script URLs
              var hasVue3Chunk = scriptSrcs.some(function (s) {
                return /chunk-vendors|chunk-libs/i.test(s);
              });
              // If Element UI classes present and #app exists, it's likely a Vue RuoYi
              if (!variant) variant = 'vue';
              evidence.push('ui:vue-spa');
            }
          }

          // --- Global objects ---
          if (window.__CONFIG__) evidence.push('global:__CONFIG__');
          if (window.__APP_BASE_API__) evidence.push('global:__APP_BASE_API__');

          // --- Cookie token ---
          var cookies = document.cookie || '';
          if (/Admin-Token/i.test(cookies)) evidence.push('cookie:Admin-Token');
          if (/token=|JSESSIONID/i.test(cookies)) evidence.push('cookie:session-token');

          // --- RuoYi variant markers ---
          if (variant !== 'cloud' && variant !== 'app') {
            var metaGen = document.querySelector('meta[name="generator"]');
            if (metaGen && /ruoyi/i.test(metaGen.content)) {
              evidence.push('meta:generator-ruoyi');
            }
            // Check for microservice indicators
            if (document.querySelector('[class*="micro"]') || /microservice/i.test(title)) {
              variant = 'microservice';
              evidence.push('layout:microservice');
            }
            // Thymeleaf variant: jQuery + Bootstrap + no Vue + iframe-based navigation
            if (!variant && !window.Vue && window.jQuery) {
              var hasThymeleaf =
                document.querySelector('link[href*="bootstrap"]') ||
                document.querySelector('iframe');
              var hasRuoYiJs = scriptSrcs.some(function (s) {
                return /\/ruoyi\/js\//i.test(s);
              });
              if (hasThymeleaf && hasRuoYiJs) {
                variant = 'thymeleaf';
                evidence.push('layout:thymeleaf');
              }
            }
          }

          // --- Inline script patterns ---
          var inline = document.querySelectorAll('script:not([src])');
          inline.forEach(function (s) {
            var t = s.textContent || '';
            if (/getRouters|getUserInfo|permission\.js|store\.dispatch.*permission/i.test(t)) {
              if (evidence.indexOf('code:ruoyi-pattern') === -1)
                evidence.push('code:ruoyi-pattern');
            }
            // RuoYi-Cloud specific API patterns
            if (/\/auth\/login|\/auth\/logout|\/auth\/getInfo/i.test(t)) {
              if (evidence.indexOf('code:cloud-auth') === -1) {
                evidence.push('code:cloud-auth');
                variant = variant || 'cloud';
              }
            }
          });

          // --- Custom API URL matches from user config ---
          var hook = window.__VK_RUOYI_HOOK__;
          var customUrls = (hook && hook.customRouterUrls) || [];

          // Determine variant
          if (!variant && evidence.length >= 2) variant = 'unknown';

          return {
            detected: evidence.length >= 2,
            evidence: evidence,
            variant: variant,
            version: version,
            cookieToken: /Admin-Token/i.test(cookies),
          };
        },
      });

      var data = (results && results[0] && results[0].result) || {
        detected: false,
        evidence: [],
        variant: null,
        version: null,
        cookieToken: false,
      };

      if (data.detected) {
        var variantLabel = data.variant ? ' [' + data.variant.toUpperCase() + ']' : '';
        var html = buildDetectHtml(
          'ruoyi-badge-ok',
          'RuoYi 框架已检测到' + variantLabel,
          data.evidence
        );

        if (data.cookieToken) {
          html +=
            '<div class="ruoyi-detect-extra">' +
            '<span class="ruoyi-detect-tag tag-token">Admin-Token Cookie 存在</span>' +
            '</div>';
        }
        if (data.version) {
          html +=
            '<div class="ruoyi-detect-extra">' +
            '<span class="ruoyi-detect-tag tag-version">Element ' +
            utils.escapeHtml(data.version) +
            '</span>' +
            '</div>';
        }

        if (resultsEl) resultsEl.innerHTML = html;
        if (statusEl)
          statusEl.textContent = '检测到 RuoYi 框架 (' + data.evidence.length + ' 个特征)';
        utils.showToast('检测到 RuoYi 框架', 'success');

        // Auto-check hook status and try to capture routes after detection
        setTimeout(function () {
          autoCaptureRoutes(tab.id, data.cookieToken);
        }, 300);
      } else if (data.evidence.length > 0) {
        if (resultsEl)
          resultsEl.innerHTML = buildDetectHtml(
            'ruoyi-badge-warn',
            '疑似 RuoYi (' + data.evidence.length + ' 个特征)',
            data.evidence
          );
        if (statusEl) statusEl.textContent = '疑似 RuoYi (' + data.evidence.length + ' 个特征)';
      } else {
        if (resultsEl)
          resultsEl.innerHTML = '<div class="empty-state">当前页面未检测到 RuoYi 框架特征</div>';
        if (statusEl) statusEl.textContent = '未检测到 RuoYi';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '检测出错';
      utils.showToast('检测失败: ' + e.message, 'error');
    }
  }

  // ====== Auto Capture (called after RuoYi detection) ======

  async function autoCaptureRoutes(tabId, hasToken) {
    var hookStatusEl = utils.get('ruoyi-hook-status');
    var panelEl = utils.get('ruoyi-captured-panel');
    try {
      // Step 1: Check if hook already captured data
      var checkResult = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          return {
            installed: !!hook,
            captured: hook ? !!hook.capturedRouters : false,
          };
        },
      });
      var status = checkResult && checkResult[0] && checkResult[0].result;

      if (status && status.captured) {
        // Already have data — show it
        if (hookStatusEl) hookStatusEl.textContent = '已捕获路由数据 (被动捕获模式)';
        await fetchCapturedRoutes();
        return;
      }

      // Step 2: Try to actively fetch /getRouters via background (bypasses CORS)
      if (hasToken) {
        // Get cookies from the page for authentication
        var cookieResult = await chrome.scripting.executeScript({
          target: { tabId: tabId },
          world: 'MAIN',
          func: function () {
            return document.cookie || '';
          },
        });
        var cookies = (cookieResult && cookieResult[0] && cookieResult[0].result) || '';
        var cookieHeader = cookies ? { Cookie: cookies } : {};

        // Try common RuoYi router URLs
        var routerPaths = [
          '/getRouters',
          '/system/menu/getRouters',
          '/prod-api/getRouters',
          '/api/getRouters',
        ];
        var tab = await getActiveTab();
        var origin = tab.url ? new URL(tab.url).origin : '';

        for (var i = 0; i < routerPaths.length; i++) {
          var probeUrl = origin + routerPaths[i];
          var resp = await chrome.runtime
            .sendMessage({
              type: 'FETCH_PROBE',
              url: probeUrl,
              method: 'GET',
              timeout: 8000,
              followRedirect: false,
              includeBody: true,
              headers: cookieHeader,
            })
            .catch(function () {
              return null;
            });

          if (resp && resp.status === 200 && resp.body) {
            // Inject captured data into hook
            await chrome.scripting.executeScript({
              target: { tabId: tabId },
              world: 'MAIN',
              func: function (body) {
                if (window.__VK_RUOYI_HOOK__) {
                  window.__VK_RUOYI_HOOK__.capturedRouters = body;
                }
              },
              args: [resp.body],
            });
            if (hookStatusEl) hookStatusEl.textContent = '已主动获取路由数据';
            await fetchCapturedRoutes();
            return;
          }
        }
      }

      // Step 3: No data captured yet — show guidance
      if (hookStatusEl) {
        if (hasToken) {
          hookStatusEl.textContent = '钩子已注入，正在监听 /getRouters...';
        } else {
          hookStatusEl.textContent = '请先登录 RuoYi 系统，钩子将自动捕获路由';
        }
      }
      if (panelEl) {
        panelEl.innerHTML =
          '<div class="empty-state">' +
          (hasToken
            ? '钩子已就绪，刷新页面或重新登录以触发 /getRouters 请求'
            : '请先登录 RuoYi 系统，登录后钩子会自动捕获路由数据') +
          '</div>';
      }
    } catch (e) {
      // Non-critical — just log
      if (hookStatusEl) hookStatusEl.textContent = '自动捕获检查失败: ' + e.message;
    }
  }

  // ====== Route Hook ======

  function setHookUI(active) {
    var installBtn = utils.get('ruoyi-hook-install-btn');
    var removeBtn = utils.get('ruoyi-hook-remove-btn');
    if (installBtn) installBtn.disabled = active;
    if (removeBtn) removeBtn.disabled = !active;
  }

  async function injectHookCode(tabId) {
    // Method 1: executeScript files (bypasses CSP)
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        files: ['src/inject/ruoyi-route-hook.js'],
      });
      return 'files';
    } catch (e) {
      // Method 2: content script as bridge
      try {
        await chrome.tabs.sendMessage(tabId, { type: 'VK_RUOYI_INJECT_HOOK' });
        for (var i = 0; i < 10; i++) {
          await new Promise(function (r) {
            setTimeout(r, 100);
          });
          var check = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            world: 'MAIN',
            func: function () {
              return !!window.__VK_RUOYI_HOOK__;
            },
          });
          if (check && check[0] && check[0].result) return 'content-script';
        }
        return null;
      } catch (e2) {
        return null;
      }
    }
  }

  function enableHookFunc(opts) {
    if (window.__VK_RUOYI_HOOK__) {
      window.__VK_RUOYI_HOOK__.enabled = true;
      window.__VK_RUOYI_HOOK__.augmentMode = opts.mode || 'auto';
      window.__VK_RUOYI_HOOK__.requestLog = [];
      if (opts.customUrl) {
        window.__VK_RUOYI_HOOK__.customRouterUrls = [opts.customUrl];
      }
      // Persist config to localStorage so it survives page refresh
      if (typeof window.__VK_RUOYI_HOOK__.saveConfig === 'function') {
        window.__VK_RUOYI_HOOK__.saveConfig();
      }
      return true;
    }
    return false;
  }

  async function installRouteHook() {
    var statusEl = utils.get('ruoyi-hook-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }

      if (statusEl) statusEl.textContent = '启用钩子中...';

      var customUrlInput = utils.get('ruoyi-custom-url');
      var customUrl = (customUrlInput && customUrlInput.value.trim()) || '';

      // The hook is ALWAYS injected at document_start via manifest content_scripts.
      // It passively captures /getRouters regardless of enabled state.
      // Here we just enable augmentation mode (extra route injection + API logging).
      var hookResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: enableHookFunc,
        args: [{ mode: augmentMode, customUrl: customUrl }],
      });

      if (hookResult && hookResult[0] && hookResult[0].result) {
        ruoyiHookActive = true;
        ruoyiTabId = tab.id;
        hookStatus = 'active';
        chrome.storage.local.set({ ruoyiHookTabId: tab.id, ruoyiHookEnabled: true });
        setHookUI(true);

        // Check if router data was already passively captured
        var capCheck = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            var hook = window.__VK_RUOYI_HOOK__;
            return {
              captured: !!hook.capturedRouters,
              logCount: (hook.requestLog || []).length,
            };
          },
        });
        var capData = capCheck && capCheck[0] && capCheck[0].result;

        if (capData && capData.captured) {
          if (statusEl) statusEl.textContent = '钩子已启用 — 路由数据已被动捕获';
          utils.showToast('路由数据已捕获', 'success');
          await checkHookStatus();
        } else {
          // Hook is listening but /getRouters hasn't been called yet.
          // No need to force page refresh — tell user to navigate/login.
          if (statusEl)
            statusEl.textContent = '钩子已启用，等待 /getRouters 请求（刷新页面或登录后自动捕获）';
          utils.showToast('钩子已启用，刷新页面或登录以触发 /getRouters', 'success');
        }
        return;
      }

      // Fallback: dynamically inject
      if (statusEl) statusEl.textContent = '动态注入钩子中...';
      var method = await injectHookCode(tab.id);

      if (!method) {
        if (statusEl) statusEl.textContent = '所有注入方式均失败';
        utils.showToast('注入失败 — 请刷新目标页面后重试', 'error');
        return;
      }

      await new Promise(function (r) {
        setTimeout(r, 400);
      });

      var retryResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: enableHookFunc,
        args: [{ mode: augmentMode, customUrl: customUrl }],
      });

      if (!(retryResult && retryResult[0] && retryResult[0].result)) {
        if (statusEl) statusEl.textContent = '注入后未检测到钩子';
        utils.showToast('钩子注入失败 [' + method + ']，请刷新页面后重试', 'warning');
        return;
      }

      ruoyiHookActive = true;
      ruoyiTabId = tab.id;
      hookStatus = 'active';
      chrome.storage.local.set({ ruoyiHookTabId: tab.id, ruoyiHookEnabled: true });
      setHookUI(true);
      if (statusEl) statusEl.textContent = '钩子已启用，正在刷新页面...';
      utils.showToast('钩子已启用，刷新页面以捕获 /getRouters', 'success');
      await chrome.tabs.reload(tab.id);
    } catch (e) {
      hookStatus = 'idle';
      if (statusEl) statusEl.textContent = '安装失败';
      utils.showToast('安装失败: ' + e.message, 'error');
    }
  }

  async function removeRouteHook() {
    var statusEl = utils.get('ruoyi-hook-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.enabled = false;
            window.__VK_RUOYI_HOOK__.extraRoutes = [];
            window.__VK_RUOYI_HOOK__.capturedRouters = null;
            window.__VK_RUOYI_HOOK__.requestLog = [];
            window.__VK_RUOYI_HOOK__.customRouterUrls = [];
            // Clear persisted config from localStorage
            if (typeof window.__VK_RUOYI_HOOK__.clearConfig === 'function') {
              window.__VK_RUOYI_HOOK__.clearConfig();
            }
          }
        },
      });

      ruoyiHookActive = false;
      ruoyiTabId = null;
      hookStatus = 'idle';
      chrome.storage.local.remove(['ruoyiHookTabId', 'ruoyiHookEnabled']);

      setHookUI(false);
      if (statusEl) statusEl.textContent = '钩子已禁用';
      utils.showToast('路由钩子已禁用', 'info');
    } catch (e) {
      utils.showToast('移除失败: ' + e.message, 'error');
    }
  }

  async function checkHookStatus() {
    var statusEl = utils.get('ruoyi-hook-status');
    var panelEl = utils.get('ruoyi-captured-panel');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (!hook) return { installed: false, pageUrl: location.href };
          return {
            installed: true,
            pageUrl: location.href,
            enabled: hook.enabled,
            alwaysCapture: !!hook.alwaysCapture,
            captured: !!hook.capturedRouters,
            augmentMode: hook.augmentMode,
            extraRouteCount: (hook.extraRoutes || []).length,
            logCount: (hook.requestLog || []).length,
            customUrls: hook.customRouterUrls || [],
            restored: !!hook.restoredFromStorage,
          };
        },
      });

      var data = (results && results[0] && results[0].result) || { installed: false };

      if (!data.installed) {
        var urlHint = data.pageUrl ? ' [' + utils.escapeHtml(data.pageUrl) + ']' : '';
        if (statusEl) statusEl.textContent = '钩子未安装，页面: ' + (data.pageUrl || '未知');
        hookStatus = 'idle';
        if (panelEl)
          panelEl.innerHTML =
            '<div class="empty-state">钩子未注入 — 请先点击「安装钩子」' + urlHint + '</div>';
      } else if (data.captured) {
        // Data already passively captured — show it regardless of enabled state
        hookStatus = data.enabled ? 'captured' : 'passive-captured';
        setHookUI(data.enabled);
        var modeText = data.enabled ? data.augmentMode || 'auto' : '被动捕获';
        var extras =
          data.enabled && data.extraRouteCount > 0
            ? '，' + data.extraRouteCount + ' 条额外路由'
            : '';
        if (statusEl) statusEl.textContent = '已捕获路由数据 (' + modeText + ' 模式' + extras + ')';
        await fetchCapturedRoutes();
      } else if (!data.enabled) {
        // Hook present but not enabled, no data yet
        if (statusEl)
          statusEl.textContent = data.alwaysCapture
            ? '钩子已注入（被动捕获模式），等待 /getRouters...'
            : '钩子已安装但未启用';
        hookStatus = 'idle';
        setHookUI(false);
        renderRequestLog(tab.id);
      } else {
        // Enabled but no data yet
        var logInfo = data.logCount > 0 ? '，已拦截 ' + data.logCount + ' 个请求' : '';
        if (statusEl) statusEl.textContent = '监听中，等待 /getRouters 请求...' + logInfo;
        hookStatus = 'active';
        setHookUI(true);
        renderRequestLog(tab.id);
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '检查失败';
    }
  }

  async function renderRequestLog(tabId) {
    try {
      var results = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (!hook || !hook.requestLog) return [];
          return hook.requestLog.slice(-20);
        },
      });

      var log = (results && results[0] && results[0].result) || [];
      if (log.length === 0) return;

      var panelEl = utils.get('ruoyi-captured-panel');
      if (!panelEl) return;

      var html = '<div class="ruoyi-log-section">';
      html += '<div class="ruoyi-log-title">请求拦截日志 (' + log.length + ')</div>';
      html += '<div class="ruoyi-log-list">';
      log.forEach(function (entry) {
        var cls = 'log-info';
        if (entry.type === 'router') cls = 'log-router';
        else if (entry.type === 'router-error') cls = 'log-error';
        else if (entry.type === 'userinfo') cls = 'log-userinfo';
        html += '<div class="ruoyi-log-entry ' + cls + '">';
        html +=
          '<span class="ruoyi-log-type">' + utils.escapeHtml(entry.method || 'GET') + '</span>';
        html += '<span class="ruoyi-log-url">' + utils.escapeHtml(entry.url || '') + '</span>';
        html +=
          '<span class="ruoyi-log-status">' +
          utils.escapeHtml(String(entry.status || '')) +
          '</span>';
        html += '<span class="ruoyi-log-time">' + utils.escapeHtml(entry.time || '') + '</span>';
        html += '</div>';
      });
      html += '</div></div>';
      panelEl.innerHTML = html;
    } catch (e) {
      // ignore — log is optional info
    }
  }

  async function fetchCapturedRoutes() {
    var panelEl = utils.get('ruoyi-captured-panel');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (!window.__VK_RUOYI_HOOK__ || !window.__VK_RUOYI_HOOK__.capturedRouters) return null;
          try {
            return JSON.parse(window.__VK_RUOYI_HOOK__.capturedRouters);
          } catch (e) {
            return { _raw: window.__VK_RUOYI_HOOK__.capturedRouters, _parseError: true };
          }
        },
      });

      var data = results && results[0] && results[0].result;
      if (!data) return;
      capturedRouterData = data;
      renderRouterData(data, panelEl);
    } catch (e) {
      utils.showToast('获取捕获数据失败: ' + e.message, 'error');
    }
  }

  // ====== Route Rendering ======

  function renderRouterData(data, containerEl) {
    if (!containerEl) return;
    var routes = data.data || data;
    if (!Array.isArray(routes)) {
      containerEl.innerHTML =
        '<div class="empty-state">' + (data._raw ? '响应解析失败' : '无路由数据') + '</div>';
      return;
    }

    var totalPaths = 0;
    var hiddenCount = 0;
    (function count(rts) {
      rts.forEach(function (r) {
        totalPaths++;
        if (r.hidden) hiddenCount++;
        if (r.children) count(r.children);
      });
    })(routes);

    var html = '<div class="ruoyi-route-toolbar">';
    html +=
      '<div class="ruoyi-route-summary">' +
      routes.length +
      ' 个顶级路由，' +
      totalPaths +
      ' 个节点' +
      (hiddenCount > 0
        ? '，<span class="ruoyi-hidden-count">' + hiddenCount + ' 个隐藏</span>'
        : '') +
      '</div>';
    html += '<div class="ruoyi-route-actions">';
    html += '<button class="btn btn-xs btn-outline" id="ruoyi-expand-all">全部展开</button>';
    html += '<button class="btn btn-xs btn-outline" id="ruoyi-collapse-all">全部收起</button>';
    html +=
      '<input type="text" class="ruoyi-search-input" id="ruoyi-route-search" placeholder="搜索路由...">';
    html += '</div></div>';
    html += '<div class="ruoyi-route-tree">';
    routes.forEach(function (r) {
      html += renderRouteNode(r, 0);
    });
    html += '</div>';
    containerEl.innerHTML = html;

    // Toggle expand/collapse
    containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var children = btn.closest('.ruoyi-route-node').querySelector('.ruoyi-route-children');
        if (children) {
          var hidden = children.style.display === 'none';
          children.style.display = hidden ? '' : 'none';
          btn.textContent = hidden ? '▼' : '▶';
        }
      });
    });

    // Expand all / Collapse all
    var expandBtn = containerEl.querySelector('#ruoyi-expand-all');
    var collapseBtn = containerEl.querySelector('#ruoyi-collapse-all');
    if (expandBtn) {
      expandBtn.addEventListener('click', function () {
        containerEl.querySelectorAll('.ruoyi-route-children').forEach(function (c) {
          c.style.display = '';
        });
        containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (t) {
          t.textContent = '▼';
        });
      });
    }
    if (collapseBtn) {
      collapseBtn.addEventListener('click', function () {
        containerEl.querySelectorAll('.ruoyi-route-children').forEach(function (c) {
          c.style.display = 'none';
        });
        containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (t) {
          if (t.textContent === '▼') t.textContent = '▶';
        });
      });
    }

    // Search filter
    var searchInput = containerEl.querySelector('#ruoyi-route-search');
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        var query = this.value.toLowerCase().trim();
        containerEl.querySelectorAll('.ruoyi-route-node').forEach(function (node) {
          if (!query) {
            node.style.display = '';
            return;
          }
          var path = (node.querySelector('.ruoyi-route-path') || {}).textContent || '';
          var name = (node.querySelector('.ruoyi-route-name') || {}).textContent || '';
          var title = (node.querySelector('.ruoyi-route-title') || {}).textContent || '';
          var match =
            path.toLowerCase().indexOf(query) !== -1 ||
            name.toLowerCase().indexOf(query) !== -1 ||
            title.toLowerCase().indexOf(query) !== -1;
          node.style.display = match ? '' : 'none';
          // Auto-expand parents of matched nodes
          if (match) {
            var parent = node.parentElement;
            while (parent) {
              if (parent.classList && parent.classList.contains('ruoyi-route-children')) {
                parent.style.display = '';
                var toggle = parent.previousElementSibling;
                if (toggle && toggle.classList.contains('ruoyi-route-toggle')) {
                  toggle.textContent = '▼';
                }
              }
              if (parent.classList && parent.classList.contains('ruoyi-route-node')) {
                parent.style.display = '';
              }
              parent = parent.parentElement;
            }
          }
        });
      });
    }
  }

  function renderRouteNode(route, depth) {
    var indent = depth * 16;
    var path = route.path || '/';
    var name = route.name || '';
    var title = (route.meta && route.meta.title) || '';
    var hidden = route.hidden;
    var hasChildren = route.children && route.children.length > 0;
    var component = route.component || '';

    var html =
      '<div class="ruoyi-route-node' +
      (hidden ? ' node-hidden' : '') +
      '" ' +
      'style="padding-left:' +
      indent +
      'px" data-path="' +
      utils.escapeHtml(path) +
      '">';
    html += '<span class="ruoyi-route-toggle">' + (hasChildren ? '▼' : '►') + '</span>';
    if (hidden) html += '<span class="ruoyi-route-hidden" title="hidden">H</span>';
    var metaType = route.meta && route.meta.type;
    if (metaType) {
      var typeLabels = { M: '目录', C: '菜单', F: '按钮' };
      var typeLabel = typeLabels[metaType] || metaType;
      html +=
        '<span class="ruoyi-route-type" title="type:' +
        utils.escapeHtml(metaType) +
        '">' +
        utils.escapeHtml(typeLabel) +
        '</span>';
    }
    if (route.meta && route.meta.noCache) {
      html += '<span class="ruoyi-route-nocache" title="noCache">NC</span>';
    }
    html += '<span class="ruoyi-route-path">' + utils.escapeHtml(path) + '</span>';
    if (name) html += '<span class="ruoyi-route-name">' + utils.escapeHtml(name) + '</span>';
    if (title) html += '<span class="ruoyi-route-title">' + utils.escapeHtml(title) + '</span>';
    if (component && typeof component === 'string') {
      html +=
        '<span class="ruoyi-route-component">' +
        utils.escapeHtml(component.split('/').pop()) +
        '</span>';
    }
    // Show meta roles if present
    if (route.meta && route.meta.roles) {
      var roles = Array.isArray(route.meta.roles) ? route.meta.roles : [route.meta.roles];
      if (roles.length > 0) {
        html +=
          '<span class="ruoyi-route-roles" title="' +
          utils.escapeHtml(roles.join(', ')) +
          '">' +
          utils.escapeHtml(roles.length > 2 ? roles[0] + ',...' : roles.join(', ')) +
          '</span>';
      }
    }
    // Show meta perms if present
    if (route.meta && route.meta.perms) {
      var perms = Array.isArray(route.meta.perms) ? route.meta.perms : [route.meta.perms];
      if (perms.length > 0) {
        html +=
          '<span class="ruoyi-route-perms" title="' +
          utils.escapeHtml(perms.join(', ')) +
          '">' +
          utils.escapeHtml(perms.length > 2 ? perms[0] + ',...' : perms.join(', ')) +
          '</span>';
      }
    }
    if (hasChildren) {
      html += '<div class="ruoyi-route-children">';
      route.children.forEach(function (child) {
        html += renderRouteNode(child, depth + 1);
      });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  // ====== JS Route Analysis ======

  async function analyzeJsRoutes() {
    var statusEl = utils.get('ruoyi-analyze-status');
    var resultsEl = utils.get('ruoyi-analyze-results');
    if (statusEl) statusEl.textContent = '分析JS路由中...';
    if (resultsEl) resultsEl.innerHTML = '';

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      // Step 1: Run discoverRoutesFromJs in MAIN world
      var discoverResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (
            window.__VK_RUOYI_HOOK__ &&
            typeof window.__VK_RUOYI_HOOK__.discoverRoutesFromJs === 'function'
          ) {
            return window.__VK_RUOYI_HOOK__.discoverRoutesFromJs();
          }
          return null;
        },
      });

      var result = (discoverResults && discoverResults[0] && discoverResults[0].result) || {
        discovered: [],
        extUrls: [],
      };
      discoveredRoutes = result.discovered || [];
      var extUrls = result.extUrls || [];

      if (statusEl)
        statusEl.textContent =
          '发现 ' +
          discoveredRoutes.length +
          ' 条路径，正在扫描外部JS (' +
          extUrls.length +
          ' 个文件)...';

      // Step 2: Fetch external scripts via background proxy
      var CONCURRENCY = 5;
      var routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
      var compPattern = /component\s*:\s*['"`]([^'"`]+?)['"`]/g;
      var skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;

      var completedBatches = 0;
      var totalBatches = Math.ceil(extUrls.length / CONCURRENCY);

      for (var batchStart = 0; batchStart < extUrls.length; batchStart += CONCURRENCY) {
        var batch = extUrls.slice(batchStart, batchStart + CONCURRENCY);
        var batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }).catch(function () {
              return null;
            });
          })
        );
        for (var b = 0; b < batchResults.length; b++) {
          var resp = batchResults[b];
          if (!resp || resp.error || !resp.data) continue;
          var text = resp.data;

          // Route path extraction
          routePattern.lastIndex = 0;
          var m;
          while ((m = routePattern.exec(text)) !== null) {
            var p = m[1];
            if (skipRe.test(p) || p.length < 4) continue;
            var alreadyExists = discoveredRoutes.some(function (r) {
              return r.path === p;
            });
            if (!alreadyExists) {
              var shortUrl = batch[b];
              if (shortUrl.length > 50) shortUrl = '...' + shortUrl.substring(shortUrl.length - 47);
              discoveredRoutes.push({ path: p, source: shortUrl, type: 'route-def' });
            }
          }

          // Component path extraction — find component refs near path definitions
          compPattern.lastIndex = 0;
          while ((m = compPattern.exec(text)) !== null) {
            var comp = m[1];
            // Only capture component-like paths (views/ or pages/)
            if (!/^(views|pages|src)\//i.test(comp)) continue;
            if (
              discoveredRoutes.some(function (r) {
                return r.component === comp;
              })
            )
              continue;
            discoveredRoutes.push({ path: '', source: '', type: 'component-ref', component: comp });
          }
        }

        completedBatches++;
        if (totalBatches > 1) {
          var pct = Math.round((completedBatches / totalBatches) * 100);
          if (statusEl)
            statusEl.textContent =
              '扫描外部JS中... ' + pct + '% (' + completedBatches + '/' + totalBatches + ')';
        }
      }

      // Step 3: Filter against captured router data
      var capturedPaths = {};
      var capturedComponents = {};
      if (capturedRouterData) {
        extractPaths(
          capturedRouterData.data || capturedRouterData,
          capturedPaths,
          capturedComponents
        );
      }

      extraRoutes = discoveredRoutes.filter(function (r) {
        if (r.type === 'component-ref') {
          return r.component && !capturedComponents[r.component];
        }
        return r.path && !capturedPaths[r.path];
      });

      // Deduplicate by path
      var seen = {};
      extraRoutes = extraRoutes.filter(function (r) {
        var key = r.path || r.component;
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      });

      extraRoutes.sort(function (a, b) {
        var pa = a.path || '';
        var pb = b.path || '';
        return pa.localeCompare(pb);
      });

      if (statusEl) statusEl.textContent = '分析完成，发现 ' + extraRoutes.length + ' 条额外路由';

      if (extraRoutes.length > 0) {
        var html =
          '<div class="ruoyi-discovery-summary">发现 ' +
          discoveredRoutes.length +
          ' 条路径，' +
          extraRoutes.length +
          ' 条不在当前路由中</div>';

        // Stats breakdown
        var routeCount = extraRoutes.filter(function (r) {
          return r.type === 'route-def';
        }).length;
        var compCount = extraRoutes.filter(function (r) {
          return r.type === 'component-ref';
        }).length;
        if (compCount > 0) {
          html += '<div class="ruoyi-discovery-stats">';
          html += '<span class="ruoyi-stat-item">路由定义: ' + routeCount + '</span>';
          html += '<span class="ruoyi-stat-item">组件引用: ' + compCount + '</span>';
          html += '</div>';
        }

        html += '<div class="ruoyi-extra-routes">';
        extraRoutes.forEach(function (r, i) {
          html += '<div class="ruoyi-extra-route-item">';
          html +=
            '<label><input type="checkbox" class="ruoyi-route-check" data-idx="' +
            i +
            '" checked> ';
          var displayPath = r.path || r.component;
          var typeLabel = r.type === 'component-ref' ? '[组件] ' : '';
          html +=
            '<span class="ruoyi-route-path">' +
            utils.escapeHtml(typeLabel + displayPath) +
            '</span></label>';
          if (r.source)
            html += '<span class="ruoyi-route-source">' + utils.escapeHtml(r.source) + '</span>';
          html += '</div>';
        });
        html += '</div>';

        if (resultsEl) resultsEl.innerHTML = html;
        utils.showToast('发现 ' + extraRoutes.length + ' 条额外路由', 'success');
      } else {
        if (resultsEl)
          resultsEl.innerHTML =
            '<div class="empty-state">' +
            (discoveredRoutes.length > 0 ? '所有发现的路径均已注册' : '未发现路由定义') +
            '</div>';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '分析出错';
      utils.showToast('分析失败: ' + e.message, 'error');
    }
  }

  function extractPaths(routes, pathMap, compMap) {
    if (!routes || !Array.isArray(routes)) return;
    routes.forEach(function (r) {
      if (r.path) pathMap[r.path] = true;
      if (r.component && typeof r.component === 'string' && compMap) {
        compMap[r.component] = true;
      }
      if (r.children) extractPaths(r.children, pathMap, compMap);
    });
  }

  // ====== Apply Extra Routes ======

  async function applyExtraRoutes() {
    var statusEl = utils.get('ruoyi-analyze-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var selected = [];
      document.querySelectorAll('.ruoyi-route-check:checked').forEach(function (cb) {
        var idx = parseInt(cb.dataset.idx, 10);
        if (extraRoutes[idx]) selected.push(extraRoutes[idx]);
      });

      if (selected.length === 0) {
        utils.showToast('请至少选择一条路由', 'warning');
        return;
      }

      // Transform component-refs into proper route objects
      var routesToApply = selected.map(function (r) {
        if (r.type === 'component-ref') {
          var compPath = r.component || '';
          var segs = compPath
            .replace(/^(views|pages|src)\//i, '')
            .replace(/\.\w+$/, '')
            .split('/');
          var routePath = '/' + segs.join('/');
          return {
            path: routePath,
            component: compPath,
            name: segs[segs.length - 1] || routePath,
            title: segs[segs.length - 1] || routePath,
          };
        }
        return r;
      });

      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (routes) {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.extraRoutes = routes;
            window.__VK_RUOYI_HOOK__.augmentMode = 'auto';
          }
        },
        args: [routesToApply],
      });

      extraRoutes = routesToApply;
      if (statusEl)
        statusEl.textContent = '已设置 ' + selected.length + ' 条额外路由，刷新页面生效';
      utils.showToast('已设置 ' + selected.length + ' 条路由，刷新页面即可生效', 'success');
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  async function clearExtraRoutes() {
    try {
      var tab = await getActiveTab();
      if (tab && tab.id) {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            if (window.__VK_RUOYI_HOOK__) {
              window.__VK_RUOYI_HOOK__.extraRoutes = [];
              window.__VK_RUOYI_HOOK__.augmentMode = 'off';
            }
          },
        });
      }
      extraRoutes = [];
      augmentMode = 'off';
      var statusEl = utils.get('ruoyi-analyze-status');
      var resultsEl = utils.get('ruoyi-analyze-results');
      if (statusEl) statusEl.textContent = '';
      if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">已清除</div>';
      utils.showToast('已清除额外路由', 'info');
    } catch (e) {
      // ignore
    }
  }

  async function setAugmentMode(mode) {
    augmentMode = mode;
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (m) {
          if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.augmentMode = m;
        },
        args: [mode],
      });
    } catch (e) {
      // ignore
    }
  }

  // ====== Export Functions ======

  async function exportCurlCommands() {
    if (!capturedRouterData) {
      utils.showToast('没有捕获的路由数据', 'warning');
      return;
    }

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }
      var baseUrl = tab.url ? new URL(tab.url).origin : 'http://target';
      var paths = [];
      extractPathsFromData(capturedRouterData.data || capturedRouterData, paths);

      var cookieHeader = '';
      try {
        var cookieResult = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            var cookies = document.cookie || '';
            var match = cookies.match(/Admin-Token=[^;]*/i);
            return match ? match[0] : '';
          },
        });
        var token = cookieResult && cookieResult[0] && cookieResult[0].result;
        if (token) {
          var safeToken = token.replace(/'/g, "'\\''");
          cookieHeader = " -H 'Cookie: " + safeToken + "'";
        }
      } catch (e) {
        // ignore cookie extraction failure
      }

      var cmds = paths.map(function (p) {
        var safePath = p.replace(/'/g, "'\\''");
        return (
          "curl -s '" +
          baseUrl +
          safePath +
          "'" +
          cookieHeader +
          " -o /dev/null -w '%{http_code} " +
          safePath +
          "\\n'"
        );
      });
      utils.copyText(cmds.join('\n'));
      utils.showToast(
        '已复制 ' + cmds.length + ' 条 curl 命令' + (cookieHeader ? ' (含认证)' : ''),
        'success'
      );
    } catch (e) {
      utils.showToast('导出失败: ' + e.message, 'error');
    }
  }

  async function exportHtmlReport() {
    if (!capturedRouterData && extraRoutes.length === 0) {
      utils.showToast('没有数据可导出', 'warning');
      return;
    }

    var routes = (capturedRouterData && capturedRouterData.data) || [];
    var html =
      '<!DOCTYPE html><html><head><meta charset="UTF-8">' +
      '<title>RuoYi Route Report</title>' +
      '<style>body{font-family:monospace;font-size:13px;padding:20px}table{border-collapse:collapse;width:100%}' +
      'th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}th{background:#f5f5f5}' +
      '.hidden{color:#999;font-style:italic}.section{margin:20px 0 10px;font-weight:bold;font-size:15px}</style>' +
      '</head><body>';

    if (routes.length > 0) {
      html += '<div class="section">Captured Routes</div>';
      html +=
        '<table><tr><th>Path</th><th>Name</th><th>Title</th><th>Component</th><th>Hidden</th></tr>';
      renderFlatRoutes(routes, function (row) {
        html += row;
      });
      html += '</table>';
    }

    if (extraRoutes.length > 0) {
      html += '<div class="section">Extra Routes (Not Registered)</div>';
      html += '<table><tr><th>Path</th><th>Source</th><th>Type</th></tr>';
      extraRoutes.forEach(function (r) {
        html +=
          '<tr><td>' +
          utils.escapeHtml(r.path || r.component || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.source || '') +
          '</td><td>' +
          utils.escapeHtml(r.type || '') +
          '</td></tr>';
      });
      html += '</table>';
    }

    html += '</body></html>';
    utils.copyText(html);
    utils.showToast('HTML 报告已复制到剪贴板', 'success');
  }

  function extractPathsFromData(routes, out) {
    if (!Array.isArray(routes)) return;
    routes.forEach(function (r) {
      if (
        r.path &&
        r.path !== '/' &&
        r.component &&
        r.component !== 'Layout' &&
        r.component !== 'ParentView'
      ) {
        out.push(r.path);
      }
      if (r.children) extractPathsFromData(r.children, out);
    });
  }

  function renderFlatRoutes(routes, emit) {
    routes.forEach(function (r) {
      var hidden = r.hidden ? ' class="hidden"' : '';
      emit(
        '<tr' +
          hidden +
          '><td>' +
          utils.escapeHtml(r.path || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.name || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml((r.meta && r.meta.title) || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.component || '') +
          '</td>' +
          '<td>' +
          (r.hidden ? 'Yes' : '') +
          '</td></tr>'
      );
      if (r.children) renderFlatRoutes(r.children, emit);
    });
  }

  // ====== Batch Route Probing ======

  var probeAbortFlag = false;

  async function batchProbeRoutes() {
    var statusEl = utils.get('ruoyi-probe-progress');
    var resultsEl = utils.get('ruoyi-probe-results');
    var probeBtn = utils.get('ruoyi-probe-btn');
    var stopBtn = utils.get('ruoyi-probe-stop-btn');

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }

      var origin;
      try {
        origin = new URL(tab.url).origin;
      } catch (e) {
        utils.showToast('无法解析页面URL', 'warning');
        return;
      }

      // Collect all paths from captured routes + extra routes
      var paths = [];
      if (capturedRouterData) {
        extractPathsFromData(capturedRouterData.data || capturedRouterData, paths);
      }
      extraRoutes.forEach(function (r) {
        if (r.path && paths.indexOf(r.path) === -1) paths.push(r.path);
      });

      if (paths.length === 0) {
        if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">没有可探测的路由路径</div>';
        return;
      }

      var concurrency = parseInt((utils.get('ruoyi-probe-concurrency') || {}).value || '5', 10);
      var method = (utils.get('ruoyi-probe-method') || {}).value || 'GET';
      var timeout = parseInt((utils.get('ruoyi-probe-timeout') || {}).value || '5000', 10);
      var followRedirect = (utils.get('ruoyi-probe-follow-redirect') || {}).checked !== false;

      if (probeBtn) probeBtn.disabled = true;
      if (stopBtn) stopBtn.disabled = false;
      probeAbortFlag = false;

      var results = [];
      var completed = 0;

      for (var i = 0; i < paths.length; i += concurrency) {
        if (probeAbortFlag) break;
        var batch = paths.slice(i, i + concurrency);
        var batchResults = await Promise.allSettled(
          batch.map(function (p) {
            return chrome.runtime
              .sendMessage({
                type: 'FETCH_PROBE',
                url: origin + p,
                method: method,
                timeout: timeout,
                followRedirect: followRedirect,
              })
              .catch(function () {
                return { error: 'send failed', status: 0 };
              });
          })
        );

        for (var j = 0; j < batchResults.length; j++) {
          var r = batchResults[j];
          var val = r.status === 'fulfilled' ? r.value : r.reason;
          results.push({
            path: batch[j],
            status: (val && val.status) || 0,
            statusText: (val && val.statusText) || '',
            error: (val && val.error) || '',
            redirected: (val && val.redirected) || false,
          });
          completed++;
          if (statusEl)
            statusEl.textContent =
              '探测中... ' +
              completed +
              '/' +
              paths.length +
              ' (' +
              Math.round((completed / paths.length) * 100) +
              '%)';
        }
      }

      if (probeBtn) probeBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      if (statusEl)
        statusEl.textContent = probeAbortFlag
          ? '已停止 (' + completed + '/' + paths.length + ')'
          : '完成 (' + completed + '/' + paths.length + ')';

      renderProbeResults(results, resultsEl);
    } catch (e) {
      if (probeBtn) probeBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      utils.showToast('探测失败: ' + e.message, 'error');
    }
  }

  function stopProbe() {
    probeAbortFlag = true;
  }

  function renderProbeResults(results, containerEl) {
    if (!containerEl) return;
    if (results.length === 0) {
      containerEl.innerHTML = '<div class="empty-state">无结果</div>';
      return;
    }

    var stats = { ok: 0, redirect: 0, auth: 0, notfound: 0, error: 0, other: 0 };
    results.forEach(function (r) {
      if (r.status >= 200 && r.status < 300) stats.ok++;
      else if (r.status >= 300 && r.status < 400) stats.redirect++;
      else if (r.status === 401 || r.status === 403) stats.auth++;
      else if (r.status === 404) stats.notfound++;
      else if (r.status === 0) stats.error++;
      else stats.other++;
    });

    var html =
      '<div class="ruoyi-probe-stats">' +
      '<span class="probe-stat probe-ok">200: ' +
      stats.ok +
      '</span>' +
      '<span class="probe-stat probe-redirect">3xx: ' +
      stats.redirect +
      '</span>' +
      '<span class="probe-stat probe-auth">401/403: ' +
      stats.auth +
      '</span>' +
      '<span class="probe-stat probe-notfound">404: ' +
      stats.notfound +
      '</span>' +
      '<span class="probe-stat probe-error">ERR: ' +
      stats.error +
      '</span>' +
      (stats.other > 0
        ? '<span class="probe-stat probe-other">Other: ' + stats.other + '</span>'
        : '') +
      '</div>';

    html += '<div class="ruoyi-probe-list">';
    results.forEach(function (r) {
      var cls = 'probe-status-other';
      if (r.status >= 200 && r.status < 300) cls = 'probe-status-ok';
      else if (r.status >= 300 && r.status < 400) cls = 'probe-status-redirect';
      else if (r.status === 401 || r.status === 403) cls = 'probe-status-auth';
      else if (r.status === 404) cls = 'probe-status-notfound';
      else if (r.status === 0) cls = 'probe-status-error';
      else if (r.status >= 500) cls = 'probe-status-error';

      html += '<div class="ruoyi-probe-item">';
      html += '<span class="probe-code ' + cls + '">' + (r.status || 'ERR') + '</span>';
      html += '<span class="probe-path">' + utils.escapeHtml(r.path) + '</span>';
      if (r.redirected) html += '<span class="probe-badge">R</span>';
      if (r.error) html += '<span class="probe-error">' + utils.escapeHtml(r.error) + '</span>';
      html += '</div>';
    });
    html += '</div>';
    containerEl.innerHTML = html;
  }

  // ====== API Traffic Viewer ======

  async function loadApiTraffic() {
    var countEl = utils.get('ruoyi-traffic-count');
    var listEl = utils.get('ruoyi-traffic-list');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (!hook || !hook.apiLog) return [];
          return hook.apiLog.slice(-200);
        },
      });

      var log = (results && results[0] && results[0].result) || [];
      if (countEl) countEl.textContent = '已捕获 ' + log.length + ' 个API请求';

      if (log.length === 0) {
        if (listEl)
          listEl.innerHTML =
            '<div class="empty-state">安装路由钩子并浏览页面后，此处显示捕获的API请求</div>';
        return;
      }

      var html = '<div class="ruoyi-traffic-list-inner">';
      log.forEach(function (entry, i) {
        var statusCls = '';
        if (entry.status >= 200 && entry.status < 300) statusCls = 'traffic-ok';
        else if (entry.status >= 400) statusCls = 'traffic-err';
        else if (entry.status === 0) statusCls = 'traffic-err';

        html += '<div class="ruoyi-traffic-item" data-idx="' + i + '">';
        html +=
          '<span class="traffic-method">' + utils.escapeHtml(entry.method || 'GET') + '</span>';
        html +=
          '<span class="traffic-status ' + statusCls + '">' + (entry.status || '-') + '</span>';
        html += '<span class="traffic-url">' + utils.escapeHtml(entry.url || '') + '</span>';
        html += '<span class="traffic-time">' + utils.escapeHtml(entry.time || '') + '</span>';
        html += '</div>';
      });
      html += '</div>';
      if (listEl) listEl.innerHTML = html;

      // Click to show body preview
      listEl.querySelectorAll('.ruoyi-traffic-item').forEach(function (el) {
        el.addEventListener('click', function () {
          var idx = parseInt(el.dataset.idx, 10);
          var entry = log[idx];
          if (!entry || !entry.body) return;
          var preview = entry.body.substring(0, 500);
          var existing = listEl.querySelector('.traffic-preview');
          if (existing) existing.remove();
          var pre = document.createElement('div');
          pre.className = 'traffic-preview';
          pre.textContent = preview;
          el.after(pre);
        });
      });
    } catch (e) {
      // ignore
    }
  }

  function clearApiTraffic() {
    var listEl = utils.get('ruoyi-traffic-list');
    var countEl = utils.get('ruoyi-traffic-count');
    if (listEl)
      listEl.innerHTML =
        '<div class="empty-state">安装路由钩子并浏览页面后，此处显示捕获的API请求</div>';
    if (countEl) countEl.textContent = '';
    getActiveTab().then(function (tab) {
      if (!tab || !tab.id) return;
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.apiLog = [];
        },
      });
    });
  }

  function exportApiTraffic() {
    getActiveTab()
      .then(function (tab) {
        if (!tab || !tab.id) return;
        return chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            return (window.__VK_RUOYI_HOOK__ && window.__VK_RUOYI_HOOK__.apiLog) || [];
          },
        });
      })
      .then(function (results) {
        var log = (results && results[0] && results[0].result) || [];
        if (log.length === 0) {
          utils.showToast('没有API流量数据', 'warning');
          return;
        }
        utils.copyText(JSON.stringify(log, null, 2));
        utils.showToast('已导出 ' + log.length + ' 条API流量', 'success');
      });
  }

  function filterApiTraffic() {
    var filterEl = utils.get('ruoyi-traffic-filter');
    if (!filterEl) return;
    var query = (filterEl.value || '').toLowerCase().trim();
    var items = document.querySelectorAll('.ruoyi-traffic-item');
    items.forEach(function (el) {
      if (!query) {
        el.style.display = '';
        return;
      }
      var url = (el.querySelector('.traffic-url') || {}).textContent || '';
      el.style.display = url.toLowerCase().indexOf(query) !== -1 ? '' : 'none';
    });
  }

  // ====== CVE Lookup ======

  function lookupCve(version) {
    if (!version) {
      utils.showToast('未检测到版本信息', 'warning');
      return;
    }
    var query = 'RuoYi ' + version;
    var url =
      'https://nvd.nist.gov/vuln/search/results?query=' +
      encodeURIComponent(query) +
      '&results_type=overview';
    window.open(url, '_blank');
  }

  // ====== Sub-tab Switching ======

  function switchRuoYiSubTab(tab) {
    document.querySelectorAll('.ruoyi-stab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.rstab === tab);
    });
    document.querySelectorAll('.ruoyi-subpanel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = document.getElementById('rstab-' + tab);
    if (target) target.classList.add('active');
  }

  // ====== Utility Functions ======

  function copyRouteJson() {
    if (!capturedRouterData) {
      utils.showToast('没有捕获的路由数据', 'warning');
      return;
    }
    utils.copyText(JSON.stringify(capturedRouterData, null, 2));
    utils.showToast('已复制路由 JSON', 'success');
  }

  function copyExtraPaths() {
    if (extraRoutes.length === 0) {
      utils.showToast('没有额外路由', 'warning');
      return;
    }
    utils.copyText(
      extraRoutes
        .map(function (r) {
          return r.path || r.component;
        })
        .join('\n')
    );
    utils.showToast('已复制 ' + extraRoutes.length + ' 条路径', 'success');
  }

  function toggleSelectAll() {
    var checks = document.querySelectorAll('.ruoyi-route-check');
    var allChecked =
      checks.length > 0 &&
      Array.from(checks).every(function (cb) {
        return cb.checked;
      });
    checks.forEach(function (cb) {
      cb.checked = !allChecked;
    });
  }

  // ====== MaR-style Dynamic Route Loading ======

  var marDynamicRoutes = [];
  var marHiddenRoutes = [];
  var marRuoyiScriptUrl = null;

  // RuoYi standard route dictionary (default menus in RuoYi / RuoYi-Cloud)
  var RUOYI_KNOWN_ROUTES = [
    // System
    { path: '/system/user', title: '用户管理', component: 'system/user/index' },
    { path: '/system/role', title: '角色管理', component: 'system/role/index' },
    { path: '/system/menu', title: '菜单管理', component: 'system/menu/index' },
    { path: '/system/dept', title: '部门管理', component: 'system/dept/index' },
    { path: '/system/dict', title: '字典管理', component: 'system/dict/index' },
    { path: '/system/config', title: '参数设置', component: 'system/config/index' },
    { path: '/system/notice', title: '通知公告', component: 'system/notice/index' },
    { path: '/system/log', title: '日志管理', component: 'system/log/index' },
    { path: '/system/log/login', title: '登录日志', component: 'system/log/login' },
    { path: '/system/log/oper', title: '操作日志', component: 'monitor/operlog/index' },
    { path: '/system/user/profile', title: '用户中心', component: 'system/user/profile/index' },
    { path: '/system/user/authRole', title: '角色授权', component: 'system/user/authRole' },
    { path: '/system/user/resetPwd', title: '重置密码', component: 'system/user/resetPwd' },
    // Monitor
    { path: '/monitor/online', title: '在线用户', component: 'monitor/online/index' },
    { path: '/monitor/job', title: '定时任务', component: 'monitor/job/index' },
    { path: '/monitor/druid', title: '数据监控', component: 'monitor/druid/index' },
    { path: '/monitor/server', title: '服务监控', component: 'monitor/server/index' },
    { path: '/monitor/cache', title: '缓存监控', component: 'monitor/cache/index' },
    { path: '/monitor/cache/list', title: '缓存列表', component: 'monitor/cache/list' },
    // Tool
    { path: '/tool/gen', title: '代码生成', component: 'tool/gen/index' },
    { path: '/tool/swagger', title: '系统接口', component: 'tool/swagger/index' },
    { path: '/tool/build', title: '表单构建', component: 'tool/build/index' },
    { path: '/tool/edit', title: '表单编辑', component: 'tool/build/index' },
    // RuoYi-Cloud additional
    { path: '/system/tenant', title: '租户管理', component: 'system/tenant/index' },
    { path: '/system/tenant/package', title: '租户套餐', component: 'system/tenant/package' },
    { path: '/system/oss', title: '文件管理', component: 'system/oss/index' },
    { path: '/system/oss/config', title: 'OSS配置', component: 'system/oss/config' },
    // RuoYi-Vue3 / Plus
    { path: '/system/post', title: '岗位管理', component: 'system/post/index' },
    { path: '/system/mail', title: '邮箱管理', component: 'system/mail/index' },
    // Common hidden/admin paths
    { path: '/system/dict-data', title: '字典数据', component: 'system/dict/data' },
    { path: '/system/role/authUser', title: '分配用户', component: 'system/role/authUser' },
    { path: '/system/menu/menus', title: '菜单分配', component: 'system/role/menu' },
  ];

  async function marScanDynamicRoutes() {
    var statusEl = utils.get('mar-scan-status');
    var resultsEl = utils.get('mar-scan-results');
    if (statusEl) statusEl.textContent = '扫描动态路由中...';
    if (resultsEl) resultsEl.innerHTML = '';

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }

      // Step 1: Get external script URLs + inline scripts from the page
      var scriptResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var urls = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            urls.push(s.src);
          });
          var inlineTexts = [];
          document.querySelectorAll('script:not([src])').forEach(function (s) {
            var t = s.textContent || '';
            if (t.length > 10 && t.length < 500000) inlineTexts.push(t);
          });
          return { urls: urls, inlineTexts: inlineTexts };
        },
      });
      var scriptData = (scriptResult && scriptResult[0] && scriptResult[0].result) || {};
      var scriptUrls = scriptData.urls || [];
      var inlineTexts = scriptData.inlineTexts || [];

      if (statusEl)
        statusEl.textContent =
          '扫描 ' + scriptUrls.length + ' 个外部JS + ' + inlineTexts.length + ' 个内联脚本...';

      // Step 2: Fetch all external JS content from page context
      var CONCURRENCY = 5;
      var allJsContents = [];

      // Also include inline scripts
      inlineTexts.forEach(function (t, i) {
        allJsContents.push({ url: 'inline#' + (i + 1), data: t });
      });

      for (var bi = 0; bi < scriptUrls.length; bi += CONCURRENCY) {
        var batch = scriptUrls.slice(bi, bi + CONCURRENCY);

        var batchFetchResult = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function (urls) {
            return Promise.all(
              urls.map(function (url) {
                return fetch(url)
                  .then(function (r) {
                    return r.text();
                  })
                  .then(function (t) {
                    return { url: url, data: t };
                  })
                  .catch(function () {
                    return { url: url, error: true };
                  });
              })
            );
          },
          args: [batch],
        });

        var batchResults =
          (batchFetchResult && batchFetchResult[0] && batchFetchResult[0].result) || [];
        batchResults.forEach(function (r) {
          if (r && r.data) allJsContents.push(r);
        });

        if (statusEl) {
          var fetched = Math.min(bi + CONCURRENCY, scriptUrls.length);
          statusEl.textContent = '获取JS中... ' + fetched + '/' + scriptUrls.length;
        }
      }

      var totalJs = allJsContents.length;
      var totalBytes = 0;
      allJsContents.forEach(function (r) {
        totalBytes += (r.data || '').length;
      });

      if (totalJs === 0) {
        if (statusEl) statusEl.textContent = '未找到任何 JS 文件';
        if (resultsEl)
          resultsEl.innerHTML = '<div class="empty-state">当前页面未加载任何 JS 脚本。</div>';
        return;
      }

      if (statusEl)
        statusEl.textContent =
          '已获取 ' +
          totalJs +
          ' 个JS (' +
          Math.round(totalBytes / 1024) +
          'KB)，正在扫描路由定义...';

      // Step 3: Scan ALL JS for route patterns (not just RuoYi-marked files)
      // This handles minified/obfuscated builds where variable names are changed.
      var ruoyiRouteJs = null;
      var ruoyiRouteContent = null;
      var extractedRoutes = [];
      var seenPaths = {};
      var seenComps = {};
      var dynRouteVarName = null;

      // RuoYi markers (Phase 1 - try to find RuoYi-specific file)
      var fRegex = /([a-zA-Z_$][a-zA-Z0-9_$]{0,30}=[^,]{0,200})\/system\/user-auth/;
      var ruoyiMarkers = [
        /constantRoutes/,
        /asyncRoutes/,
        /dynamicRoutes/,
        /\/system\/user-auth/,
        /\/system\/role-auth/,
        /\/system\/menu/,
        /\/monitor\/online/,
        /\/tool\/gen/,
        /loadView|loadComponent/,
        /\bLayout\b\s*[=:[(]/,
        /ParentView/,
        /getRouters/,
      ];

      // Universal route patterns (Phase 2 - scan everything)
      var pathRegex = /path\s*:\s*["'`]([/"`][^"'`]+)["'`]/g;
      var compRegex = /component\s*:\s*(?:["'`]([^"'`]+)["'`]|import\(["'`]([^"'`]+)["'`]\))/g;
      // Also catch: "/system/xxx", "/monitor/xxx", "/tool/xxx" as bare strings
      var barePathRegex =
        /["'`](\/(?:system|monitor|tool|auth|resource|infra|gen)\/[a-zA-Z0-9_\-/]+)["'`]/g;

      for (var si = 0; si < allJsContents.length; si++) {
        var jsItem = allJsContents[si];
        var text = jsItem.data || '';

        if (text.length < 50) continue;

        // Skip known third-party libraries
        var jsUrl = (jsItem.url || '').toLowerCase();
        if (
          /\/(jquery|bootstrap|lodash|axios|echarts|element-ui|element-plus|vue|react|core-js|babel|webpack|sockjs)\b/i.test(
            jsUrl
          )
        )
          continue;

        // Phase 1: Check for RuoYi markers
        if (!ruoyiRouteContent) {
          var isRuoYiRoute = false;
          for (var mi = 0; mi < ruoyiMarkers.length; mi++) {
            if (ruoyiMarkers[mi].test(text)) {
              isRuoYiRoute = true;
              break;
            }
          }
          if (isRuoYiRoute) {
            ruoyiRouteJs = jsItem.url;
            ruoyiRouteContent = text;
          }
        }

        // Phase 2: Extract route paths from ALL JS
        // path: "/xxx" or path: '/xxx'
        pathRegex.lastIndex = 0;
        var m;
        while ((m = pathRegex.exec(text)) !== null) {
          var p = m[1];
          if (!seenPaths[p] && p.length > 1 && p.startsWith('/')) {
            seenPaths[p] = true;
            extractedRoutes.push({
              path: p,
              type: 'path-def',
              source: jsItem.url,
            });
          }
        }

        // component: "views/xxx" or component: () => import("...")
        compRegex.lastIndex = 0;
        while ((m = compRegex.exec(text)) !== null) {
          var comp = m[1] || m[2];
          if (comp && !seenComps[comp] && /^(views|pages|src|@\/|\.\/)/i.test(comp)) {
            seenComps[comp] = true;
            extractedRoutes.push({
              path: '',
              component: comp,
              type: 'component-ref',
              source: jsItem.url,
            });
          }
        }

        // Bare string paths like "/system/user", "/monitor/online"
        barePathRegex.lastIndex = 0;
        while ((m = barePathRegex.exec(text)) !== null) {
          var bp = m[1];
          if (!seenPaths[bp]) {
            seenPaths[bp] = true;
            extractedRoutes.push({
              path: bp,
              type: 'bare-string',
              source: jsItem.url,
            });
          }
        }
      }

      // Step 4: Try to extract dynamic routes variable name from RuoYi-marked file
      if (ruoyiRouteContent) {
        var fMatch = fRegex.exec(ruoyiRouteContent);
        if (fMatch) {
          var context = fMatch[1];
          var sRegex = /([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*)=\[/;
          var sMatch = sRegex.exec(context);
          if (sMatch) {
            dynRouteVarName = sMatch[1];
          }
        }
        if (!dynRouteVarName) {
          var varPatterns = [
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[[\s\S]*?path\s*:\s*["']\/system/,
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[[\s\S]*?path\s*:\s*["']\/monitor/,
          ];
          for (var vpi = 0; vpi < varPatterns.length && !dynRouteVarName; vpi++) {
            var vpm = varPatterns[vpi].exec(ruoyiRouteContent);
            if (vpm) dynRouteVarName = vpm[1];
          }
        }
      }

      // Step 5: Merge in RuoYi known routes dictionary
      // Production RuoYi builds may have NO static route definitions in JS.
      // All routes come from backend /getRouters API based on user permissions.
      // We use a known routes dictionary to find hidden (permission-filtered) routes.
      var jsRouteCount = extractedRoutes.length;
      RUOYI_KNOWN_ROUTES.forEach(function (kr) {
        if (!seenPaths[kr.path]) {
          seenPaths[kr.path] = true;
          extractedRoutes.push({
            path: kr.path,
            type: 'known-dict',
            source: 'RuoYi标准路由',
            title: kr.title,
            component: kr.component,
          });
        }
      });

      if (extractedRoutes.length === 0) {
        if (statusEl) statusEl.textContent = '未发现任何路由';
        if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">未发现路由定义</div>';
        return;
      }

      var dictAddedCount = extractedRoutes.length - jsRouteCount;

      // Step 6: Compare with captured router data to find hidden routes
      var capturedPaths = {};
      if (capturedRouterData) {
        extractPaths(capturedRouterData.data || capturedRouterData, capturedPaths, {});
      }

      // Also get routes currently in Vue Router
      var routerResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (hook && typeof hook.getRouterInfo === 'function') {
            return hook.getRouterInfo();
          }
          return { found: false, routes: [], currentRoutes: [] };
        },
      });
      var routerInfo = (routerResult && routerResult[0] && routerResult[0].result) || {};

      // Add router's current routes to captured paths
      if (routerInfo.currentRoutes) {
        routerInfo.currentRoutes.forEach(function (rp) {
          capturedPaths[rp] = true;
        });
      }

      marDynamicRoutes = extractedRoutes;
      marHiddenRoutes = extractedRoutes.filter(function (r) {
        if (r.type === 'component-ref') return true;
        return (
          r.path &&
          !capturedPaths[r.path] &&
          r.path !== '/' &&
          r.path !== '/login' &&
          r.path !== '*'
        );
      });

      // Deduplicate
      var dedupSeen = {};
      marHiddenRoutes = marHiddenRoutes.filter(function (r) {
        var key = r.path || r.component;
        if (dedupSeen[key]) return false;
        dedupSeen[key] = true;
        return true;
      });

      // Render results
      marRenderScanResults(
        statusEl,
        resultsEl,
        extractedRoutes,
        marHiddenRoutes,
        dynRouteVarName,
        ruoyiRouteJs,
        routerInfo
      );
    } catch (e) {
      if (statusEl) statusEl.textContent = '扫描失败: ' + e.message;
      utils.showToast('MaR扫描失败: ' + e.message, 'error');
    }
  }

  function marRenderScanResults(
    statusEl,
    resultsEl,
    allRoutes,
    hiddenRoutes,
    varName,
    jsUrl,
    routerInfo
  ) {
    if (!resultsEl) return;

    var html = '';

    // Info header
    html += '<div class="mar-info-section">';
    html += '<div class="mar-info-row"><span class="mar-label">JS文件:</span> ';
    var shortUrl = jsUrl || '';
    if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
    html += '<span class="mar-value">' + utils.escapeHtml(shortUrl) + '</span></div>';
    if (varName) {
      html +=
        '<div class="mar-info-row"><span class="mar-label">动态路由变量:</span> ' +
        '<span class="mar-value mar-highlight">' +
        utils.escapeHtml(varName) +
        '</span></div>';
    }
    if (routerInfo.found) {
      html +=
        '<div class="mar-info-row"><span class="mar-label">Vue Router:</span> ' +
        '<span class="mar-value">已找到 (' +
        routerInfo.routeCount +
        ' 条路由, ' +
        utils.escapeHtml(routerInfo.mode || '') +
        ')</span></div>';
    } else {
      html +=
        '<div class="mar-info-row"><span class="mar-label">Vue Router:</span> ' +
        '<span class="mar-value mar-warn">未找到</span></div>';
    }
    html += '</div>';

    // Stats
    var routeCount = allRoutes.filter(function (r) {
      return r.type === 'path-def' || r.type === 'bare-string';
    }).length;
    var compCount = allRoutes.filter(function (r) {
      return r.type === 'component-ref';
    }).length;
    var dictCount = allRoutes.filter(function (r) {
      return r.type === 'known-dict';
    }).length;

    html += '<div class="mar-stats">';
    html += '<span class="mar-stat-item">JS路径: ' + routeCount + '</span>';
    html += '<span class="mar-stat-item">组件: ' + compCount + '</span>';
    if (dictCount > 0) {
      html += '<span class="mar-stat-item mar-stat-dict">字典: ' + dictCount + '</span>';
    }
    html +=
      '<span class="mar-stat-item mar-stat-hidden">未注册: ' + hiddenRoutes.length + '</span>';
    html += '</div>';

    if (hiddenRoutes.length === 0) {
      html += '<div class="empty-state">所有路由均已注册，无需额外加载</div>';
      if (statusEl) statusEl.textContent = '扫描完成 — 未发现隐藏路由';
      resultsEl.innerHTML = html;
      return;
    }

    // Hidden routes list with checkboxes
    html += '<div class="mar-routes-header">';
    html += '<span>发现 ' + hiddenRoutes.length + ' 条未注册路由（可选择注入到 Vue Router）</span>';
    html += '</div>';

    html += '<div class="mar-route-list">';
    hiddenRoutes.forEach(function (r, i) {
      var displayPath = r.path || r.component;
      var typeLabel = '';
      if (r.type === 'component-ref') typeLabel = '[组件] ';
      else if (r.type === 'known-dict') typeLabel = '[字典] ';
      else if (r.type === 'bare-string') typeLabel = '[字符串] ';
      var titleSuffix = r.title ? ' — ' + r.title : '';
      html += '<div class="mar-route-item">';
      html +=
        '<label><input type="checkbox" class="mar-route-check" data-idx="' + i + '" checked> ';
      html +=
        '<span class="mar-route-path">' + utils.escapeHtml(typeLabel + displayPath) + '</span>';
      if (titleSuffix) {
        html += '<span class="mar-route-title">' + utils.escapeHtml(titleSuffix) + '</span>';
      }
      html += '</label>';
      html += '</div>';
    });
    html += '</div>';

    resultsEl.innerHTML = html;
    if (statusEl)
      statusEl.textContent =
        '扫描完成 — ' + allRoutes.length + ' 条路由，' + hiddenRoutes.length + ' 条未注册';
  }

  async function marInjectToRouter() {
    var statusEl = utils.get('mar-scan-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }

      // Get selected routes
      var selected = [];
      document.querySelectorAll('.mar-route-check:checked').forEach(function (cb) {
        var idx = parseInt(cb.dataset.idx, 10);
        if (marHiddenRoutes[idx]) selected.push(marHiddenRoutes[idx]);
      });

      if (selected.length === 0) {
        utils.showToast('请至少选择一条路由', 'warning');
        return;
      }

      // Build route objects for Vue Router injection
      var routesToInject = [];
      selected.forEach(function (r) {
        if (r.type === 'known-dict') {
          routesToInject.push({
            path: r.path,
            name: (r.path || '').replace(/^\/+/, '').replace(/\//g, '-') || r.path,
            component: r.component || '',
            meta: { title: r.title || r.path },
          });
        } else if (r.type === 'component-ref') {
          var compPath = (r.component || '').replace(/^@\//, 'views/').replace(/\.\w+$/, '');
          var segs = compPath.replace(/^(views|pages|src)\//i, '').split('/');
          routesToInject.push({
            path: '/' + segs.join('/'),
            name: segs[segs.length - 1] || 'unknown',
            component: r.component,
            meta: { title: segs[segs.length - 1] || r.component },
          });
        } else if (r.path) {
          var segs2 = r.path.replace(/^\/+/, '').split('/');
          routesToInject.push({
            path: r.path,
            name: segs2.join('-') || r.path,
            meta: { title: r.path },
          });
        }
      });

      // Step 1: Check if Vue Router exists in the page
      var routerCheck = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          // Find Vue Router instance
          function findRouter() {
            if (window.__vue_app__) {
              try {
                var cfg = window.__vue_app__.config;
                if (cfg && cfg.globalProperties && cfg.globalProperties.$router)
                  return cfg.globalProperties.$router;
              } catch (e) {}
            }
            var selectors = ['#app', '[data-v-app]', '.app-wrapper', '#app-main'];
            for (var si = 0; si < selectors.length; si++) {
              var els = document.querySelectorAll(selectors[si]);
              for (var ei = 0; ei < els.length; ei++) {
                var el = els[ei];
                if (el.__vue_app__) {
                  try {
                    var r = el.__vue_app__.config.globalProperties.$router;
                    if (r) return r;
                  } catch (e) {}
                }
                if (el.__vue__) {
                  var r2 = el.__vue__.$router || (el.__vue__.$root && el.__vue__.$root.$router);
                  if (r2) return r2;
                }
              }
            }
            var allEls = document.querySelectorAll('*');
            for (var ai = 0; ai < allEls.length; ai++) {
              var ael = allEls[ai];
              if (ael.__vue__ && ael.__vue__.$router) return ael.__vue__.$router;
              if (ael.__vue__ && ael.__vue__.$root && ael.__vue__.$root.$router)
                return ael.__vue__.$root.$router;
            }
            return null;
          }
          var router = findRouter();
          return {
            hasVue: !!window.Vue || !!window.__vue_app__,
            hasRouter: !!router,
            routerMode: router ? router.mode || 'unknown' : null,
            currentPath: location.pathname + location.hash,
          };
        },
      });

      var pageState = (routerCheck && routerCheck[0] && routerCheck[0].result) || {};

      if (!pageState.hasRouter) {
        // No Vue Router — fall back to direct URL access
        // This handles: Thymeleaf RuoYi, login page, or non-Vue apps
        var origin;
        try {
          origin = new URL(tab.url).origin;
        } catch (e) {
          utils.showToast('无法解析页面URL', 'error');
          return;
        }

        var paths = routesToInject.map(function (r) {
          return r.path;
        });

        // Detect if this is a Thymeleaf (non-SPA) or login page
        var isThymeleaf = !pageState.hasVue;
        var hint = isThymeleaf
          ? '当前为非 Vue 应用 (Thymeleaf/jQuery)，直接访问 URL 测试权限绕过'
          : 'Vue 应用未加载，请先登录后重试，或直接访问 URL';

        if (statusEl) statusEl.textContent = hint;

        // Open first selected route in current tab, copy all URLs
        var urls = paths.map(function (p) {
          return origin + p;
        });
        utils.copyText(urls.join('\n'));

        // Open first URL in new tab as demo
        if (urls.length > 0) {
          chrome.tabs.create({ url: urls[0] });
        }

        utils.showToast('已复制 ' + urls.length + ' 条 URL，并在新标签页打开第一条', 'success');
        return;
      }

      // Step 2: Vue Router found — inject routes
      var injectResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (routes) {
          var result = { injected: 0, skipped: 0, errors: [], routerFound: false, routerMode: '' };

          function findRouter() {
            if (window.__vue_app__) {
              try {
                var cfg = window.__vue_app__.config;
                if (cfg && cfg.globalProperties && cfg.globalProperties.$router)
                  return cfg.globalProperties.$router;
              } catch (e) {}
            }
            var selectors = ['#app', '[data-v-app]', '.app-wrapper', '#app-main'];
            for (var si = 0; si < selectors.length; si++) {
              var els = document.querySelectorAll(selectors[si]);
              for (var ei = 0; ei < els.length; ei++) {
                var el = els[ei];
                if (el.__vue_app__) {
                  try {
                    var r = el.__vue_app__.config.globalProperties.$router;
                    if (r) return r;
                  } catch (e) {}
                }
                if (el.__vue__) {
                  var r2 = el.__vue__.$router || (el.__vue__.$root && el.__vue__.$root.$router);
                  if (r2) return r2;
                }
              }
            }
            return null;
          }

          var router = findRouter();
          if (!router) {
            result.errors.push('Vue Router 消失了');
            return result;
          }

          result.routerFound = true;
          result.routerMode = router.mode || 'unknown';

          var loadView = null;
          if (typeof window.loadView === 'function') loadView = window.loadView;
          if (!loadView && typeof window.loadComponent === 'function')
            loadView = window.loadComponent;

          var existingPaths = {};
          try {
            var currentRoutes = router.getRoutes ? router.getRoutes() : [];
            currentRoutes.forEach(function (r) {
              if (r.path) existingPaths[r.path] = true;
            });
          } catch (e) {}

          routes.forEach(function (route) {
            try {
              var path = route.path;
              if (!path || existingPaths[path]) {
                result.skipped++;
                return;
              }

              var routeObj = {
                path: path,
                name: route.name || path.replace(/^\/+/, '').replace(/\//g, '-'),
                meta: route.meta || {},
              };

              if (route.component && typeof route.component === 'string') {
                if (loadView) {
                  try {
                    routeObj.component = loadView(route.component);
                  } catch (e) {
                    routeObj.component = {
                      template: '<div style="padding:20px"><h3>' + path + '</h3></div>',
                    };
                  }
                } else {
                  try {
                    var viewPath = route.component;
                    if (!/^views\//i.test(viewPath)) viewPath = 'views/' + viewPath;
                    routeObj.component = function () {
                      return import('@/' + viewPath + '.vue').catch(function () {
                        return {
                          template: '<div style="padding:20px"><h3>' + path + '</h3></div>',
                        };
                      });
                    };
                  } catch (e) {
                    routeObj.component = {
                      template: '<div style="padding:20px"><h3>' + path + '</h3></div>',
                    };
                  }
                }
              } else {
                routeObj.component = {
                  template: '<div style="padding:20px"><h3>' + path + '</h3></div>',
                };
              }

              if (typeof router.addRoute === 'function') {
                router.addRoute(routeObj);
              } else if (typeof router.addRoutes === 'function') {
                router.addRoutes([routeObj]);
              } else {
                result.errors.push('No addRoute/addRoutes method');
                return;
              }
              result.injected++;
              existingPaths[path] = true;
            } catch (e) {
              result.errors.push((route.path || '?') + ': ' + e.message);
            }
          });

          return result;
        },
        args: [routesToInject],
      });

      var result = (injectResult && injectResult[0] && injectResult[0].result) || {};

      if (!result.routerFound) {
        if (statusEl) statusEl.textContent = '注入失败: Vue Router 未找到';
        utils.showToast('Vue Router 未找到', 'error');
        return;
      }

      var msg = '成功注入 ' + result.injected + ' 条路由到 Vue Router';
      if (result.skipped > 0) msg += '，跳过 ' + result.skipped + ' 条已存在';
      if (result.errors.length > 0) msg += '，' + result.errors.length + ' 个错误';

      if (statusEl) statusEl.textContent = msg;
      utils.showToast(msg, result.injected > 0 ? 'success' : 'warning');
    } catch (e) {
      if (statusEl) statusEl.textContent = '注入失败: ' + e.message;
      utils.showToast('注入失败: ' + e.message, 'error');
    }
  }

  function marToggleSelectAll() {
    var checks = document.querySelectorAll('.mar-route-check');
    var allChecked =
      checks.length > 0 &&
      Array.from(checks).every(function (cb) {
        return cb.checked;
      });
    checks.forEach(function (cb) {
      cb.checked = !allChecked;
    });
  }

  function marCopyHiddenPaths() {
    if (marHiddenRoutes.length === 0) {
      utils.showToast('没有隐藏路由', 'warning');
      return;
    }
    var paths = marHiddenRoutes
      .map(function (r) {
        return r.path || r.component;
      })
      .join('\n');
    utils.copyText(paths);
    utils.showToast('已复制 ' + marHiddenRoutes.length + ' 条路径', 'success');
  }

  // ====== Public API ======

  return {
    detectRuoYi: detectRuoYi,
    installRouteHook: installRouteHook,
    removeRouteHook: removeRouteHook,
    checkHookStatus: checkHookStatus,
    analyzeJsRoutes: analyzeJsRoutes,
    applyExtraRoutes: applyExtraRoutes,
    clearExtraRoutes: clearExtraRoutes,
    setAugmentMode: setAugmentMode,
    switchRuoYiSubTab: switchRuoYiSubTab,
    copyRouteJson: copyRouteJson,
    copyExtraPaths: copyExtraPaths,
    toggleSelectAll: toggleSelectAll,
    exportCurlCommands: exportCurlCommands,
    exportHtmlReport: exportHtmlReport,
    batchProbeRoutes: batchProbeRoutes,
    stopProbe: stopProbe,
    loadApiTraffic: loadApiTraffic,
    clearApiTraffic: clearApiTraffic,
    exportApiTraffic: exportApiTraffic,
    filterApiTraffic: filterApiTraffic,
    lookupCve: lookupCve,
    marScanDynamicRoutes: marScanDynamicRoutes,
    marInjectToRouter: marInjectToRouter,
    marToggleSelectAll: marToggleSelectAll,
    marCopyHiddenPaths: marCopyHiddenPaths,
    get ruoyiHookActive() {
      return ruoyiHookActive;
    },
    set ruoyiHookActive(v) {
      ruoyiHookActive = v;
    },
    get ruoyiTabId() {
      return ruoyiTabId;
    },
    set ruoyiTabId(v) {
      ruoyiTabId = v;
    },
    get hookStatus() {
      return hookStatus;
    },
    set hookStatus(v) {
      hookStatus = v;
    },
    get extraRoutes() {
      return extraRoutes;
    },
    set extraRoutes(v) {
      extraRoutes = v;
    },
    get augmentMode() {
      return augmentMode;
    },
    set augmentMode(v) {
      augmentMode = v;
    },
  };
})();
