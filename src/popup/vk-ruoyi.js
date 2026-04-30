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

      if (statusEl) statusEl.textContent = '安装钩子中...';

      var customUrlInput = utils.get('ruoyi-custom-url');
      var customUrl = (customUrlInput && customUrlInput.value.trim()) || '';

      // Try to enable existing hook (document_start already injected)
      var hookResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: enableHookFunc,
        args: [{ mode: augmentMode, customUrl: customUrl }],
      });

      if (hookResult && hookResult[0] && hookResult[0].result) {
        // document_start hook was already present and config saved to localStorage
        ruoyiHookActive = true;
        ruoyiTabId = tab.id;
        hookStatus = 'active';
        chrome.storage.local.set({ ruoyiHookTabId: tab.id, ruoyiHookEnabled: true });
        setHookUI(true);

        // Check if router data was already captured (hook was auto-restored from storage)
        var capCheck = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            var hook = window.__VK_RUOYI_HOOK__;
            return {
              captured: !!hook.capturedRouters,
              restored: !!hook.restoredFromStorage,
            };
          },
        });
        var capData = capCheck && capCheck[0] && capCheck[0].result;

        if (capData && capData.captured) {
          if (statusEl) statusEl.textContent = '钩子已启用 — 路由数据已捕获';
          utils.showToast('路由钩子已启用，路由数据已捕获', 'success');
          await checkHookStatus();
        } else if (capData && capData.restored) {
          if (statusEl) statusEl.textContent = '钩子已从存储恢复 — 正在监听 /getRouters...';
          utils.showToast('钩子已恢复，等待 /getRouters 请求', 'success');
        } else {
          // First time: refresh the page so hook captures /getRouters during page load
          if (statusEl) statusEl.textContent = '钩子已启用，正在刷新页面...';
          utils.showToast('钩子已启用，刷新页面以捕获 /getRouters', 'success');
          await chrome.tabs.reload(tab.id);
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
      } else if (!data.enabled) {
        if (statusEl) statusEl.textContent = '钩子已安装但未启用';
        hookStatus = 'idle';
        setHookUI(false);
      } else if (!data.captured) {
        var logInfo = data.logCount > 0 ? '，已拦截 ' + data.logCount + ' 个请求' : '';
        var restoreInfo = data.restored ? ' [已恢复]' : '';
        if (statusEl)
          statusEl.textContent = '监听中，等待 /getRouters 请求...' + logInfo + restoreInfo;
        hookStatus = 'active';
        setHookUI(true);
        renderRequestLog(tab.id);
      } else {
        hookStatus = 'captured';
        setHookUI(true);
        var modeText = data.augmentMode || 'auto';
        var extras = data.extraRouteCount > 0 ? '，' + data.extraRouteCount + ' 条额外路由' : '';
        var capRestore = data.restored ? ' [已恢复]' : '';
        if (statusEl)
          statusEl.textContent =
            '已捕获路由数据 (' + modeText + ' 模式' + extras + ')' + capRestore;
        await fetchCapturedRoutes();
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
