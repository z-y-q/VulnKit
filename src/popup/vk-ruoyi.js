// VulnKit - RuoYi Dynamic Route Module
window.VulnKitRuoYi = (function () {
  'use strict';

  function getUtils() { return window.VulnKitUtils || null; }
  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
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

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function getActiveTab() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
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
          var scripts = document.querySelectorAll('script[src]');
          scripts.forEach(function (s) {
            var src = s.src || '';
            if (/\/request\.js/i.test(src)) evidence.push('script:request.js');
            if (/\/auth\.js/i.test(src)) evidence.push('script:auth.js');
            if (/\/permission\.js/i.test(src)) evidence.push('script:permission.js');
            if (/\/validate\.js/i.test(src)) evidence.push('script:validate.js');
            if (/\/ruoyi/i.test(src)) evidence.push('script:ruoyi');
            if (/\/router\/index\.js/i.test(src)) evidence.push('script:router/index.js');
            if (/\/store\/modules\/(user|permission|app)\.js/i.test(src)) evidence.push('script:store');
          });

          if (document.querySelector('.app-container') && document.querySelector('.sidebar-container')) {
            evidence.push('layout:ruoyi-sidebar');
          }

          var title = document.title || '';
          if (/若依|RuoYi|管理系统/i.test(title)) evidence.push('title:若依/RuoYi');

          var hasEl = !!window.ELEMENT || !!window.ElPlus || document.querySelector('[class*="el-"]');
          if (hasEl) evidence.push('ui:element');

          if (window.__CONFIG__) evidence.push('global:__CONFIG__');

          // Check for common RuoYi API patterns in inline scripts
          var inline = document.querySelectorAll('script:not([src])');
          inline.forEach(function (s) {
            var t = s.textContent || '';
            if (/getRouters|getUserInfo|permission\.js|store\.dispatch.*permission/i.test(t)) {
              if (evidence.indexOf('code:ruoyi-pattern') === -1) evidence.push('code:ruoyi-pattern');
            }
          });

          return { detected: evidence.length >= 2, evidence: evidence };
        },
      });

      var data = (results && results[0] && results[0].result) || { detected: false, evidence: [] };

      if (data.detected) {
        var html = '<div class="ruoyi-detect-info">';
        html += '<div class="ruoyi-detect-badge ruoyi-badge-ok">RuoYi 框架已检测到</div>';
        html += '<div class="ruoyi-evidence-list">';
        data.evidence.forEach(function (e) {
          html += '<span class="ruoyi-evidence-item">' + utils.escapeHtml(e) + '</span>';
        });
        html += '</div></div>';
        if (resultsEl) resultsEl.innerHTML = html;
        if (statusEl) statusEl.textContent = '检测到 RuoYi 框架 (' + data.evidence.length + ' 个特征)';
        utils.showToast('检测到 RuoYi 框架', 'success');
      } else if (data.evidence.length > 0) {
        var html2 = '<div class="ruoyi-detect-info">';
        html2 += '<div class="ruoyi-detect-badge ruoyi-badge-warn">疑似 RuoYi (' + data.evidence.length + ' 个特征)</div>';
        html2 += '<div class="ruoyi-evidence-list">';
        data.evidence.forEach(function (e) {
          html2 += '<span class="ruoyi-evidence-item">' + utils.escapeHtml(e) + '</span>';
        });
        html2 += '</div></div>';
        if (resultsEl) resultsEl.innerHTML = html2;
        if (statusEl) statusEl.textContent = '疑似 RuoYi (' + data.evidence.length + ' 个特征)';
      } else {
        if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">当前页面未检测到 RuoYi 框架特征</div>';
        if (statusEl) statusEl.textContent = '未检测到 RuoYi';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '检测出错';
      utils.showToast('检测失败: ' + e.message, 'error');
    }
  }

  // ====== Route Hook ======

  async function installRouteHook() {
    var statusEl = utils.get('ruoyi-hook-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }

      if (statusEl) statusEl.textContent = '安装钩子中...';

      // Enable the hook in MAIN world
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (mode) {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.enabled = true;
            window.__VK_RUOYI_HOOK__.augmentMode = mode || 'auto';
            return true;
          }
          return false;
        },
        args: [augmentMode],
      });

      var hookResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () { return !!window.__VK_RUOYI_HOOK__; },
      });

      if (!(hookResult && hookResult[0] && hookResult[0].result)) {
        utils.showToast('钩子未安装 — 需要在页面加载前注入，请刷新页面后重试', 'warning');
        if (statusEl) statusEl.textContent = '钩子未注入，请刷新页面后重试';
        return;
      }

      ruoyiHookActive = true;
      ruoyiTabId = tab.id;
      hookStatus = 'active';
      chrome.storage.local.set({ ruoyiHookTabId: tab.id });

      var installBtn = utils.get('ruoyi-hook-install-btn');
      var removeBtn = utils.get('ruoyi-hook-remove-btn');
      if (installBtn) installBtn.disabled = true;
      if (removeBtn) removeBtn.disabled = false;
      if (statusEl) statusEl.textContent = '钩子已启用，请刷新页面捕获 /getRouters 响应';
      utils.showToast('路由钩子已启用，请刷新页面', 'success');
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
          }
        },
      });

      ruoyiHookActive = false;
      ruoyiTabId = null;
      hookStatus = 'idle';
      chrome.storage.local.remove('ruoyiHookTabId');

      var installBtn = utils.get('ruoyi-hook-install-btn');
      var removeBtn = utils.get('ruoyi-hook-remove-btn');
      if (installBtn) installBtn.disabled = false;
      if (removeBtn) removeBtn.disabled = true;
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
          if (!hook) return { installed: false };
          return {
            installed: true,
            enabled: hook.enabled,
            captured: !!hook.capturedRouters,
            augmentMode: hook.augmentMode,
            extraRouteCount: (hook.extraRoutes || []).length,
          };
        },
      });

      var data = (results && results[0] && results[0].result) || { installed: false };

      if (!data.installed) {
        if (statusEl) statusEl.textContent = '钩子未安装（需刷新页面后才能使用）';
        hookStatus = 'idle';
        if (panelEl) panelEl.innerHTML = '<div class="empty-state">钩子未注入到当前页面</div>';
      } else if (!data.enabled) {
        if (statusEl) statusEl.textContent = '钩子已安装但未启用';
        hookStatus = 'idle';
      } else if (!data.captured) {
        if (statusEl) statusEl.textContent = '监听中，等待 /getRouters 请求...';
        hookStatus = 'active';
      } else {
        hookStatus = 'captured';
        var modeText = data.augmentMode || 'auto';
        if (statusEl) statusEl.textContent = '已捕获路由数据 (' + modeText + ' 模式, ' + data.extraRouteCount + ' 条额外路由)';
        await fetchCapturedRoutes();
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '检查失败';
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

      var data = (results && results[0] && results[0].result);
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
      containerEl.innerHTML = '<div class="empty-state">' + (data._raw ? '响应解析失败' : '无路由数据') + '</div>';
      return;
    }

    var totalPaths = 0;
    (function count(rts) { rts.forEach(function (r) { totalPaths++; if (r.children) count(r.children); }); })(routes);

    var html = '<div class="ruoyi-route-summary">共 ' + routes.length + ' 个顶级路由，' + totalPaths + ' 个节点</div>';
    html += '<div class="ruoyi-route-tree">';
    routes.forEach(function (r) { html += renderRouteNode(r, 0); });
    html += '</div>';
    containerEl.innerHTML = html;

    containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var children = btn.closest('.ruoyi-route-node').querySelector('.ruoyi-route-children');
        if (children) {
          var hidden = children.style.display === 'none';
          children.style.display = hidden ? 'block' : 'none';
          btn.textContent = hidden ? '▼' : '▶';
        }
      });
    });
  }

  function renderRouteNode(route, depth) {
    var indent = depth * 16;
    var path = route.path || '/';
    var name = route.name || '';
    var title = (route.meta && route.meta.title) || '';
    var hidden = route.hidden;
    var hasChildren = route.children && route.children.length > 0;
    var component = route.component || '';

    var html = '<div class="ruoyi-route-node" style="padding-left:' + indent + 'px">';
    html += '<span class="ruoyi-route-toggle">' + (hasChildren ? '▼' : '►') + '</span>';
    if (hidden) html += '<span class="ruoyi-route-hidden" title="hidden">H</span>';
    html += '<span class="ruoyi-route-path">' + utils.escapeHtml(path) + '</span>';
    if (name) html += '<span class="ruoyi-route-name">' + utils.escapeHtml(name) + '</span>';
    if (title) html += '<span class="ruoyi-route-title">' + utils.escapeHtml(title) + '</span>';
    if (component && typeof component === 'string') {
      html += '<span class="ruoyi-route-component">' + utils.escapeHtml(component.split('/').pop()) + '</span>';
    }
    if (hasChildren) {
      html += '<div class="ruoyi-route-children">';
      route.children.forEach(function (child) { html += renderRouteNode(child, depth + 1); });
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
          if (window.__VK_RUOYI_HOOK__ && typeof window.__VK_RUOYI_HOOK__.discoverRoutesFromJs === 'function') {
            return window.__VK_RUOYI_HOOK__.discoverRoutesFromJs();
          }
          return null;
        },
      });

      var result = (discoverResults && discoverResults[0] && discoverResults[0].result) || { discovered: [], extUrls: [] };
      discoveredRoutes = result.discovered || [];
      var extUrls = result.extUrls || [];

      if (statusEl) statusEl.textContent = '发现 ' + discoveredRoutes.length + ' 条路径，正在扫描外部JS (' + extUrls.length + ' 个文件)...';

      // Step 2: Fetch external scripts via background proxy
      var CONCURRENCY = 5;
      var routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
      var skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)/i;

      for (var batchStart = 0; batchStart < extUrls.length; batchStart += CONCURRENCY) {
        var batch = extUrls.slice(batchStart, batchStart + CONCURRENCY);
        var batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }).catch(function () { return null; });
          })
        );
        for (var b = 0; b < batchResults.length; b++) {
          var resp = batchResults[b];
          if (!resp || resp.error || !resp.data) continue;
          var text = resp.data;
          routePattern.lastIndex = 0;
          var m;
          while ((m = routePattern.exec(text)) !== null) {
            var p = m[1];
            if (skipRe.test(p) || p.length < 4) continue;
            var alreadyExists = discoveredRoutes.some(function (r) { return r.path === p; });
            if (!alreadyExists) {
              var shortUrl = batch[b];
              if (shortUrl.length > 50) shortUrl = '...' + shortUrl.substring(shortUrl.length - 47);
              discoveredRoutes.push({ path: p, source: shortUrl, type: 'route-def' });
            }
          }
        }
      }

      // Step 3: Filter against captured router data
      var capturedPaths = {};
      if (capturedRouterData) {
        extractPaths(capturedRouterData.data || capturedRouterData, capturedPaths);
      }

      extraRoutes = discoveredRoutes.filter(function (r) {
        return !capturedPaths[r.path];
      });

      // Sort by path
      extraRoutes.sort(function (a, b) { return a.path.localeCompare(b.path); });

      if (statusEl) statusEl.textContent = '分析完成，发现 ' + extraRoutes.length + ' 条额外路由';

      if (extraRoutes.length > 0) {
        var html = '<div class="ruoyi-discovery-summary">发现 ' + discoveredRoutes.length + ' 条路径，' + extraRoutes.length + ' 条不在当前路由中</div>';
        html += '<div class="ruoyi-extra-routes">';
        extraRoutes.forEach(function (r, i) {
          html += '<div class="ruoyi-extra-route-item">';
          html += '<label><input type="checkbox" class="ruoyi-route-check" data-idx="' + i + '" checked> ';
          html += '<span class="ruoyi-route-path">' + utils.escapeHtml(r.path) + '</span></label>';
          if (r.source) html += '<span class="ruoyi-route-source">' + utils.escapeHtml(r.source) + '</span>';
          html += '</div>';
        });
        html += '</div>';
        if (resultsEl) resultsEl.innerHTML = html;
        utils.showToast('发现 ' + extraRoutes.length + ' 条额外路由', 'success');
      } else {
        if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">' +
          (discoveredRoutes.length > 0 ? '所有发现的路径均已注册' : '未发现路由定义') + '</div>';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '分析出错';
      utils.showToast('分析失败: ' + e.message, 'error');
    }
  }

  function extractPaths(routes, map) {
    if (!routes || !Array.isArray(routes)) return;
    routes.forEach(function (r) {
      if (r.path) map[r.path] = true;
      if (r.children) extractPaths(r.children, map);
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

      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (routes) {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.extraRoutes = routes;
            window.__VK_RUOYI_HOOK__.augmentMode = 'auto';
          }
        },
        args: [selected],
      });

      extraRoutes = selected;
      if (statusEl) statusEl.textContent = '已设置 ' + selected.length + ' 条额外路由，刷新页面生效';
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
      var resultsEl = utils.get('ruoyi-analyze-results');
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
    utils.copyText(extraRoutes.map(function (r) { return r.path; }).join('\n'));
    utils.showToast('已复制 ' + extraRoutes.length + ' 条路径', 'success');
  }

  function toggleSelectAll() {
    var checks = document.querySelectorAll('.ruoyi-route-check');
    var allChecked = checks.length > 0 && Array.from(checks).every(function (cb) { return cb.checked; });
    checks.forEach(function (cb) { cb.checked = !allChecked; });
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
    get ruoyiHookActive() { return ruoyiHookActive; },
    set ruoyiHookActive(v) { ruoyiHookActive = v; },
    get ruoyiTabId() { return ruoyiTabId; },
    set ruoyiTabId(v) { ruoyiTabId = v; },
    get hookStatus() { return hookStatus; },
    set hookStatus(v) { hookStatus = v; },
    get extraRoutes() { return extraRoutes; },
    set extraRoutes(v) { extraRoutes = v; },
    get augmentMode() { return augmentMode; },
    set augmentMode(v) { augmentMode = v; },
  };
})();
