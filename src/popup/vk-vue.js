window.VulnKitVue = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  // ====== Vue Analysis ======
  let lastVueResult = '';
  let permInterceptActive = false;
  let permCapturedData = [];
  let permSelectedIndex = -1;
  let permViewMode = 'list';
  let permRefreshTimer = null;
  let permCapturedLength = -1;
  let lastCompareHiddenRoutes = [];
  let lastJsMatchContexts = [];
  let jsSearchFoundPaths = [];

  function startPermAutoRefresh() {
    stopPermAutoRefresh();
    permRefreshTimer = setInterval(function () {
      if (permInterceptActive && permViewMode === 'list') {
        refreshPermCaptured();
      }
    }, 5000);
  }

  function stopPermAutoRefresh() {
    if (permRefreshTimer) {
      clearInterval(permRefreshTimer);
      permRefreshTimer = null;
    }
  }

  async function detectOnce(tabId) {
    try {
      var data = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
      if (!data || !data.detected) return data;
      return data;
    } catch (e) {
      // Content script not loaded yet, inject it on-the-fly then retry
      try {
        await utils.execInTab(tabId, ['src/content/vk-content.js'], { world: 'ISOLATED' });
        await sleep(100);
        var data2 = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
        if (!data2 || !data2.detected) return data2;
        return data2;
      } catch (e2) {
        return null;
      }
    }
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  async function detectWithRetry(tabId) {
    var delays = [0, 300, 600];
    for (var i = 0; i < delays.length; i++) {
      if (i > 0) await sleep(delays[i]);
      var result = await detectOnce(tabId);
      if (result && result.detected) return result;
    }
    return null;
  }

  async function detectVue() {
    const statusEl = utils.get('vue-status');
    const resultsEl = utils.get('vue-results');
    if (!statusEl || !resultsEl) return;

    statusEl.textContent = '检测中...';
    resultsEl.innerHTML = '';

    try {
      const tab = await utils.requireTabId();
      if (!tab) {
        statusEl.textContent = '无法获取当前标签页';
        return;
      }

      const data = await detectWithRetry(tab.id);

      if (!data) {
        statusEl.textContent = '未检测到 Vue';
        resultsEl.innerHTML = utils.emptyHtml('当前页面未使用 Vue 框架');
        return;
      }

      statusEl.textContent = '检测到 Vue ' + data.version;

      var ri = data.routerInfo || {};
      lastRouterBase = ri.base || '/';
      lastRouterMode = ri.mode || 'history';
      lastPageOrigin = data.pageOrigin || '';

      let html = '';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">版本</span><span class="vue-info-value"><span class="vue-badge vue-badge-ok">Vue ' +
        utils.escapeHtml(data.version) +
        '</span></span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">Vue Router</span><span class="vue-info-value">' +
        (data.router
          ? '<span class="vue-badge vue-badge-ok">已检测 (' +
            utils.escapeHtml(ri.mode || '?') +
            ' 模式)</span>'
          : '未检测到') +
        '</span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">Base Path</span><span class="vue-info-value">' +
        utils.escapeHtml(ri.base || '/') +
        '</span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">状态管理</span><span class="vue-info-value">' +
        (data.store ? '<span class="vue-badge vue-badge-warn">已检测</span>' : '未检测到') +
        '</span></div>';

      if (data.router && data.routes.length > 0) {
        html += '<div class="card-spacing"><div class="vue-route-toolbar">';
        html += '<span class="vue-route-count">路由列表 (' + data.routes.length + ')</span>';
        html +=
          '<button class="btn btn-xs btn-outline vue-copy-hist-btn">复制 History URL</button>';
        html += '<button class="btn btn-xs btn-outline vue-copy-hash-btn">复制 Hash URL</button>';
        html += '</div></div>';
        html += renderRouteTree(data.routes, 0, ri.base || '/', ri.mode || 'history');
      }

      resultsEl.innerHTML = html;
      lastVueResult = JSON.stringify(data, null, 2);
    } catch (e) {
      statusEl.textContent = '检测出错';
      resultsEl.innerHTML = utils.emptyHtml(e.message);
    }
  }

  var lastRouterBase = '/';
  var lastRouterMode = 'history';

  var lastPageOrigin = '';

  function buildRouteUrl(path, base, mode) {
    var origin = lastPageOrigin || 'https://example.com';
    var basePath = base || '/';
    if (basePath.charAt(basePath.length - 1) !== '/') basePath += '/';
    var fullPath = basePath + (path || '/').replace(/^\//, '');
    if (mode === 'hash') {
      return origin + basePath + '#' + (path || '/');
    }
    return origin + fullPath;
  }

  function collectAllPaths(routes, prefix, base, mode) {
    var result = [];
    if (!routes || !Array.isArray(routes)) return result;
    var probeValues = ['1', 'admin', 'test', '0'];
    routes.forEach(function (r) {
      var p = r.path || '/';
      if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
        p = prefix + '/' + p;
      }
      // Keep template route
      var url = buildRouteUrl(p, base, mode);
      result.push({
        path: p,
        url: url,
        name: r.name || '',
        isParam: p.indexOf(':') !== -1 || p.indexOf('*') !== -1,
      });
      // Generate probe paths for parameterized routes
      if (p.indexOf(':') !== -1 || p.indexOf('*') !== -1) {
        var probePath = p.replace(/:[^/]+/g, '1').replace(/\*/g, 'test');
        var probeUrl = buildRouteUrl(probePath, base, mode);
        result.push({
          path: probePath,
          url: probeUrl,
          name: (r.name || '') + ':probe',
          isProbe: true,
        });
      }
      if (r.children && r.children.length > 0) {
        var childPaths = collectAllPaths(r.children, p === '/' ? '/' : p, base, mode);
        result = result.concat(childPaths);
      }
    });
    return result;
  }

  function renderRouteTree(routes, depth, base, mode) {
    let html = '';
    if (!routes || !Array.isArray(routes) || depth > 10) return html;
    base = base || '/';
    mode = mode || 'history';
    routes.forEach(route => {
      var routePath = route.path || '/';
      var histUrl = buildRouteUrl(routePath, base, 'history');
      var hashUrl = buildRouteUrl(routePath, base, 'hash');

      html += '<div class="vue-route-item vue-depth-' + depth + '">';
      html += '<span class="vue-route-path">' + utils.escapeHtml(routePath) + '</span>';
      if (route.name)
        html += '<span class="vue-route-name">' + utils.escapeHtml(route.name) + '</span>';
      if (route.meta) {
        try {
          var metaStr = JSON.stringify(route.meta).substring(0, 60);
          html += '<span class="vue-route-meta">meta: ' + utils.escapeHtml(metaStr) + '</span>';
        } catch (e) {
          html += '<span class="vue-route-meta">meta: [无法序列化]</span>';
        }
      }
      html += '<span class="vue-route-urls">';
      html +=
        '<button class="vue-route-open-btn" data-url="' +
        utils.escapeHtml(histUrl) +
        '" title="' +
        utils.escapeHtml(histUrl) +
        '">H</button>';
      html +=
        '<button class="vue-route-open-btn" data-url="' +
        utils.escapeHtml(hashUrl) +
        '" title="' +
        utils.escapeHtml(hashUrl) +
        '">#</button>';
      html += '</span>';
      html += '</div>';
      if (route.children && route.children.length > 0) {
        html += renderRouteTree(route.children, depth + 1, base, mode);
      }
    });
    return html;
  }

  async function exportVueRoutes() {
    const tab = await utils.requireTabId();
    if (!tab) return;

    try {
      const results = await utils.execInTab(tab.id, () => {
        function safeSerialize(obj) {
          try {
            return JSON.parse(JSON.stringify(obj));
          } catch (e) {
            return null;
          }
        }
        function getRoutes(router) {
          if (!router) return null;
          if (typeof router.getRoutes === 'function') {
            return router.getRoutes().map(function (r) {
              return { path: r.path, name: r.name || '', meta: safeSerialize(r.meta) || {} };
            });
          }
          return router.options ? safeSerialize(router.options.routes) || null : null;
        }
        const appEl =
          document.querySelector('#app') ||
          document.querySelector('[data-v-app]') ||
          document.querySelector('[id^="app"]') ||
          document.querySelector('#root') ||
          document.querySelector('#application') ||
          document.querySelector('#main');
        if (appEl && appEl.__vue_app__) {
          var r = getRoutes(appEl.__vue_app__.config.globalProperties.$router);
          if (r) return r;
        }
        const allEls = document.querySelectorAll('*');
        for (const el of allEls) {
          if (el.__vue__) {
            const vm = el.__vue__.$root || el.__vue__;
            var r2 = getRoutes(vm.$router);
            if (r2) return r2;
          }
        }
        return null;
      });

      const routes = utils.execResult(results);
      if (!routes) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }

      const json = JSON.stringify(routes, null, 2);
      utils.copyText(json);
      lastVueResult = json;
      utils.showToast('路由已复制 (' + routes.length + ' 条)', 'success');
    } catch (e) {
      utils.showToast('导出失败: ' + e.message, 'error');
    }
  }

  async function bypassVueGuards() {
    const tab = await utils.requireTabId();
    if (!tab) return;

    try {
      const bypassResults = await utils.execInTab(tab.id, () => {
        // Vue 3
        const appEl =
          document.querySelector('#app') ||
          document.querySelector('[data-v-app]') ||
          document.querySelector('[id^="app"]') ||
          document.querySelector('#root') ||
          document.querySelector('#application') ||
          document.querySelector('#main');
        if (appEl && appEl.__vue_app__) {
          const router = appEl.__vue_app__.config.globalProperties.$router;
          if (router) {
            // Vue Router 4: clear internal guard arrays
            if (Array.isArray(router.beforeGuards)) router.beforeGuards.length = 0;
            if (Array.isArray(router.afterGuards)) router.afterGuards.length = 0;
            if (Array.isArray(router.beforeResolveGuards)) router.beforeResolveGuards.length = 0;
            // Clear per-route beforeEnter guards
            if (router.options && Array.isArray(router.options.routes)) {
              (function clearRouteGuards(routes) {
                for (var i = 0; i < routes.length; i++) {
                  if (typeof routes[i].beforeEnter === 'function') {
                    routes[i].beforeEnter = undefined;
                  }
                  if (routes[i].children) clearRouteGuards(routes[i].children);
                }
              })(router.options.routes);
            }
            return 'vue3';
          }
        }
        // Vue 2
        const allEls = document.querySelectorAll('*');
        for (const el of allEls) {
          if (el.__vue__) {
            const vm = el.__vue__.$root || el.__vue__;
            if (vm.$router) {
              if (Array.isArray(vm.$router.beforeHooks)) vm.$router.beforeHooks.length = 0;
              if (Array.isArray(vm.$router.afterHooks)) vm.$router.afterHooks.length = 0;
              if (Array.isArray(vm.$router.beforeResolveHooks))
                vm.$router.beforeResolveHooks.length = 0;
              return 'vue2';
            }
          }
        }
        return null;
      });

      const result = utils.execResult(bypassResults);
      if (!result) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }
      utils.showToast('路由守卫已清除 (Vue ' + (result === 'vue3' ? '3' : '2') + ')', 'success');
    } catch (e) {
      utils.showToast('绕过失败: ' + e.message, 'error');
    }
  }

  async function disableRouteAuth() {
    const tab = await utils.requireTabId();
    if (!tab) return;

    try {
      const results = await utils.execInTab(tab.id, () => {
        var authKeys = [
          'auth',
          'requireAuth',
          'requiresAuth',
          'login',
          'needLogin',
          'requiresLogin',
        ];
        var changed = 0;

        function clearAuthMeta(routes, depth) {
          if (!routes || !Array.isArray(routes) || depth > 20) return;
          for (var i = 0; i < routes.length; i++) {
            var route = routes[i];
            if (route.meta && typeof route.meta === 'object') {
              for (var j = 0; j < authKeys.length; j++) {
                if (authKeys[j] in route.meta && route.meta[authKeys[j]]) {
                  route.meta[authKeys[j]] = false;
                  changed++;
                }
              }
            }
            if (route.children) clearAuthMeta(route.children, depth + 1);
          }
        }

        // Vue 3
        var appEl =
          document.querySelector('#app') ||
          document.querySelector('[data-v-app]') ||
          document.querySelector('[id^="app"]') ||
          document.querySelector('#root') ||
          document.querySelector('#application') ||
          document.querySelector('#main');
        if (appEl && appEl.__vue_app__) {
          var router = appEl.__vue_app__.config.globalProperties.$router;
          if (router) {
            if (router.options && router.options.routes) clearAuthMeta(router.options.routes, 0);
            var flatRoutes;
            try {
              flatRoutes = router.getRoutes();
            } catch (e) {}
            if (flatRoutes) {
              for (var k = 0; k < flatRoutes.length; k++) {
                if (flatRoutes[k].meta && typeof flatRoutes[k].meta === 'object') {
                  for (var m = 0; m < authKeys.length; m++) {
                    if (authKeys[m] in flatRoutes[k].meta && flatRoutes[k].meta[authKeys[m]]) {
                      flatRoutes[k].meta[authKeys[m]] = false;
                      changed++;
                    }
                  }
                }
              }
            }
            return { version: 'vue3', changed: changed };
          }
        }

        // Vue 2
        var allEls = document.querySelectorAll('*');
        for (var n = 0; n < allEls.length; n++) {
          if (allEls[n].__vue__) {
            var vm = allEls[n].__vue__.$root || allEls[n].__vue__;
            if (vm.$router && vm.$router.options && vm.$router.options.routes) {
              clearAuthMeta(vm.$router.options.routes, 0);
              return { version: 'vue2', changed: changed };
            }
          }
        }

        return null;
      });

      const result = utils.execResult(results);
      if (!result) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }
      if (result.changed > 0) {
        utils.showToast(
          '已修改 ' +
            result.changed +
            ' 条路由 auth (Vue ' +
            (result.version === 'vue3' ? '3' : '2') +
            ')',
          'success'
        );
      } else {
        utils.showToast('未发现需要修改的 auth 字段', 'warning');
      }
    } catch (e) {
      utils.showToast('修改失败: ' + e.message, 'error');
    }
  }

  // ====== Vue Sub-tab Switching ======

  function switchVueSubTab(tab) {
    utils.switchSubTabs('vue-stab', 'vstab', 'vstab', tab);
  }

  // ====== Store Reader (injected into page to read Pinia/Vuex/localStorage) ======
  var permStoreReaderFunc = function () {
    if (!window.__PERM_INTERCEPTOR__) return;
    var MENU_KEYWORDS = [
      'menu',
      'menulist',
      'menuList',
      'menuData',
      'permission',
      'permissions',
      'permList',
      'menuIds',
      'menu_ids',
      'menuId',
      'isAdmin',
      'isadmin',
      'role',
      'roles',
      'getMenu',
      'getMenus',
      'getPermission',
      'getUserInfo',
      'navList',
      'sideMenu',
      'sidebar',
    ];
    function classifyStr(str, url) {
      var urlLower = (url || '').toLowerCase();
      if (/permission/i.test(urlLower)) return 'permission';
      if (/role/i.test(urlLower)) return 'role';
      if (/menu/i.test(urlLower)) return 'menu';
      for (var i = 0; i < MENU_KEYWORDS.length; i++) {
        if (str.indexOf(MENU_KEYWORDS[i]) !== -1) return 'menu';
      }
      return 'other';
    }
    function sanitizeForTransfer(obj, depth) {
      if (obj === null || obj === undefined) return obj;
      if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean')
        return obj;
      if (typeof obj === 'function') return '[function]';
      if (obj instanceof HTMLElement) return '[HTMLElement]';
      if (obj instanceof RegExp) return '[RegExp]';
      if (depth > 12) return '[max-depth]';
      if (Array.isArray(obj)) {
        return obj.map(function (item) {
          return sanitizeForTransfer(item, depth + 1);
        });
      }
      if (typeof obj === 'object') {
        var skipKeys = {
          component: 1,
          _Ctor: 1,
          _compiled: 1,
          _scopeId: 1,
          staticRenderFns: 1,
          render: 1,
          beforeCreate: 1,
          created: 1,
          beforeMount: 1,
          mounted: 1,
          beforeUpdate: 1,
          updated: 1,
          beforeDestroy: 1,
          destroyed: 1,
          activated: 1,
          deactivated: 1,
          mixins: 1,
          extends: 1,
          directives: 1,
          filters: 1,
          _ssrRegister: 1,
          __file: 1,
          _functional: 1,
          _inject: 1,
          _provided: 1,
          model: 1,
          inheritAttrs: 1,
          comments: 1,
        };
        var result = {};
        try {
          var keys = Object.keys(obj);
          for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            if (skipKeys[k]) {
              if (k === 'component') {
                var v = obj[k];
                result[k] =
                  v && (v.name || v.__name || v.displayName)
                    ? '[component: ' + (v.name || v.__name || v.displayName) + ']'
                    : '[component]';
              }
              continue;
            }
            result[k] = sanitizeForTransfer(obj[k], depth + 1);
          }
        } catch (e) {
          return '[error-reading-keys]';
        }
        return result;
      }
      return String(obj);
    }
    function tryAdd(data, url) {
      if (!data || typeof data === 'string') return;
      var cap = window.__PERM_INTERCEPTOR__.captured;
      for (var di = 0; di < cap.length; di++) {
        if (cap[di].url === url && cap[di].method === 'store-read') return;
      }
      var clean = sanitizeForTransfer(data, 0);
      var str = JSON.stringify(clean);
      var type = classifyStr(str, url);
      if (type !== 'other') {
        cap.push({
          url: url,
          type: type,
          subtype: null,
          data: clean,
          rawText: str,
          size: str.length,
          timestamp: Date.now(),
          method: 'store-read',
        });
      }
    }
    // Check Vue 3 Pinia stores
    var appEl =
      document.querySelector('#app') ||
      document.querySelector('[data-v-app]') ||
      document.querySelector('[id^="app"]') ||
      document.querySelector('#root') ||
      document.querySelector('#application') ||
      document.querySelector('#main');
    if (appEl && appEl.__vue_app__) {
      var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
      if (pinia && pinia._s) {
        pinia._s.forEach(function (store, id) {
          var state = store.$state;
          for (var key in state) {
            if (
              /menu|permission|nav|route|sidebar/i.test(key) &&
              (Array.isArray(state[key]) || (typeof state[key] === 'object' && state[key] !== null))
            ) {
              tryAdd(state[key], 'pinia://' + id + '/' + key);
            }
          }
        });
      }
    }
    // Check Vue 2 Vuex store
    var allEls = document.querySelectorAll('*');
    for (var i = 0; i < allEls.length; i++) {
      if (allEls[i].__vue__) {
        var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
        if (vm.$store && vm.$store.state) {
          for (var key in vm.$store.state) {
            if (
              /menu|permission|nav|route|sidebar/i.test(key) &&
              (Array.isArray(vm.$store.state[key]) ||
                (typeof vm.$store.state[key] === 'object' && vm.$store.state[key] !== null))
            ) {
              tryAdd(vm.$store.state[key], 'vuex://state/' + key);
            }
          }
        }
        break;
      }
    }
    // Check localStorage for menu-like keys
    var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar'];
    for (var s = 0; s < localStorage.length; s++) {
      var storageKey = localStorage.key(s);
      if (storageKey) {
        for (var p = 0; p < storagePrefixes.length; p++) {
          if (storageKey.toLowerCase().indexOf(storagePrefixes[p]) !== -1) {
            try {
              var parsed = JSON.parse(localStorage.getItem(storageKey));
              tryAdd(parsed, 'localStorage://' + storageKey);
            } catch (e) {}
            break;
          }
        }
      }
    }
  };

  // ====== Permission Menu Interceptor ======
  var permInterceptorFunc = function () {
    if (window.__PERM_INTERCEPTOR__) {
      window.__PERM_INTERCEPTOR__.active = true;
      return 'already_injected';
    }

    var MENU_KEYWORDS = [
      'menu',
      'menulist',
      'menuList',
      'menuData',
      'permission',
      'permissions',
      'permList',
      'menuIds',
      'menu_ids',
      'menuId',
      'isAdmin',
      'isadmin',
      'role',
      'roles',
      'getMenu',
      'getMenus',
      'getPermission',
      'getUserInfo',
      'navList',
      'sideMenu',
      'sidebar',
    ];

    var URL_MENU_PATTERNS = [
      /\/api\/.*menu/i,
      /\/api\/.*permission/i,
      /\/api\/.*role/i,
      /\/api\/.*user.*info/i,
      /\/api\/.*auth/i,
      /\/api\/.*nav/i,
      /\/menu(?:\/|$|[?#])/i,
      /\/permission(?:\/|$|[?#])/i,
      /\/getMenu/i,
      /\/getUserInfo/i,
      /\/getRouters/i,
      /\/getRoutes(?:\/|$|[?#])/i,
    ];

    function classifyResponse(data, url) {
      var urlLower = url.toLowerCase();
      try {
        var json = typeof data === 'string' ? JSON.parse(data) : data;
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          var keys = Object.keys(json);
          for (var k = 0; k < keys.length; k++) {
            if (
              /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
                keys[k]
              )
            )
              return { type: 'role', subtype: 'special_zero' };
          }
          for (var k = 0; k < keys.length; k++) {
            for (var i = 0; i < MENU_KEYWORDS.length; i++) {
              if (keys[k].toLowerCase() === MENU_KEYWORDS[i].toLowerCase())
                return { type: 'menu', subtype: null };
            }
          }
        }
      } catch (e) {}
      if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
      if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
      if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
      return { type: 'other', subtype: null };
    }

    function parseBody(text) {
      try {
        var json = JSON.parse(text);
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          if (json.data !== undefined) return json.data;
          if (json.result !== undefined) return json.result;
          if (json.Data !== undefined) return json.Data;
          if (json.Result !== undefined) return json.Result;
        }
        return json;
      } catch (e) {
        return text;
      }
    }

    var captured = [];

    var originalFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      return originalFetch
        .apply(this, args)
        .then(function (response) {
          if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active) {
            var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
            var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
              return p.test(url);
            });
            if (isMenuApi) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              if (override !== null && override !== undefined) {
                var overrideBody = JSON.stringify(override);
                try {
                  var info = classifyResponse(override, url);
                  if (info.type !== 'other') {
                    captured.push({
                      url: url,
                      type: info.type,
                      subtype: info.subtype,
                      data: override,
                      rawText: overrideBody,
                      size: overrideBody.length,
                      timestamp: Date.now(),
                      method: 'fetch-override',
                    });
                  }
                } catch (e) {}
                return new Response(overrideBody, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              } else {
                var cloned = response.clone();
                cloned
                  .text()
                  .then(function (text) {
                    try {
                      var parsed = parseBody(text);
                      var info = classifyResponse(parsed, url);
                      if (info.type !== 'other') {
                        captured.push({
                          url: url,
                          type: info.type,
                          subtype: info.subtype,
                          data: parsed,
                          rawText: text,
                          size: text.length,
                          timestamp: Date.now(),
                          method: 'fetch',
                        });
                      }
                    } catch (e) {}
                  })
                  .catch(function () {});
              }
            }
          }
          return response;
        })
        .catch(function (err) {
          throw err;
        });
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__perm_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var self = this;
      if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active && this.__perm_url) {
        var url = this.__perm_url;
        var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
          return p.test(url);
        });
        if (isMenuApi) {
          this.addEventListener('readystatechange', function () {
            if (self.readyState === 4) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              var originalText = self.responseText;
              if (override !== null && override !== undefined) {
                try {
                  var overrideBody = JSON.stringify(override);
                  Object.defineProperty(self, 'responseText', {
                    value: overrideBody,
                    writable: true,
                    configurable: true,
                  });
                  Object.defineProperty(self, 'response', {
                    value: overrideBody,
                    writable: true,
                    configurable: true,
                  });
                } catch (e) {}
              }
              try {
                var text =
                  override !== null && override !== undefined
                    ? JSON.stringify(override)
                    : originalText;
                if (!text) return;
                var parsed = parseBody(text);
                var info = classifyResponse(parsed, url);
                if (info.type !== 'other') {
                  captured.push({
                    url: url,
                    type: info.type,
                    subtype: info.subtype,
                    data: parsed,
                    rawText: text,
                    size: text.length,
                    timestamp: Date.now(),
                    method: override != null ? 'xhr-override' : 'xhr',
                  });
                }
              } catch (e) {}
            }
          });
        }
      }
      return origSend.apply(this, arguments);
    };

    window.__PERM_INTERCEPTOR__ = {
      active: true,
      captured: captured,
      getCaptured: function () {
        return captured;
      },
      clear: function () {
        captured.length = 0;
      },
      stop: function () {
        this.active = false;
      },
      start: function () {
        this.active = true;
      },
      _overrideData: null,
      getOverride: function () {
        return this._overrideData;
      },
      setOverride: function (d) {
        this._overrideData = d;
      },
    };
    return 'injected';
  };

  async function startPermInterception() {
    var statusEl = utils.get('perm-status');
    try {
      const tab = await utils.requireTabId();
      if (!tab) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }
      var results = await utils.execInTab(tab.id, permInterceptorFunc);
      var status = utils.execResult(results);
      if (status === 'already_injected') {
        await utils.execInTab(tab.id, function () {
          if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.start();
        });
      }
      permInterceptActive = true;
      chrome.storage.local.set({ permInterceptTabId: tab.id });
      utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', true);
      if (statusEl) statusEl.textContent = '拦截中... 请操作页面触发菜单API请求，或刷新页面';
      utils.showToast('拦截已启动，请操作页面或刷新页面', 'success');
      // Try to read already-loaded data from Vue/Pinia/Vuex stores
      try {
        await utils.execInTab(tab.id, permStoreReaderFunc);
      } catch (e) {
        // Non-critical: store reading is best-effort
      }
      renderPermList();
      startPermAutoRefresh();
    } catch (e) {
      if (statusEl) statusEl.textContent = '启动失败: ' + e.message;
    }
  }

  async function stopPermInterception() {
    stopPermAutoRefresh();
    try {
      const tab = await utils.requireTabId();
      if (!tab) return;
      await utils.execInTab(tab.id, function () {
        if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.stop();
      });
      permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', false);
      utils.setStatus('perm-status', '拦截已停止');
      utils.showToast('拦截已停止', 'info');
    } catch (e) {
      permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.setStatus('perm-status', '停止失败: ' + (e.message || '未知错误'));
      utils.showToast('停止拦截失败', 'error');
    }
  }

  async function refreshPermCaptured() {
    try {
      const tab = await utils.requireTabId();
      if (!tab) return;
      var results = await utils.execInTab(tab.id, function () {
        if (!window.__PERM_INTERCEPTOR__) return { items: [], length: 0 };
        var captured = window.__PERM_INTERCEPTOR__.getCaptured();
        return { items: captured, length: captured.length };
      });
      var result = utils.execResult(results) || { items: [], length: 0 };
      if (result.length === permCapturedLength) return;
      permCapturedLength = result.length;
      permCapturedData = result.items || [];
      renderPermList();
    } catch (e) {
      utils.showToast('获取捕获数据失败', 'error');
    }
  }

  function renderPermList() {
    var container = utils.get('perm-captured-list');
    var countEl = utils.get('perm-count');
    if (!container) return;
    var filterVal = (utils.get('perm-filter') ? utils.get('perm-filter').value : '').toLowerCase();
    var typeFilter = utils.get('perm-type-filter') ? utils.get('perm-type-filter').value : 'all';

    var filtered = permCapturedData.filter(function (item) {
      if (filterVal && item.url.toLowerCase().indexOf(filterVal) === -1) return false;
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      return true;
    });

    if (filtered.length === 0) {
      utils.setEmpty('perm-captured-list', '暂无捕获数据，请先操作页面触发菜单请求');
      if (countEl)
        countEl.textContent =
          permCapturedData.length > 0 ? '共 ' + permCapturedData.length + ' 条 (筛选后 0)' : '';
      return;
    }

    if (countEl)
      countEl.textContent =
        '共 ' +
        permCapturedData.length +
        ' 条' +
        (filtered.length < permCapturedData.length ? ' (显示 ' + filtered.length + ')' : '');

    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var item = filtered[i];
      var realIdx = permCapturedData.indexOf(item);
      var cls = classifyPermType(item.data);
      var clsLabel = cls.label.split(' - ')[0];
      html += '<div class="perm-item" data-idx="' + realIdx + '">';
      html += '<span class="perm-item-type type-' + item.type + '">' + item.type + '</span>';
      html += '<span class="perm-item-cls ' + cls.cssClass + '">' + clsLabel + '</span>';
      html += '<span class="perm-item-url" title="' + utils.escapeHtml(item.url) + '">';
      html += utils.escapeHtml(item.url) + '</span>';
      html += '<span class="perm-item-size">' + (item.size / 1024).toFixed(1) + 'KB</span>';
      html += '</div>';
    }
    container.innerHTML = html;

    container.querySelectorAll('.perm-item').forEach(function (el) {
      el.addEventListener('click', function () {
        permSelectedIndex = parseInt(this.dataset.idx);
        showPermDetail(permSelectedIndex);
      });
    });
  }

  function showPermDetail(idx) {
    var item = permCapturedData[idx];
    if (!item) return;
    permViewMode = 'detail';
    var capturedList = utils.get('perm-captured-list');
    if (capturedList) capturedList.classList.add('hidden');
    var filterRow = utils.get('perm-filter-row');
    if (filterRow) filterRow.classList.add('hidden');
    var detailPanel = utils.get('perm-detail');
    if (!detailPanel) return;
    detailPanel.classList.remove('hidden');
    var urlEl = utils.get('perm-detail-url');
    if (urlEl) urlEl.textContent = item.url;
    var typeEl = utils.get('perm-detail-type');
    if (typeEl) typeEl.textContent = item.type.toUpperCase();

    var classification = classifyPermType(item.data);
    var classifyEl = utils.get('perm-classify');
    if (classifyEl) {
      classifyEl.textContent = classification.label;
      classifyEl.className = 'perm-classify ' + classification.cssClass;
    }

    if (typeof showPermSuggestions === 'function') showPermSuggestions(classification);

    var permEditor = utils.get('perm-json-editor');
    if (permEditor) permEditor.value = JSON.stringify(item.data, null, 2);
  }

  function classifyPermType(data) {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var k = 0; k < keys.length; k++) {
        if (
          /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
            keys[k]
          )
        ) {
          var val = data[keys[k]];
          if (val === 0 || val === false || val === '0' || val === '' || val === null) {
            return {
              label: '特殊0开放 - ' + keys[k] + '=' + val + '，可修改为1/true/admin',
              cssClass: 'perm-classify-danger',
              type: 'special-zero',
            };
          }
          return {
            label: '特殊0开放 - 检测到角色控制字段',
            cssClass: 'perm-classify-warning',
            type: 'special-zero',
          };
        }
      }
      for (var kt = 0; kt < keys.length; kt++) {
        if (/^type$/i.test(keys[kt])) {
          var tval = data[keys[kt]];
          var roleVals = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
          if (
            (typeof tval === 'string' && roleVals.test(tval)) ||
            (typeof tval === 'number' && tval >= 0 && tval <= 10)
          ) {
            if (tval === 0 || /^(user|normal|guest)$/i.test(String(tval))) {
              return {
                label: '特殊0开放 - ' + keys[kt] + '=' + tval + '，可修改为admin/1',
                cssClass: 'perm-classify-danger',
                type: 'special-zero',
              };
            }
            return {
              label: '特殊0开放 - 检测到角色控制字段 type=' + tval,
              cssClass: 'perm-classify-warning',
              type: 'special-zero',
            };
          }
        }
      }
      for (var k2 = 0; k2 < keys.length; k2++) {
        if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(keys[k2])) {
          var arr = data[keys[k2]];
          if (
            Array.isArray(arr) &&
            arr.length > 0 &&
            arr.every(function (v) {
              return typeof v === 'number';
            })
          ) {
            return {
              label: '菜单ID限制 - ' + keys[k2] + ': [' + arr.join(',') + ']，可展开范围',
              cssClass: 'perm-classify-info',
              type: 'menuid-limit',
            };
          }
        }
      }
    }
    if (Array.isArray(data) && data.length > 0) {
      var allHaveShowField = data.every(function (item) {
        return (
          item &&
          typeof item === 'object' &&
          ('isshow' in item ||
            'isShow' in item ||
            'hidden' in item ||
            'display' in item ||
            'status' in item)
        );
      });
      if (allHaveShowField) {
        var hasHidden = data.some(function (item) {
          return (
            item.isshow === '0' ||
            item.isShow === '0' ||
            item.hidden === true ||
            item.display === false ||
            item.status === 0
          );
        });
        if (hasHidden) {
          return {
            label: '全开放 - 所有菜单已返回，部分标记为隐藏 (isshow/display)',
            cssClass: 'perm-classify-success',
            type: 'full-open',
          };
        }
        return {
          label: '全开放 - 所有菜单已返回且均已显示',
          cssClass: 'perm-classify-success',
          type: 'full-open',
        };
      }
      return {
        label: '半开放 - 返回了部分菜单列表',
        cssClass: 'perm-classify-info',
        type: 'semi-open',
      };
    }
    if (Array.isArray(data) && data.length === 0) {
      return {
        label: '0开放 - 菜单返回为空，需要搜索JS源码',
        cssClass: 'perm-classify-danger',
        type: 'zero-open',
      };
    }
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var inner = data.data || data.result || data.Data;
      if (Array.isArray(inner) && inner.length === 0) {
        return {
          label: '0开放 - 菜单返回为空，需要搜索JS源码',
          cssClass: 'perm-classify-danger',
          type: 'zero-open',
        };
      }
    }
    return {
      label: '未知类型 - 请手动检查数据结构',
      cssClass: 'perm-classify-unknown',
      type: 'unknown',
    };
  }

  function showPermSuggestions(classification) {
    var sugEl = utils.get('perm-suggestions');
    if (!sugEl) return;
    var cType = classification.type || 'unknown';
    var html = '<span class="perm-suggestion-hint">建议操作：</span>';

    // Reset highlight on all action buttons
    var actionBtns = document.querySelectorAll('.perm-detail-actions .btn');
    actionBtns.forEach(function (b) {
      b.classList.remove('btn-suggested');
    });

    if (cType === 'full-open') {
      // Highlight existing "全部显示" button instead of duplicating
      var openAllBtn = utils.get('perm-open-all');
      if (openAllBtn) openAllBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「全部显示」按钮</span>';
    } else if (cType === 'semi-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-compare-inject">对比并补全缺失菜单</button>';
    } else if (cType === 'zero-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-auto-search">自动搜索JS菜单定义</button>';
    } else if (cType === 'special-zero') {
      // Highlight existing "提权至管理员" button
      var adminBtn = utils.get('perm-change-admin');
      if (adminBtn) adminBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「提权至管理员」按钮</span>';
    } else if (cType === 'menuid-limit') {
      // Highlight existing "展开menuIds" button
      var expandBtn = utils.get('perm-expand-ids');
      if (expandBtn) expandBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「展开menuIds」按钮</span>';
    } else {
      sugEl.innerHTML = '';
      sugEl.classList.add('hidden');
      return;
    }
    sugEl.innerHTML = html;
    sugEl.classList.remove('hidden');

    var sugCompareInject = utils.get('sug-compare-inject');
    if (sugCompareInject)
      sugCompareInject.addEventListener('click', async function () {
        try {
          switchVueSubTab('compare');
          await compareRoutesAndMenu();
          if (lastCompareHiddenRoutes.length > 0) {
            switchVueSubTab('perm');
            if (permSelectedIndex < 0 && permCapturedData.length > 0) {
              permSelectedIndex = 0;
              showPermDetail(0);
            }
            autoInjectHiddenRoutes();
          } else {
            utils.showToast('路由对比未发现隐藏路由', 'info');
            switchVueSubTab('perm');
          }
        } catch (e) {
          utils.showToast('对比执行失败: ' + (e instanceof Error ? e.message : String(e)), 'error');
        }
      });
    var sugAutoSearch = utils.get('sug-auto-search');
    if (sugAutoSearch) sugAutoSearch.addEventListener('click', autoSearchForZeroOpen);
  }

  function transformShowAll(data) {
    if (Array.isArray(data)) {
      return data.map(function (item) {
        if (item && typeof item === 'object') {
          var c = {};
          for (var k in item) {
            if (item.hasOwnProperty(k)) c[k] = item[k];
          }
          if ('isshow' in c) c.isshow = '1';
          if ('isShow' in c) c.isShow = '1';
          if ('hidden' in c) c.hidden = false;
          if ('display' in c) c.display = true;
          if ('status' in c) c.status = 1;
          if ('visible' in c) c.visible = true;
          if (c.children) c.children = transformShowAll(c.children);
          if (c.child) c.child = transformShowAll(c.child);
          if (c.subList) c.subList = transformShowAll(c.subList);
          return c;
        }
        return item;
      });
    }
    if (data && typeof data === 'object') {
      var c = {};
      for (var k in data) {
        if (data.hasOwnProperty(k)) c[k] = transformShowAll(data[k]);
      }
      return c;
    }
    return data;
  }

  function permOpenAll() {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    try {
      var data = JSON.parse(editor.value);
      data = transformShowAll(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已将所有 isshow/display 改为显示', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function transformAdmin(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(transformAdmin);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (
        /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
          k
        )
      ) {
        c[k] = typeof data[k] === 'string' ? '1' : 1;
      } else if (k === 'roleId' || k === 'role_id') {
        c[k] = 1;
      } else if (/^type$/i.test(k)) {
        var tv = data[k];
        var roleVals = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
        if (
          (typeof tv === 'string' && roleVals.test(tv)) ||
          (typeof tv === 'number' && tv >= 0 && tv <= 10)
        ) {
          c[k] = typeof tv === 'string' ? 'admin' : 1;
        } else {
          c[k] = tv;
        }
      } else if (typeof data[k] === 'object') {
        c[k] = transformAdmin(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permChangeAdmin() {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    try {
      var data = JSON.parse(editor.value);
      data = transformAdmin(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已提权：角色/管理员字段已修改', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function expandMenuIds(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(expandMenuIds);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(k) && Array.isArray(data[k])) {
        var allNum = data[k].every(function (v) {
          return typeof v === 'number';
        });
        if (allNum && data[k].length > 0) {
          var max = Math.max.apply(null, data[k]);
          var end = Math.max(max, 50);
          var expanded = [];
          for (var i = 1; i <= end; i++) expanded.push(i);
          c[k] = expanded;
          if (data.hasOwnProperty('total') || data.hasOwnProperty('Total')) {
            var tKey = data.hasOwnProperty('total') ? 'total' : 'Total';
            c[tKey] = expanded.length;
          }
          continue;
        }
      }
      if (typeof data[k] === 'object') {
        c[k] = expandMenuIds(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permExpandMenuIds() {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    try {
      var data = JSON.parse(editor.value);
      data = expandMenuIds(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已展开菜单ID范围', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  async function applyPermOverride() {
    var editor = utils.get('perm-json-editor');
    if (!editor) {
      utils.showToast('编辑器未就绪', 'error');
      return;
    }
    var modifiedData;
    try {
      modifiedData = JSON.parse(editor.value);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }

    try {
      const tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      var results = await utils.execInTab(
        tab.id,
        function (overrideData) {
          if (!window.__PERM_INTERCEPTOR__) return false;
          window.__PERM_INTERCEPTOR__.setOverride(overrideData);

          function patchDeepState(state, override) {
            if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
            for (var key in state) {
              if (!state.hasOwnProperty(key)) continue;
              if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
              var val = state[key];
              if (Array.isArray(val)) {
                if (typeof state.__ob__ === 'object' && state.__ob__) {
                  try {
                    state[key].splice(0, state[key].length);
                  } catch (e) {}
                  try {
                    override.forEach(function (item) {
                      state[key].push(item);
                    });
                  } catch (e) {}
                } else {
                  state[key] = override;
                }
                return true;
              }
              if (val && typeof val === 'object' && !Array.isArray(val)) {
                if (patchDeepState(val, override)) return true;
              }
            }
            return false;
          }

          // Vue 3 + Pinia
          var appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
            if (pinia && pinia._s) {
              pinia._s.forEach(function (store) {
                var state = store.$state;
                for (var key in state) {
                  if (!state.hasOwnProperty(key)) continue;
                  if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
                  var val = state[key];
                  if (Array.isArray(val)) {
                    if (store.$patch) {
                      var patch = {};
                      patch[key] = overrideData;
                      store.$patch(patch);
                    } else {
                      state[key] = overrideData;
                    }
                  } else if (val && typeof val === 'object') {
                    patchDeepState(val, overrideData);
                  }
                }
              });
            }
          }

          // Vue 2 + Vuex
          var allEls = document.querySelectorAll('*');
          for (var i = 0; i < allEls.length; i++) {
            if (allEls[i].__vue__) {
              var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
              if (vm.$store && vm.$store.state) {
                patchDeepState(vm.$store.state, overrideData);
              }
              break;
            }
          }

          // Patch localStorage and sessionStorage menu caches
          var storagePatchCount = 0;
          var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar', 'role', 'auth'];
          var storageTargets = [localStorage, sessionStorage];
          for (var st = 0; st < storageTargets.length; st++) {
            var storage = storageTargets[st];
            try {
              for (var si = 0; si < storage.length; si++) {
                var sKey = storage.key(si);
                if (!sKey) continue;
                var sKeyLower = sKey.toLowerCase();
                var matched = false;
                for (var sp = 0; sp < storagePrefixes.length; sp++) {
                  if (sKeyLower.indexOf(storagePrefixes[sp]) !== -1) {
                    matched = true;
                    break;
                  }
                }
                if (!matched) continue;
                try {
                  var sVal = storage.getItem(sKey);
                  var sParsed = JSON.parse(sVal);
                  if (Array.isArray(sParsed)) {
                    storage.setItem(sKey, JSON.stringify(overrideData));
                    storagePatchCount++;
                  } else if (sParsed && typeof sParsed === 'object' && !Array.isArray(sParsed)) {
                    var patched = false;
                    for (var sk in sParsed) {
                      if (!sParsed.hasOwnProperty(sk)) continue;
                      if (
                        /menu|permission|route|nav|sidebar/i.test(sk) &&
                        Array.isArray(sParsed[sk])
                      ) {
                        sParsed[sk] = overrideData;
                        patched = true;
                      }
                    }
                    if (patched) {
                      storage.setItem(sKey, JSON.stringify(sParsed));
                      storagePatchCount++;
                    }
                  }
                } catch (e) {}
              }
            } catch (e) {}
          }

          return { success: true, storagePatchCount: storagePatchCount };
        },
        { args: [modifiedData] }
      );
      var overrideResult = utils.execResult(results);
      if (!overrideResult || !overrideResult.success) {
        utils.showToast('拦截器未注入，请先启动权限拦截', 'error');
        return;
      }
      var msg = '已应用修改（拦截器 + Vue存储';
      if (overrideResult.storagePatchCount > 0) {
        msg += ' + ' + overrideResult.storagePatchCount + '个本地缓存';
      }
      msg += '）→ 请在页面上点击菜单或刷新页面，检查是否出现新菜单项';
      utils.showToast(msg, 'success');
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  // ====== JS Keyword Search ======
  async function searchJsKeywords(keyword) {
    var statusEl = utils.get('jssearch-status');
    var resultsEl = utils.get('jssearch-results');
    if (!keyword || keyword.length < 2) {
      utils.showToast('请输入至少2个字符', 'warning');
      return;
    }
    if (statusEl) statusEl.textContent = '搜索中...';
    lastJsMatchContexts = [];

    try {
      const tab = await utils.requireTabId();
      if (!tab) return;

      // 1. Search inline scripts
      var inlineResults = await utils.execInTab(
        tab.id,
        function (kw) {
          var matches = [];
          var seen = {};
          var scripts = document.querySelectorAll('script:not([src])');
          for (var i = 0; i < scripts.length; i++) {
            var text = scripts[i].textContent || '';
            if (text.indexOf(kw) === -1) continue;
            var lines = text.split('\n');
            for (var j = 0; j < lines.length; j++) {
              var idx = lines[j].indexOf(kw);
              while (idx !== -1) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(lines[j].length, idx + kw.length + 60);
                var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                var key = i + ':' + idx;
                if (!seen[key]) {
                  seen[key] = true;
                  matches.push({
                    source: '(inline script #' + (i + 1) + ')',
                    line: j + 1,
                    context: context,
                  });
                }
                if (matches.length >= 50) break;
                idx = lines[j].indexOf(kw, idx + 1);
              }
              if (matches.length >= 50) break;
            }
            if (matches.length >= 50) break;
          }
          // Also return external script URLs for further fetching
          var extUrls = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            extUrls.push(s.src);
          });
          return { matches: matches, extUrls: extUrls };
        },
        { args: [keyword], world: 'ISOLATED' }
      );

      var inlineData = utils.execResult(inlineResults) || {};
      var matchList = inlineData.matches || [];
      var extUrls = inlineData.extUrls || [];

      // 2. Search external scripts via background fetch proxy (parallel batches)
      var CONCURRENCY = 5;
      for (
        var batchStart = 0;
        batchStart < extUrls.length && matchList.length < 50;
        batchStart += CONCURRENCY
      ) {
        var batch = extUrls.slice(batchStart, batchStart + CONCURRENCY);
        var batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }).catch(function () {
              return null;
            });
          })
        );
        for (var b = 0; b < batchResults.length && matchList.length < 50; b++) {
          var resp = batchResults[b];
          if (!resp || resp.error || !resp.data) continue;
          var text = resp.data;
          if (text && text.indexOf(keyword) !== -1) {
            var shortUrl = batch[b];
            if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
            var lines = text.split('\n');
            for (var j = 0; j < lines.length && matchList.length < 50; j++) {
              var idx = lines[j].indexOf(keyword);
              while (idx !== -1 && matchList.length < 50) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(lines[j].length, idx + keyword.length + 60);
                var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                matchList.push({ source: shortUrl, line: j + 1, context: context });
                idx = lines[j].indexOf(keyword, idx + 1);
              }
            }
          }
        }
      }

      if (matchList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到匹配';
        if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('在页面JS中未找到「' + keyword + '」');
        return;
      }

      if (statusEl) statusEl.textContent = '找到 ' + matchList.length + ' 处匹配';
      var html = '';
      for (var i = 0; i < matchList.length; i++) {
        var m = matchList[i];
        lastJsMatchContexts.push(m.context);
        var escapedKeyword = utils.escapeHtml(keyword).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var escaped = utils.escapeHtml(m.context);
        var highlighted = escaped.replace(
          new RegExp('(' + escapedKeyword + ')', 'gi'),
          '<mark>$1</mark>'
        );
        html += '<div class="jssearch-match">';
        html +=
          '<div class="jssearch-match-source">' +
          utils.escapeHtml(m.source) +
          ' : line ' +
          m.line +
          '</div>';
        html += '<div class="jssearch-match-code">' + highlighted + '</div>';
        html += '</div>';
      }
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '搜索出错';
      utils.showToast('搜索失败: ' + e.message, 'error');
    }
  }

  function extractPathsFromJsResults() {
    var found = new Set();
    var pathRegex = /(?:path|url|href|route|component)\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi;
    var genericRegex = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)['"`]/g;
    for (var i = 0; i < lastJsMatchContexts.length; i++) {
      var ctx = lastJsMatchContexts[i];
      var m;
      pathRegex.lastIndex = 0;
      while ((m = pathRegex.exec(ctx)) !== null) {
        var p = m[1];
        if (p.indexOf('/api/') === -1 && p.length > 2) found.add(p);
      }
      genericRegex.lastIndex = 0;
      while ((m = genericRegex.exec(ctx)) !== null) {
        var p2 = m[1];
        if (
          p2.indexOf('/api/') === -1 &&
          p2.length > 3 &&
          !/^\.(js|css|png|jpg|svg|ico|woff)/.test(p2)
        )
          found.add(p2);
      }
    }
    jsSearchFoundPaths = Array.from(found);
    return jsSearchFoundPaths;
  }

  function autoFillFromJsPaths() {
    if (jsSearchFoundPaths.length === 0) {
      extractPathsFromJsResults();
    }
    if (jsSearchFoundPaths.length === 0) {
      utils.showToast('未找到JS路径，请先搜索关键词', 'warning');
      return;
    }
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    var text = editor.value;
    if (!text) {
      utils.showToast('请先选择一条捕获数据', 'warning');
      return;
    }
    try {
      var parsed = JSON.parse(text);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }
    var template = getTemplateFromMenuData(parsed);
    var targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
    if (!targetArray) {
      utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
      return;
    }
    var menuPaths = new Set();
    extractMenuPaths(parsed, menuPaths);
    var injected = 0;
    for (var p = 0; p < jsSearchFoundPaths.length; p++) {
      var routePath = jsSearchFoundPaths[p];
      if (!menuPaths.has(routePath)) {
        var newItem = constructMenuItemFromRoute({ path: routePath, name: routePath }, template);
        targetArray.push(newItem);
        menuPaths.add(routePath);
        injected++;
      }
    }
    editor.value = JSON.stringify(parsed, null, 2);
    utils.showToast('已注入 ' + injected + ' 条JS路径到菜单数据', 'success');
  }

  function extractKeywordsFromCapturedUrls() {
    var keywords = [];
    var seen = {};
    if (!permCapturedData || permCapturedData.length === 0) return keywords;

    for (var i = 0; i < permCapturedData.length; i++) {
      var item = permCapturedData[i];
      if (!item || !item.url) continue;
      var url = item.url;
      var segments = url.split(/[\/?#]/);
      var processed = 0;
      for (var s = segments.length - 1; s >= 0 && processed < 2; s--) {
        var seg = segments[s].trim();
        if (!seg || seg.length < 3) continue;
        if (
          /^(api|v1|v2|v3|v4|index|list|detail|page|id|json|html|js|css|get|post|put|delete)$/i.test(
            seg
          )
        )
          continue;
        if (/^\d+$/.test(seg)) continue;

        var words = seg.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[\s_\-]+/);
        for (var w = 0; w < words.length; w++) {
          var word = words[w];
          if (word.length < 4) continue;
          if (!seen[word.toLowerCase()]) {
            seen[word.toLowerCase()] = true;
            keywords.push(word);
          }
        }
        if (!seen[seg.toLowerCase()]) {
          seen[seg.toLowerCase()] = true;
          keywords.push(seg);
        }
        processed++;
      }
    }
    return keywords.slice(0, 8);
  }

  async function autoSearchForZeroOpen() {
    lastJsMatchContexts = [];
    var allContexts = [];
    var classifyEl = utils.get('perm-classify');

    if (classifyEl) classifyEl.textContent = '正在搜索: menu...';
    await searchJsKeywords('menu');
    allContexts = allContexts.concat(lastJsMatchContexts);

    if (classifyEl) classifyEl.textContent = '正在搜索: routes... (' + allContexts.length + ' 条)';
    await searchJsKeywords('routes');
    allContexts = allContexts.concat(lastJsMatchContexts);

    var urlKeywords = extractKeywordsFromCapturedUrls();
    for (var uk = 0; uk < urlKeywords.length; uk++) {
      if (allContexts.length >= 50) break;
      var kw = urlKeywords[uk];
      if (/^(menu|routes|route|permission)$/i.test(kw)) continue;
      if (classifyEl)
        classifyEl.textContent = '正在搜索: ' + kw + '... (' + allContexts.length + ' 条)';
      lastJsMatchContexts = [];
      await searchJsKeywords(kw);
      allContexts = allContexts.concat(lastJsMatchContexts);
    }

    if (classifyEl) classifyEl.textContent = '搜索完成，共 ' + allContexts.length + ' 条结果';

    lastJsMatchContexts = allContexts;
    extractPathsFromJsResults();
    if (jsSearchFoundPaths.length > 0) {
      utils.showToast(
        '找到 ' + jsSearchFoundPaths.length + ' 条路径，可点击「应用修改」注入',
        'success'
      );
      switchVueSubTab('perm');
      var editor = utils.get('perm-json-editor');
      if (editor && editor.value) {
        autoFillFromJsPaths();
      }
    } else {
      utils.showToast('未从JS中提取到路径，请手动搜索关键词', 'warning');
    }
  }

  // ====== Route vs Menu Comparison ======
  function extractMenuPaths(data, paths) {
    if (typeof data !== 'object' || data === null) return;
    var pathKeys = ['path', 'url', 'href', 'menuUrl', 'menuPath', 'link', 'index'];
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i++) extractMenuPaths(data[i], paths);
      return;
    }
    for (var k = 0; k < pathKeys.length; k++) {
      var val = data[pathKeys[k]];
      if (val && typeof val === 'string' && (val === '/' || /^\/[a-zA-Z0-9_\-]/.test(val)))
        paths.add(val);
    }
    if (data.children) extractMenuPaths(data.children, paths);
    if (data.subList) extractMenuPaths(data.subList, paths);
    if (data.child) extractMenuPaths(data.child, paths);
    if (data.childList) extractMenuPaths(data.childList, paths);
    if (data.items) extractMenuPaths(data.items, paths);
  }

  function isPathInMenu(routePath, menuPaths) {
    if (menuPaths.has(routePath)) return true;
    var iter = menuPaths.values();
    var mp = iter.next();
    while (!mp.done) {
      var menuPath = mp.value;
      if (routePath.indexOf(menuPath) === 0 && routePath !== menuPath) {
        var nextChar = routePath.charAt(menuPath.length);
        if (nextChar === '/' || !nextChar) return true;
      }
      mp = iter.next();
    }
    return false;
  }

  function findMenuArray(data, depth) {
    if (depth === undefined) depth = 0;
    if (depth > 3 || data === null || data === undefined) return null;
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null) {
      return data;
    }
    if (typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var i = 0; i < keys.length; i++) {
        if (
          Array.isArray(data[keys[i]]) &&
          data[keys[i]].length > 0 &&
          typeof data[keys[i]][0] === 'object' &&
          data[keys[i]][0] !== null
        ) {
          return data[keys[i]];
        }
      }
      for (var j = 0; j < keys.length; j++) {
        if (
          typeof data[keys[j]] === 'object' &&
          data[keys[j]] !== null &&
          !Array.isArray(data[keys[j]])
        ) {
          var found = findMenuArray(data[keys[j]], depth + 1);
          if (found) return found;
        }
      }
    }
    return null;
  }

  function getTemplateFromMenuData(data) {
    var arr = findMenuArray(data);
    if (!arr || arr.length === 0) return null;
    var item = {};
    for (var k in arr[0]) {
      if (arr[0].hasOwnProperty(k)) item[k] = arr[0][k];
    }
    return item;
  }

  function constructMenuItemFromRoute(route, templateItem) {
    if (!templateItem || typeof templateItem !== 'object') {
      return {
        path: route.path,
        name: route.name || route.path,
        title: route.name || route.path,
        isshow: '1',
        status: 1,
      };
    }
    var item = {};
    for (var k in templateItem) {
      if (!templateItem.hasOwnProperty(k)) continue;
      if (k === 'path' || k === 'url' || k === 'href' || k === 'menuUrl' || k === 'menuPath') {
        item[k] = route.path;
      } else if (k === 'name' || k === 'menuName') {
        item[k] = route.name || route.path;
      } else if (k === 'title' || k === 'label' || k === 'text') {
        item[k] = route.name || route.path;
      } else if (k === 'id' || k === 'menuId' || k === 'key') {
        item[k] = Math.floor(Math.random() * 90000) + 10000;
      } else if (k === 'isshow' || k === 'isShow') {
        item[k] = '1';
      } else if (k === 'hidden') {
        item[k] = false;
      } else if (k === 'display' || k === 'visible') {
        item[k] = true;
      } else if (k === 'status') {
        item[k] = 1;
      } else if (
        k === 'children' ||
        k === 'child' ||
        k === 'subList' ||
        k === 'childList' ||
        k === 'items'
      ) {
        item[k] = [];
      } else if (k === 'meta' || k === 'component') {
        continue;
      } else {
        item[k] = templateItem[k];
      }
    }
    if (!item.path) item.path = route.path;
    return item;
  }

  function autoInjectHiddenRoutes() {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    var text = editor.value;
    if (!text) {
      utils.showToast('请先选择一条捕获数据', 'warning');
      return;
    }
    if (lastCompareHiddenRoutes.length === 0) {
      utils.showToast('无缓存的路由对比结果，请先执行「路由对比」', 'warning');
      return;
    }
    try {
      var parsed = JSON.parse(text);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }
    var template = getTemplateFromMenuData(parsed);
    var targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
    if (!targetArray) {
      utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
      return;
    }
    var menuPaths = new Set();
    extractMenuPaths(parsed, menuPaths);
    var injected = 0;
    for (var h = 0; h < lastCompareHiddenRoutes.length; h++) {
      var route = lastCompareHiddenRoutes[h];
      if (!isPathInMenu(route.path, menuPaths)) {
        var newItem = constructMenuItemFromRoute(route, template);
        targetArray.push(newItem);
        injected++;
      }
    }
    editor.value = JSON.stringify(parsed, null, 2);
    utils.showToast('已注入 ' + injected + ' 条缺失路由到菜单数据', 'success');
  }

  // ====== Auto-traverse routes ======
  var traverseActive = false;

  function addTraverseLog(idx, path, status) {
    var logEl = utils.get('traverse-log');
    if (!logEl) return;
    var statusClass = status === 'ok' ? 'log-ok' : status === 'fail' ? 'log-fail' : 'log-skip';
    var statusText = status === 'ok' ? '✓' : status === 'fail' ? '✗' : '–';
    var div = document.createElement('div');
    div.className = 'traverse-log-entry';
    div.innerHTML =
      '<span class="log-idx">' +
      idx +
      '</span>' +
      '<span class="log-path">' +
      utils.escapeHtml(path) +
      '</span>' +
      '<span class="' +
      statusClass +
      '">' +
      statusText +
      '</span>';
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function updateTraverseProgress(current, total, path) {
    var progressEl = utils.get('traverse-progress');
    if (progressEl) progressEl.textContent = current + '/' + total + (path ? ' → ' + path : '');
  }

  function stopTraverse() {
    traverseActive = false;
    utils.toggleBtnPair('traverse-start-btn', 'traverse-stop-btn', false);
    var progressEl = utils.get('traverse-progress');
    if (progressEl && !progressEl.textContent.includes('完成')) {
      progressEl.textContent += ' (已停止)';
    }
    utils.requireTabId().then(function (tab) {
      if (!tab) return;
      utils
        .execInTab(tab.id, function () {
          window.__VULN_TRAVERSE_ACTIVE__ = false;
        })
        .catch(function () {});
    });
  }

  async function startTraverseRoutes() {
    if (traverseActive) return;

    var hiddenOnly = utils.get('traverse-hidden-only');
    var useHiddenOnly = hiddenOnly ? hiddenOnly.checked : true;
    var delaySelect = utils.get('traverse-delay');
    var delay = delaySelect ? parseInt(delaySelect.value) : 3000;

    var routes = [];
    if (useHiddenOnly) {
      if (lastCompareHiddenRoutes.length === 0) {
        utils.showToast('没有隐藏路由，请先执行「路由对比」', 'warning');
        return;
      }
      routes = lastCompareHiddenRoutes.map(function (r) {
        return r.path;
      });
    } else {
      // Fetch all routes from page
      try {
        var tab = await utils.requireTabId();
        if (!tab) {
          utils.showToast('无法获取当前标签页', 'error');
          return;
        }
        var routeResults = await utils.execInTab(tab.id, function () {
          var routes = [];
          var seen = {};
          function extract(rts, prefix) {
            rts.forEach(function (r) {
              var childPath = r.path || '/';
              var path;
              if (childPath.charAt(0) === '/') path = childPath;
              else if (prefix === '' || prefix === '/') path = '/' + childPath;
              else path = prefix + '/' + childPath;
              if (r.path && r.path !== '*' && !seen[path]) {
                seen[path] = true;
                routes.push(path);
              }
              if (r.children) extract(r.children, path === '/' ? '/' : path);
            });
          }
          var appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('#root') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            var router = appEl.__vue_app__.config.globalProperties.$router;
            if (router && typeof router.getRoutes === 'function') {
              router.getRoutes().forEach(function (r) {
                if (r.path && r.path !== '*' && !seen[r.path]) {
                  seen[r.path] = true;
                  routes.push(r.path);
                }
              });
            } else if (router && router.options && router.options.routes) {
              extract(router.options.routes, '');
            }
          } else {
            var els = document.querySelectorAll('*');
            for (var i = 0; i < els.length; i++) {
              if (els[i].__vue__) {
                var vm = els[i].__vue__.$root || els[i].__vue__;
                if (vm.$router) {
                  if (typeof vm.$router.getRoutes === 'function') {
                    vm.$router.getRoutes().forEach(function (r) {
                      if (r.path && r.path !== '*' && !seen[r.path]) {
                        seen[r.path] = true;
                        routes.push(r.path);
                      }
                    });
                  } else if (vm.$router.options && vm.$router.options.routes) {
                    extract(vm.$router.options.routes, '');
                  }
                }
                if (routes.length > 0) break;
              }
            }
          }
          return routes;
        });
        routes = utils.execResult(routeResults) || [];
      } catch (e) {
        utils.showToast('获取路由失败: ' + e.message, 'error');
        return;
      }
      if (routes.length === 0) {
        utils.showToast('未检测到路由，请先在「基础检测」中检测 Vue', 'warning');
        return;
      }
    }

    traverseActive = true;
    var logEl = utils.get('traverse-log');
    utils.toggleBtnPair('traverse-start-btn', 'traverse-stop-btn', true);
    if (logEl) logEl.innerHTML = '';
    updateTraverseProgress(0, routes.length, '准备中...');

    var tab = await utils.requireTabId();
    if (!tab) {
      stopTraverse();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    // Use chrome.tabs messaging for progress updates
    var tabId = tab.id;
    var currentIdx = 0;
    var total = routes.length;

    function navigateNext() {
      if (!traverseActive || currentIdx >= total) {
        if (traverseActive) {
          updateTraverseProgress(total, total, '遍历完成');
          var progressEl = utils.get('traverse-progress');
          if (progressEl) progressEl.textContent = total + '/' + total + ' 完成';
          utils.showToast('路由遍历完成，共 ' + total + ' 条', 'success');
        }
        stopTraverse();
        return;
      }

      var path = routes[currentIdx];
      updateTraverseProgress(currentIdx + 1, total, path);

      utils
        .execInTab(
          tabId,
          function (p) {
            var router = null;
            var appEl =
              document.querySelector('#app') ||
              document.querySelector('[data-v-app]') ||
              document.querySelector('#root') ||
              document.querySelector('#main');
            if (appEl && appEl.__vue_app__) {
              router = appEl.__vue_app__.config.globalProperties.$router;
            } else {
              var els = document.querySelectorAll('*');
              for (var i = 0; i < els.length; i++) {
                if (els[i].__vue__) {
                  var vm = els[i].__vue__.$root || els[i].__vue__;
                  if (vm.$router) {
                    router = vm.$router;
                    break;
                  }
                }
              }
            }
            if (router) {
              try {
                router.push(p);
                return { path: p, ok: true };
              } catch (e) {
                return { path: p, ok: false, error: e.message };
              }
            }
            return { path: p, ok: false, error: 'no router' };
          },
          { args: [path] }
        )
        .then(function (results) {
          var res = utils.execResult(results);
          if (res && res.ok) {
            addTraverseLog(currentIdx + 1, path, 'ok');
          } else {
            addTraverseLog(currentIdx + 1, path, res && res.error ? 'fail' : 'fail');
          }
          currentIdx++;
          if (traverseActive) {
            setTimeout(navigateNext, delay);
          }
        })
        .catch(function (err) {
          addTraverseLog(currentIdx + 1, path, 'fail');
          currentIdx++;
          if (traverseActive) {
            setTimeout(navigateNext, delay);
          }
        });
    }

    navigateNext();
  }

  async function compareRoutesAndMenu() {
    var statusEl = utils.get('compare-status');
    var resultsEl = utils.get('compare-results');
    if (statusEl) statusEl.textContent = '对比中...';

    try {
      const tab = await utils.requireTabId();
      if (!tab) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }
      var routeResults = await utils.execInTab(tab.id, function () {
        var routes = [];
        var seen = {};
        function extract(rts, prefix) {
          rts.forEach(function (r) {
            var childPath = r.path || '/';
            var path;
            if (childPath.charAt(0) === '/') {
              path = childPath;
            } else if (prefix === '' || prefix === '/') {
              path = '/' + childPath;
            } else {
              path = prefix + '/' + childPath;
            }
            if (r.path && r.path !== '*' && !seen[path]) {
              seen[path] = true;
              routes.push({ path: path, name: r.name || '' });
            }
            if (r.children) extract(r.children, path === '/' ? '/' : path);
          });
        }
        function getAndExtract(router) {
          if (!router) return;
          if (typeof router.getRoutes === 'function') {
            var flat = router.getRoutes();
            for (var i = 0; i < flat.length; i++) {
              var p = flat[i].path;
              if (p && p !== '*' && !seen[p]) {
                seen[p] = true;
                routes.push({ path: p, name: flat[i].name || '' });
              }
            }
          } else if (router.options && router.options.routes) {
            extract(router.options.routes, '');
          }
        }
        var appEl =
          document.querySelector('#app') ||
          document.querySelector('[data-v-app]') ||
          document.querySelector('[id^="app"]') ||
          document.querySelector('#root') ||
          document.querySelector('#application') ||
          document.querySelector('#main');
        if (appEl && appEl.__vue_app__) {
          getAndExtract(appEl.__vue_app__.config.globalProperties.$router);
        } else {
          var els = document.querySelectorAll('*');
          for (var i = 0; i < els.length; i++) {
            if (els[i].__vue__) {
              var vm = els[i].__vue__.$root || els[i].__vue__;
              getAndExtract(vm.$router);
              if (routes.length > 0) break;
            }
          }
        }
        return routes;
      });

      var routeList = utils.execResult(routeResults) || [];

      var menuResults = await utils.execInTab(tab.id, function () {
        return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
      });
      var captured = utils.execResult(menuResults) || [];

      var menuPaths = new Set();
      for (var i = 0; i < captured.length; i++) extractMenuPaths(captured[i].data, menuPaths);

      if (routeList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到路由';
        resultsEl.innerHTML = utils.emptyHtml('请先在「基础检测」中检测 Vue 路由');
        return;
      }

      var hiddenRoutes = [];
      var visibleRoutes = [];
      for (var j = 0; j < routeList.length; j++) {
        var r = routeList[j];
        if (isPathInMenu(r.path, menuPaths)) {
          visibleRoutes.push(r);
        } else {
          hiddenRoutes.push(r);
        }
      }
      lastCompareHiddenRoutes = hiddenRoutes.slice();

      var html = '';
      if (hiddenRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">隐藏路由 (路由存在但菜单中未显示) - ' +
          hiddenRoutes.length +
          ' 条</div>';
        for (var h = 0; h < hiddenRoutes.length; h++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-hidden">[隐藏]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(hiddenRoutes[h].path) +
            '</span>';
          if (hiddenRoutes[h].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(hiddenRoutes[h].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (visibleRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">已显示路由 - ' + visibleRoutes.length + ' 条</div>';
        for (var v = 0; v < visibleRoutes.length; v++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-visible">[显示]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(visibleRoutes[v].path) +
            '</span>';
          if (visibleRoutes[v].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(visibleRoutes[v].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (captured.length === 0) {
        html += '<div class="compare-section-title compare-hint-title">提示</div>';
        html +=
          '<div class="compare-route-item compare-hint-text">未捕获菜单数据。请先在「权限菜单」标签中开始拦截，然后刷新页面。</div>';
      }

      if (statusEl)
        statusEl.textContent =
          '路由 ' + routeList.length + ' 条，隐藏 ' + hiddenRoutes.length + ' 条';
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '对比出错';
      utils.showToast('对比失败: ' + e.message, 'error');
    }
  }

  // ====== Store Explorer ======

  async function exploreVueStore() {
    var statusEl = utils.get('vue-store-status');
    var resultsEl = utils.get('vue-store-results');
    var actionsEl = utils.get('vue-store-actions');
    var directivesEl = utils.get('vue-store-directives');
    if (!resultsEl) return;

    if (statusEl) statusEl.textContent = '正在探索 Store...';

    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        if (statusEl) statusEl.textContent = '无法获取标签页';
        return;
      }

      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
      if (!data) {
        if (statusEl) statusEl.textContent = '无响应';
        resultsEl.innerHTML = utils.emptyHtml('未能获取 Store 数据');
        return;
      }

      if (data.error) {
        if (statusEl) statusEl.textContent = '错误: ' + data.error;
        resultsEl.innerHTML = utils.emptyHtml(data.error);
        return;
      }

      // data = { store: {...}, actions: {...}, directives: [...] }
      var storeInfo = data.store || {};
      var actionsInfo = data.actions || {};
      var dirsInfo = data.directives || [];

      // Status
      var frameworks = storeInfo.frameworks || [];
      var storeKeys = Object.keys(storeInfo.stores || {});
      if (statusEl) {
        if (frameworks.length > 0) {
          statusEl.textContent =
            '检测到 ' + frameworks.join(', ') + ' | ' + storeKeys.length + ' 个 Store';
        } else {
          statusEl.textContent = '未检测到 Vuex/Pinia Store';
        }
      }

      // Render stores
      var html = '';
      if (storeKeys.length === 0) {
        html += utils.emptyHtml('未发现 Vuex/Pinia Store 数据');
      } else {
        storeKeys.forEach(function (storeId) {
          var storeData = storeInfo.stores[storeId];
          html += '<div class="vue-store-card">';
          html += '<div class="vue-store-header">';
          html += '<span class="vue-store-name">' + utils.escapeHtml(storeId) + '</span>';
          html +=
            '<span class="vue-store-type">' +
            utils.escapeHtml(storeData.type || 'unknown') +
            '</span>';
          html += '</div>';
          html += renderStoreTree(storeData.state, '', 0);
          if (storeData.getters && storeData.getters.length > 0) {
            html += '<div class="vue-store-section">';
            html +=
              '<div class="vue-store-section-title">Getters (' +
              storeData.getters.length +
              ')</div>';
            html += '<div class="vue-store-tags">';
            storeData.getters.forEach(function (g) {
              html += '<span class="vue-store-tag">' + utils.escapeHtml(g) + '</span>';
            });
            html += '</div></div>';
          }
          if (storeData.mutations && storeData.mutations.length > 0) {
            html += '<div class="vue-store-section">';
            html +=
              '<div class="vue-store-section-title">Mutations (' +
              storeData.mutations.length +
              ')</div>';
            html += '<div class="vue-store-tags">';
            storeData.mutations.forEach(function (m) {
              html +=
                '<span class="vue-store-tag vue-store-tag-mut">' + utils.escapeHtml(m) + '</span>';
            });
            html += '</div></div>';
          }
          if (storeData.actions && storeData.actions.length > 0) {
            html += '<div class="vue-store-section">';
            html +=
              '<div class="vue-store-section-title">Actions (' +
              storeData.actions.length +
              ')</div>';
            html += '<div class="vue-store-tags">';
            storeData.actions.forEach(function (a) {
              html +=
                '<span class="vue-store-tag vue-store-tag-act">' + utils.escapeHtml(a) + '</span>';
            });
            html += '</div></div>';
          }
          html += '</div>';
        });
      }
      resultsEl.innerHTML = html;

      // Render actions / API endpoints
      if (actionsEl) {
        var actionHtml = '';
        var actionNames = actionsInfo.actionNames || [];
        var getterNames = actionsInfo.getterNames || [];
        var apiEndpoints = actionsInfo.apiEndpoints || [];

        if (actionNames.length === 0 && apiEndpoints.length === 0) {
          actionHtml = utils.emptyHtml('未发现 Action 或 API 端点');
        } else {
          if (apiEndpoints.length > 0) {
            actionHtml += '<div class="vue-store-section">';
            actionHtml +=
              '<div class="vue-store-section-title">API 端点 (' + apiEndpoints.length + ')</div>';
            actionHtml += '<div class="vue-store-api-list">';
            apiEndpoints.forEach(function (ep) {
              actionHtml +=
                '<div class="vue-store-api-item" data-url="' + utils.escapeHtml(ep) + '">';
              actionHtml += '<code>' + utils.escapeHtml(ep) + '</code>';
              actionHtml +=
                '<button class="btn btn-sm btn-outline vue-api-copy-btn" data-url="' +
                utils.escapeHtml(ep) +
                '">复制</button>';
              actionHtml += '</div>';
            });
            actionHtml += '</div></div>';
          }
          if (actionNames.length > 0) {
            actionHtml += '<div class="vue-store-section">';
            actionHtml +=
              '<div class="vue-store-section-title">Actions (' + actionNames.length + ')</div>';
            actionHtml += '<div class="vue-store-tags">';
            actionNames.forEach(function (a) {
              actionHtml +=
                '<span class="vue-store-tag vue-store-tag-act">' + utils.escapeHtml(a) + '</span>';
            });
            actionHtml += '</div></div>';
          }
          if (getterNames.length > 0) {
            actionHtml += '<div class="vue-store-section">';
            actionHtml +=
              '<div class="vue-store-section-title">Getters (' + getterNames.length + ')</div>';
            actionHtml += '<div class="vue-store-tags">';
            getterNames.forEach(function (g) {
              actionHtml += '<span class="vue-store-tag">' + utils.escapeHtml(g) + '</span>';
            });
            actionHtml += '</div></div>';
          }
        }
        actionsEl.innerHTML = actionHtml;

        // Bind copy buttons
        actionsEl.querySelectorAll('.vue-api-copy-btn').forEach(function (btn) {
          btn.addEventListener('click', function () {
            var url = btn.getAttribute('data-url') || '';
            utils.copyAndToast(url, '已复制: ' + url);
          });
        });
      }

      // Render directives
      if (directivesEl) {
        var dirHtml = '';
        if (dirsInfo.length === 0) {
          dirHtml = utils.emptyHtml('未发现自定义指令');
        } else {
          dirHtml += '<div class="vue-dir-summary">发现 ' + dirsInfo.length + ' 个自定义指令</div>';
          dirsInfo.forEach(function (d) {
            dirHtml += '<div class="vue-dir-item">';
            dirHtml += '<span class="vue-dir-name">' + utils.escapeHtml(d.name) + '</span>';
            dirHtml += '<span class="vue-dir-count">' + d.count + ' 次</span>';
            if (d.examples && d.examples.length > 0) {
              dirHtml += '<div class="vue-dir-examples">';
              d.examples.forEach(function (ex) {
                dirHtml += '<code>' + utils.escapeHtml(ex) + '</code>';
              });
              dirHtml += '</div>';
            }
            dirHtml += '</div>';
          });
        }
        directivesEl.innerHTML = dirHtml;
      }

      // Store errors
      var storeErrors = storeInfo.errors || [];
      if (storeErrors.length > 0 && statusEl) {
        statusEl.textContent += ' | 错误: ' + storeErrors.join('; ');
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '探索失败';
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('错误: ' + e.message);
    }
  }

  function renderStoreTree(obj, prefix, depth) {
    if (depth > 5) return '<div class="vue-store-node vue-store-truncated">...</div>';
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return '';

    var html = '';
    var keys = Object.keys(obj);
    var maxShow = 30;
    var shown = 0;

    keys.forEach(function (key) {
      if (shown >= maxShow) return;
      shown++;
      var val = obj[key];
      var path = prefix ? prefix + '.' + key : key;
      var isExpandable =
        val !== null &&
        typeof val === 'object' &&
        !Array.isArray(val) &&
        Object.keys(val).length > 0;
      var isArr = Array.isArray(val);

      html += '<div class="vue-store-node">';
      html += '<div class="vue-store-key-row" data-path="' + utils.escapeHtml(path) + '">';

      if (isExpandable) {
        html += '<span class="vue-store-toggle vue-store-toggle-collapsed">&#9654;</span>';
      } else {
        html += '<span class="vue-store-toggle vue-store-toggle-leaf"></span>';
      }

      html += '<span class="vue-store-key">' + utils.escapeHtml(key) + '</span>';

      if (isArr) {
        html += '<span class="vue-store-type-badge">Array[' + val.length + ']</span>';
        html +=
          '<span class="vue-store-val">' +
          utils.escapeHtml(JSON.stringify(val).substring(0, 120)) +
          '</span>';
      } else if (typeof val === 'string') {
        html +=
          '<span class="vue-store-val">"' +
          utils.escapeHtml(val.substring(0, 100)) +
          (val.length > 100 ? '...' : '') +
          '"</span>';
      } else if (typeof val === 'number' || typeof val === 'boolean') {
        html += '<span class="vue-store-val">' + String(val) + '</span>';
      } else if (val === null) {
        html += '<span class="vue-store-val vue-store-null">null</span>';
      }

      html += '</div>';

      if (isExpandable) {
        html += '<div class="vue-store-children hidden">';
        html += renderStoreTree(val, path, depth + 1);
        html += '</div>';
      }

      html += '</div>';
    });

    if (keys.length > maxShow) {
      html += '<div class="vue-store-more">... 还有 ' + (keys.length - maxShow) + ' 个键</div>';
    }

    return html;
  }

  function copyVueStoreJson() {
    var resultsEl = utils.get('vue-store-results');
    if (!resultsEl) return;
    // Find the stored data from last explore
    var storeCards = resultsEl.querySelectorAll('.vue-store-card');
    if (storeCards.length === 0) {
      utils.showToast('没有 Store 数据可复制', 'error');
      return;
    }
    utils.showToast('请先点击「读取 Store」获取数据，然后使用浏览器复制');
  }

  async function copyFullStoreJson() {
    try {
      var tab = await utils.requireTabId();
      if (!tab) return;
      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
      if (!data || data.error) {
        utils.showToast('获取 Store 失败', 'error');
        return;
      }
      var json = JSON.stringify(data.store ? data.store.stores : {}, null, 2);
      await utils.copyText(json);
      utils.showToast('Store JSON 已复制 (' + json.length + ' 字符)');
    } catch (e) {
      utils.showToast('复制失败: ' + e.message, 'error');
    }
  }

  function initStoreExplorerEvents() {
    var resultsEl = utils.get('vue-store-results');
    if (!resultsEl) return;

    resultsEl.addEventListener('click', function (e) {
      var toggle = e.target.closest('.vue-store-toggle-collapsed, .vue-store-toggle-expanded');
      if (toggle) {
        var node = toggle.closest('.vue-store-node');
        if (!node) return;
        var children = node.querySelector('.vue-store-children');
        if (!children) return;
        var isHidden = children.classList.contains('hidden');
        children.classList.toggle('hidden');
        toggle.classList.toggle('vue-store-toggle-collapsed');
        toggle.classList.toggle('vue-store-toggle-expanded');
        toggle.textContent = isHidden ? '▼' : '▶';
      }
    });
  }

  return {
    detectVue,
    exportVueRoutes,
    bypassVueGuards,
    disableRouteAuth,
    collectAllPaths,
    switchVueSubTab,
    startPermInterception,
    stopPermInterception,
    refreshPermCaptured,
    showPermDetail,
    permOpenAll,
    permChangeAdmin,
    permExpandMenuIds,
    applyPermOverride,
    searchJsKeywords,
    extractPathsFromJsResults,
    autoFillFromJsPaths,
    extractKeywordsFromCapturedUrls,
    autoSearchForZeroOpen,
    compareRoutesAndMenu,
    startTraverseRoutes,
    stopTraverse,
    autoInjectHiddenRoutes,
    renderPermList,
    startPermAutoRefresh,
    stopPermAutoRefresh,
    exploreVueStore,
    copyFullStoreJson,
    initStoreExplorerEvents,
    get lastVueResult() {
      return lastVueResult;
    },
    set lastVueResult(v) {
      lastVueResult = v;
    },
    get permInterceptActive() {
      return permInterceptActive;
    },
    set permInterceptActive(v) {
      permInterceptActive = v;
    },
    get permCapturedData() {
      return permCapturedData;
    },
    set permCapturedData(v) {
      permCapturedData = v;
    },
    get permSelectedIndex() {
      return permSelectedIndex;
    },
    set permSelectedIndex(v) {
      permSelectedIndex = v;
    },
    get permViewMode() {
      return permViewMode;
    },
    set permViewMode(v) {
      permViewMode = v;
    },
  };
})();
