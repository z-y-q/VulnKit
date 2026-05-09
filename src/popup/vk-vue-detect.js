// vk-vue-detect.js -- 灵眸 Chrome Extension
// Vue detection, route analysis, guard bypass, auth disable

import { utilsProxy as utils } from './vk-namespace.js';
import { vueState } from './vk-vue-state.js';

const S = vueState;

let lastRouterBase = '/';
let lastRouterMode = 'history';
let lastPageOrigin = '';

async function detectOnce(tabId) {
  try {
    let data = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
    if (!data || !data.detected) return data;
    return data;
  } catch (e) {
    try {
      await utils.execInTab(tabId, ['src/content/vk-content.js'], { world: 'ISOLATED' });
      await sleep(100);
      const data2 = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
      if (!data2 || !data2.detected) return data2;
      return data2;
    } catch (e2) {
      return null;
    }
  }
}

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

async function detectWithRetry(tabId) {
  const delays = [0, 300, 600];
  for (let i = 0; i < delays.length; i++) {
    if (i > 0) await sleep(delays[i]);
    let result = await detectOnce(tabId);
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

    await injectRouterFinder(tab);

    statusEl.textContent = `检测到 Vue ${data.version}`;

    const ri = data.routerInfo || {};
    lastRouterBase = ri.base || '/';
    lastRouterMode = ri.mode || 'history';
    lastPageOrigin = data.pageOrigin || '';

    let html = '';
    html += `<div class="vue-info-row"><span class="vue-info-label">版本</span><span class="vue-info-value"><span class="vue-badge vue-badge-ok">Vue ${utils.escapeHtml(data.version)}</span></span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">Vue Router</span><span class="vue-info-value">${data.router ? `<span class="vue-badge vue-badge-ok">已检测 (${utils.escapeHtml(ri.mode || '?')} 模式)</span>` : '未检测到'}</span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">Base Path</span><span class="vue-info-value">${utils.escapeHtml(ri.base || '/')}</span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">状态管理</span><span class="vue-info-value">${data.store ? '<span class="vue-badge vue-badge-warn">已检测</span>' : '未检测到'}</span></div>`;

    if (data.router && data.routes.length > 0) {
      html += renderGuardStats(data.guards, data.version);
      html += renderRouteSummary(data.routes);
      html += `<div class="card-spacing"><div class="vue-route-toolbar"><span class="vue-route-count">路由列表 (${data.routes.length})</span><button class="btn btn-xs btn-outline vue-copy-hist-btn">复制 History URL</button><button class="btn btn-xs btn-outline vue-copy-hash-btn">复制 Hash URL</button></div></div>`;
      html += renderRouteTree(data.routes, 0, ri.base || '/', ri.mode || 'history');
    }

    resultsEl.innerHTML = html;
    S.lastVueResult = JSON.stringify(data, null, 2);
  } catch (e) {
    statusEl.textContent = '检测出错';
    resultsEl.innerHTML = utils.emptyHtml(e.message);
  }
}

function buildRouteUrl(path, base, mode) {
  const origin = lastPageOrigin || 'https://example.com';
  let basePath = base || '/';
  if (basePath.charAt(basePath.length - 1) !== '/') basePath += '/';
  const fullPath = basePath + (path || '/').replace(/^\//, '');
  if (mode === 'hash') {
    return `${origin}${basePath}#${path || '/'}`;
  }
  return `${origin}${fullPath}`;
}

function collectAllPaths(routes, prefix, base, mode) {
  let result = [];
  if (!routes || !Array.isArray(routes)) return result;
  routes.forEach(function (r) {
    let p = r.path || '/';
    if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
      p = `${prefix}/${p}`;
    }
    let url = buildRouteUrl(p, base, mode);
    result.push({
      path: p,
      url: url,
      name: r.name || '',
      isParam: p.indexOf(':') !== -1 || p.indexOf('*') !== -1,
    });
    if (p.indexOf(':') !== -1 || p.indexOf('*') !== -1) {
      const probePath = p.replace(/:[^/]+/g, '1').replace(/\*/g, 'test');
      let probeUrl = buildRouteUrl(probePath, base, mode);
      result.push({
        path: probePath,
        url: probeUrl,
        name: `${r.name || ''}:probe`,
        isProbe: true,
      });
    }
    if (r.children && r.children.length > 0) {
      let childPaths = collectAllPaths(r.children, p === '/' ? '/' : p, base, mode);
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
  routes.forEach(function (route) {
    const routePath = route.path || '/';
    const histUrl = buildRouteUrl(routePath, base, 'history');
    const hashUrl = buildRouteUrl(routePath, base, 'hash');

    let badges = '';
    if (route.hasAuth) badges += '<span class="vue-badge vue-badge-auth">auth</span>';
    if (route.sensitive) badges += '<span class="vue-badge vue-badge-sensitive">sensitive</span>';
    if (route.hasBeforeEnter)
      badges += '<span class="vue-badge vue-badge-enter">beforeEnter</span>';
    if (route.childCount > 0)
      badges += `<span class="vue-badge vue-badge-children">${route.childCount} sub</span>`;

    let metaHtml = '';
    if (route.meta && Object.keys(route.meta).length > 0) {
      try {
        const metaStr = JSON.stringify(route.meta).substring(0, 60);
        metaHtml = `<span class="vue-route-meta">meta: ${utils.escapeHtml(metaStr)}</span>`;
      } catch (e) {
        metaHtml = '<span class="vue-route-meta">meta: [无法序列化]</span>';
      }
    }

    html += `<div class="vue-route-item vue-depth-${depth}" data-path="${utils.escapeHtml(routePath)}" data-name="${utils.escapeHtml(route.name || '')}">`;
    html += `<span class="vue-route-path">${utils.escapeHtml(routePath)}</span>`;
    if (route.name) html += `<span class="vue-route-name">${utils.escapeHtml(route.name)}</span>`;
    html += badges;
    html += metaHtml;
    html += `<span class="vue-route-urls">`;
    html += `<button class="vue-route-jump-btn" data-path="${utils.escapeHtml(routePath)}" title="跳转到此路由">Go</button>`;
    html += `<button class="vue-route-open-btn" data-url="${utils.escapeHtml(histUrl)}" title="${utils.escapeHtml(histUrl)}">H</button>`;
    html += `<button class="vue-route-open-btn" data-url="${utils.escapeHtml(hashUrl)}" title="${utils.escapeHtml(hashUrl)}">#</button>`;
    html += `</span></div>`;
    if (route.children && route.children.length > 0) {
      html += renderRouteTree(route.children, depth + 1, base, mode);
    }
  });
  return html;
}

function renderGuardStats(guards, version) {
  if (!guards || Object.keys(guards).length === 0) return '';
  const isVue3 = version && version.charAt(0) === '3';
  let html = '<div class="vue-guard-stats">';
  html += '<span class="vue-guard-label">全局守卫:</span>';
  if (isVue3) {
    html += `<span class="vue-guard-item">beforeGuards(${guards.beforeGuards || 0})</span>`;
    html += `<span class="vue-guard-item">afterGuards(${guards.afterGuards || 0})</span>`;
    html += `<span class="vue-guard-item">beforeResolve(${guards.beforeResolveGuards || 0})</span>`;
  } else {
    html += `<span class="vue-guard-item">beforeHooks(${guards.beforeHooks || 0})</span>`;
    html += `<span class="vue-guard-item">afterHooks(${guards.afterHooks || 0})</span>`;
    html += `<span class="vue-guard-item">beforeResolve(${guards.beforeResolveHooks || 0})</span>`;
  }
  html += '</div>';
  return html;
}

function countRouteStats(routes) {
  let total = 0,
    authCount = 0,
    sensitiveCount = 0,
    beforeEnterCount = 0;
  function walk(arr) {
    if (!arr) return;
    arr.forEach(function (r) {
      total++;
      if (r.hasAuth) authCount++;
      if (r.sensitive) sensitiveCount++;
      if (r.hasBeforeEnter) beforeEnterCount++;
      if (r.children) walk(r.children);
    });
  }
  walk(routes);
  return {
    total: total,
    authCount: authCount,
    sensitiveCount: sensitiveCount,
    beforeEnterCount: beforeEnterCount,
  };
}

function renderRouteSummary(routes) {
  const s = countRouteStats(routes);
  let html = '<div class="vue-route-summary">';
  html += `<span>总计 ${s.total} 条路由</span>`;
  if (s.authCount > 0)
    html += `<span class="vue-badge vue-badge-auth">需认证 ${s.authCount}</span>`;
  if (s.sensitiveCount > 0)
    html += `<span class="vue-badge vue-badge-sensitive">敏感路径 ${s.sensitiveCount}</span>`;
  if (s.beforeEnterCount > 0)
    html += `<span class="vue-badge vue-badge-enter">beforeEnter ${s.beforeEnterCount}</span>`;
  html += '</div>';
  return html;
}

var AUTH_KEY_RE =
  /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i;

function findRouterInPage() {
  var appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
  if (appEl && appEl.__vue_app__) {
    var r = appEl.__vue_app__.config.globalProperties.$router;
    if (r) return { router: r, version: 'vue3' };
  }
  var allEls = document.querySelectorAll('*');
  for (var n = 0; n < allEls.length; n++) {
    if (allEls[n].__vue__) {
      var vm = allEls[n].__vue__.$root || allEls[n].__vue__;
      if (vm.$router) return { router: vm.$router, version: 'vue2' };
    }
  }
  return null;
}

function safeSerialize(obj) {
  try {
    return JSON.parse(JSON.stringify(obj));
  } catch (e) {
    return null;
  }
}

async function exportVueRoutes() {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await injectRouterFinder(tab);
    const routes = await utils.execInTabData(tab.id, function () {
      function ss(obj) {
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
            return {
              path: r.path,
              name: r.name || '',
              meta: ss(r.meta) || {},
              hasAuth: typeof r.beforeEnter === 'function',
              hasBeforeEnter: typeof r.beforeEnter === 'function',
            };
          });
        }
        return router.options ? ss(router.options.routes) || null : null;
      }
      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return null;
      return getRoutes(found.router);
    });
    if (!routes) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }

    const json = JSON.stringify(routes, null, 2);
    utils.copyText(json);
    S.lastVueResult = json;
    utils.showToast(`路由已复制 (${routes.length} 条)`, 'success');
  } catch (e) {
    utils.showToast(`导出失败: ${e.message}`, 'error');
  }
}

async function ensureBackup(tab) {
  await utils.execInTabData(tab.id, function () {
    if (window.__VK_VUE_BACKUP__) return;
    var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
    if (!found) return;
    var router = found.router;
    var backup = { guards: {}, authMeta: [], timestamp: Date.now(), version: found.version };
    if (Array.isArray(router.beforeGuards))
      backup.guards.beforeGuards = router.beforeGuards.slice();
    if (Array.isArray(router.afterGuards)) backup.guards.afterGuards = router.afterGuards.slice();
    if (Array.isArray(router.beforeResolveGuards))
      backup.guards.beforeResolveGuards = router.beforeResolveGuards.slice();
    if (Array.isArray(router.beforeHooks)) backup.guards.beforeHooks = router.beforeHooks.slice();
    if (Array.isArray(router.afterHooks)) backup.guards.afterHooks = router.afterHooks.slice();
    if (Array.isArray(router.beforeResolveHooks))
      backup.guards.beforeResolveHooks = router.beforeResolveHooks.slice();

    function collectAuthMeta(routes, depth) {
      if (!routes || !Array.isArray(routes) || depth > 20) return;
      for (var i = 0; i < routes.length; i++) {
        var route = routes[i];
        if (route.meta && typeof route.meta === 'object') {
          var authKeys = Object.keys(route.meta).filter(function (k) {
            return /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i.test(
              k
            );
          });
          if (authKeys.length > 0) {
            var saved = {};
            authKeys.forEach(function (k) {
              saved[k] = route.meta[k];
            });
            backup.authMeta.push({ path: route.path, authKeys: saved });
          }
        }
        if (route.children) collectAuthMeta(route.children, depth + 1);
      }
    }

    if (router.options && router.options.routes) collectAuthMeta(router.options.routes, 0);
    window.__VK_VUE_BACKUP__ = backup;
  });
}

async function bypassVueGuards() {
  const ok = await utils.confirmDanger(
    '即将清除所有 Vue Router 导航守卫（操作前将自动备份，可通过恢复按钮还原），是否继续？'
  );
  if (!ok) return;
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await injectRouterFinder(tab);
    await ensureBackup(tab);
    let result = await utils.execInTabData(tab.id, function () {
      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return null;
      var router = found.router;
      if (found.version === 'vue3') {
        if (Array.isArray(router.beforeGuards)) router.beforeGuards.length = 0;
        if (Array.isArray(router.afterGuards)) router.afterGuards.length = 0;
        if (Array.isArray(router.beforeResolveGuards)) router.beforeResolveGuards.length = 0;
        if (router.options && Array.isArray(router.options.routes)) {
          (function clearRouteGuards(routes) {
            for (var i = 0; i < routes.length; i++) {
              if (typeof routes[i].beforeEnter === 'function') routes[i].beforeEnter = undefined;
              if (routes[i].children) clearRouteGuards(routes[i].children);
            }
          })(router.options.routes);
        }
        return 'vue3';
      }
      if (Array.isArray(router.beforeHooks)) router.beforeHooks.length = 0;
      if (Array.isArray(router.afterHooks)) router.afterHooks.length = 0;
      if (Array.isArray(router.beforeResolveHooks)) router.beforeResolveHooks.length = 0;
      return 'vue2';
    });
    if (!result) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }
    utils.showToast(`路由守卫已清除 (Vue ${result === 'vue3' ? '3' : '2'}，已备份)`, 'success');
  } catch (e) {
    utils.showToast(`绕过失败: ${e.message}`, 'error');
  }
}

async function disableRouteAuth() {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await injectRouterFinder(tab);
    await ensureBackup(tab);
    const result = await utils.execInTabData(tab.id, function () {
      var AUTH_RE =
        /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i;
      var changed = 0;

      function clearAuthMeta(routes, depth) {
        if (!routes || !Array.isArray(routes) || depth > 20) return;
        for (var i = 0; i < routes.length; i++) {
          var route = routes[i];
          if (route.meta && typeof route.meta === 'object') {
            var keys = Object.keys(route.meta);
            for (var j = 0; j < keys.length; j++) {
              if (AUTH_RE.test(keys[j]) && route.meta[keys[j]]) {
                route.meta[keys[j]] = false;
                changed++;
              }
            }
          }
          if (route.children) clearAuthMeta(route.children, depth + 1);
        }
      }

      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return null;
      var router = found.router;
      if (router.options && router.options.routes) clearAuthMeta(router.options.routes, 0);
      var flatRoutes;
      try {
        flatRoutes = router.getRoutes();
      } catch (e) {
        /* ignore */
      }
      if (flatRoutes) {
        for (var k = 0; k < flatRoutes.length; k++) {
          if (flatRoutes[k].meta && typeof flatRoutes[k].meta === 'object') {
            var metaKeys = Object.keys(flatRoutes[k].meta);
            for (var m = 0; m < metaKeys.length; m++) {
              if (AUTH_RE.test(metaKeys[m]) && flatRoutes[k].meta[metaKeys[m]]) {
                flatRoutes[k].meta[metaKeys[m]] = false;
                changed++;
              }
            }
          }
        }
      }
      return { version: found.version, changed: changed };
    });
    if (!result) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }
    if (result.changed > 0) {
      utils.showToast(
        `已修改 ${result.changed} 条路由 auth (Vue ${result.version === 'vue3' ? '3' : '2'}，已备份)`,
        'success'
      );
    } else {
      utils.showToast('未发现需要修改的 auth 字段', 'warning');
    }
  } catch (e) {
    utils.showToast(`修改失败: ${e.message}`, 'error');
  }
}

async function restoreVueRuntime() {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await injectRouterFinder(tab);
    const restored = await utils.execInTabData(tab.id, function () {
      var backup = window.__VK_VUE_BACKUP__;
      if (!backup) return { ok: false, msg: '无备份数据' };

      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return { ok: false, msg: '未找到 Vue Router' };
      var router = found.router;

      // Restore guard arrays
      var g = backup.guards;
      if (g.beforeGuards && Array.isArray(router.beforeGuards)) {
        router.beforeGuards.length = 0;
        g.beforeGuards.forEach(function (fn) {
          router.beforeGuards.push(fn);
        });
      }
      if (g.afterGuards && Array.isArray(router.afterGuards)) {
        router.afterGuards.length = 0;
        g.afterGuards.forEach(function (fn) {
          router.afterGuards.push(fn);
        });
      }
      if (g.beforeResolveGuards && Array.isArray(router.beforeResolveGuards)) {
        router.beforeResolveGuards.length = 0;
        g.beforeResolveGuards.forEach(function (fn) {
          router.beforeResolveGuards.push(fn);
        });
      }
      if (g.beforeHooks && Array.isArray(router.beforeHooks)) {
        router.beforeHooks.length = 0;
        g.beforeHooks.forEach(function (fn) {
          router.beforeHooks.push(fn);
        });
      }
      if (g.afterHooks && Array.isArray(router.afterHooks)) {
        router.afterHooks.length = 0;
        g.afterHooks.forEach(function (fn) {
          router.afterHooks.push(fn);
        });
      }
      if (g.beforeResolveHooks && Array.isArray(router.beforeResolveHooks)) {
        router.beforeResolveHooks.length = 0;
        g.beforeResolveHooks.forEach(function (fn) {
          router.beforeResolveHooks.push(fn);
        });
      }

      // Restore auth meta values
      var restored = 0;
      function restoreAuthMeta(routes, depth) {
        if (!routes || !Array.isArray(routes) || depth > 20) return;
        for (var i = 0; i < routes.length; i++) {
          var route = routes[i];
          if (route.meta && typeof route.meta === 'object') {
            for (var j = 0; j < backup.authMeta.length; j++) {
              if (backup.authMeta[j].path === route.path) {
                var saved = backup.authMeta[j].authKeys;
                var sKeys = Object.keys(saved);
                for (var k = 0; k < sKeys.length; k++) {
                  route.meta[sKeys[k]] = saved[sKeys[k]];
                  restored++;
                }
                break;
              }
            }
          }
          if (route.children) restoreAuthMeta(route.children, depth + 1);
        }
      }
      if (router.options && router.options.routes) restoreAuthMeta(router.options.routes, 0);

      delete window.__VK_VUE_BACKUP__;
      return { ok: true, msg: restored + ' 个 auth 值已恢复' };
    });
    if (!restored.ok) {
      utils.showToast(restored.msg, 'warning');
      return;
    }
    utils.showToast(`已恢复: ${restored.msg}`, 'success');
  } catch (e) {
    utils.showToast(`恢复失败: ${e.message}`, 'error');
  }
}

async function navigateVueRoute(path) {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await injectRouterFinder(tab);
    const result = await utils.execInTabData(
      tab.id,
      function (targetPath) {
        var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
        if (!found) return { ok: false, msg: '未找到 Router' };
        var router = found.router;
        try {
          router.push(targetPath);
          return { ok: true };
        } catch (e) {
          return { ok: false, msg: e.message };
        }
      },
      { args: [path], world: 'MAIN' }
    );
    if (!result.ok) {
      utils.showToast(`跳转失败: ${result.msg}`, 'error');
    } else {
      utils.showToast(`正在跳转到 ${path}`, 'success');
    }
  } catch (e) {
    utils.showToast(`跳转失败: ${e.message}`, 'error');
  }
}

async function jumpToRoute(path) {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    await ensureBackup(tab);
    // Clear guards
    await utils.execInTabData(tab.id, function () {
      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return;
      var router = found.router;
      if (found.version === 'vue3') {
        if (Array.isArray(router.beforeGuards)) router.beforeGuards.length = 0;
        if (Array.isArray(router.afterGuards)) router.afterGuards.length = 0;
        if (Array.isArray(router.beforeResolveGuards)) router.beforeResolveGuards.length = 0;
      } else {
        if (Array.isArray(router.beforeHooks)) router.beforeHooks.length = 0;
        if (Array.isArray(router.afterHooks)) router.afterHooks.length = 0;
        if (Array.isArray(router.beforeResolveHooks)) router.beforeResolveHooks.length = 0;
      }
    });
    // Disable auth
    await utils.execInTabData(tab.id, function () {
      var AUTH_RE =
        /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i;
      var found = window.__vk_findRouter ? window.__vk_findRouter() : null;
      if (!found) return;
      var router = found.router;
      function clearAuth(routes, depth) {
        if (!routes || !Array.isArray(routes) || depth > 20) return;
        for (var i = 0; i < routes.length; i++) {
          if (routes[i].meta && typeof routes[i].meta === 'object') {
            var keys = Object.keys(routes[i].meta);
            for (var j = 0; j < keys.length; j++) {
              if (AUTH_RE.test(keys[j]) && routes[i].meta[keys[j]]) routes[i].meta[keys[j]] = false;
            }
          }
          if (routes[i].children) clearAuth(routes[i].children, depth + 1);
        }
      }
      if (router.options && router.options.routes) clearAuth(router.options.routes, 0);
      try {
        var flat = router.getRoutes();
        if (flat)
          flat.forEach(function (r) {
            if (r.meta && typeof r.meta === 'object') {
              var keys = Object.keys(r.meta);
              for (var i = 0; i < keys.length; i++) {
                if (AUTH_RE.test(keys[i]) && r.meta[keys[i]]) r.meta[keys[i]] = false;
              }
            }
          });
      } catch (e) {
        /* ignore */
      }
    });
    // Navigate
    await navigateVueRoute(path);
    // Auto-restore after 3 seconds
    setTimeout(function () {
      restoreVueRuntime();
    }, 3000);
    utils.showToast(`已跳转到 ${path}（3秒后自动恢复守卫）`, 'success');
  } catch (e) {
    utils.showToast(`一键跳转失败: ${e.message}`, 'error');
  }
}

var _filterTimer = null;
function filterRouteTree(keyword) {
  if (_filterTimer) clearTimeout(_filterTimer);
  _filterTimer = setTimeout(function () {
    var items = document.querySelectorAll('.vue-route-item');
    var lower = (keyword || '').toLowerCase();
    items.forEach(function (el) {
      if (!lower) {
        el.style.display = '';
        return;
      }
      var path = (el.dataset.path || '').toLowerCase();
      var name = (el.dataset.name || '').toLowerCase();
      if (path.indexOf(lower) !== -1 || name.indexOf(lower) !== -1) {
        el.style.display = '';
      } else {
        el.style.display = 'none';
      }
    });
  }, 200);
}

async function injectRouterFinder(tab) {
  await utils.execInTabData(tab.id, function () {
    if (window.__vk_findRouter) return;
    window.__vk_findRouter = function () {
      var appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
      if (appEl && appEl.__vue_app__) {
        var r = appEl.__vue_app__.config.globalProperties.$router;
        if (r) return { router: r, version: 'vue3' };
      }
      var allEls = document.querySelectorAll('*');
      for (var n = 0; n < allEls.length; n++) {
        if (allEls[n].__vue__) {
          var vm = allEls[n].__vue__.$root || allEls[n].__vue__;
          if (vm.$router) return { router: vm.$router, version: 'vue2' };
        }
      }
      return null;
    };
  });
}

// Register on shared state for cross-module references
S.Detect = {
  detectVue: detectVue,
  exportVueRoutes: exportVueRoutes,
  bypassVueGuards: bypassVueGuards,
  disableRouteAuth: disableRouteAuth,
  restoreVueRuntime: restoreVueRuntime,
  navigateVueRoute: navigateVueRoute,
  jumpToRoute: jumpToRoute,
  filterRouteTree: filterRouteTree,
  collectAllPaths: collectAllPaths,
  sleep: sleep,
};

export {
  detectVue,
  exportVueRoutes,
  bypassVueGuards,
  disableRouteAuth,
  restoreVueRuntime,
  navigateVueRoute,
  jumpToRoute,
  filterRouteTree,
  collectAllPaths,
  sleep,
};
