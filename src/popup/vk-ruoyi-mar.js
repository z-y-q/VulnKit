// 灵眸 - RuoYi MaR Sub-module
// Dynamic route scanning (dictionary-based), rendering, and Vue Router injection

import { utils, toggleSelectAll, copyRoutePaths } from './vk-ruoyi-common.js';

let state = null;
const commonToggleAll = toggleSelectAll;
const commonCopyPaths = copyRoutePaths;

// RuoYi standard route dictionary
const RUOYI_KNOWN_ROUTES = [
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
  { path: '/monitor/online', title: '在线用户', component: 'monitor/online/index' },
  { path: '/monitor/job', title: '定时任务', component: 'monitor/job/index' },
  { path: '/monitor/druid', title: '数据监控', component: 'monitor/druid/index' },
  { path: '/monitor/server', title: '服务监控', component: 'monitor/server/index' },
  { path: '/monitor/cache', title: '缓存监控', component: 'monitor/cache/index' },
  { path: '/monitor/cache/list', title: '缓存列表', component: 'monitor/cache/list' },
  { path: '/tool/gen', title: '代码生成', component: 'tool/gen/index' },
  { path: '/tool/swagger', title: '系统接口', component: 'tool/swagger/index' },
  { path: '/tool/build', title: '表单构建', component: 'tool/build/index' },
  { path: '/tool/edit', title: '表单编辑', component: 'tool/build/index' },
  { path: '/system/tenant', title: '租户管理', component: 'system/tenant/index' },
  { path: '/system/tenant/package', title: '租户套餐', component: 'system/tenant/package' },
  { path: '/system/oss', title: '文件管理', component: 'system/oss/index' },
  { path: '/system/oss/config', title: 'OSS配置', component: 'system/oss/config' },
  { path: '/system/post', title: '岗位管理', component: 'system/post/index' },
  { path: '/system/mail', title: '邮箱管理', component: 'system/mail/index' },
  { path: '/system/dict-data', title: '字典数据', component: 'system/dict/data' },
  { path: '/system/role/authUser', title: '分配用户', component: 'system/role/authUser' },
  { path: '/system/menu/menus', title: '菜单分配', component: 'system/role/menu' },
];

// Cloud-specific endpoint dictionary
const CLOUD_KNOWN_ROUTES = [
  { path: '/actuator', title: 'Actuator', component: '' },
  { path: '/actuator/health', title: '健康检查', component: '' },
  { path: '/actuator/info', title: '应用信息', component: '' },
  { path: '/actuator/env', title: '环境变量', component: '' },
  { path: '/actuator/env/{name}', title: '环境变量详情', component: '' },
  { path: '/actuator/beans', title: 'Bean列表', component: '' },
  { path: '/actuator/mappings', title: '请求映射', component: '' },
  { path: '/actuator/gateway/routes', title: 'Gateway路由', component: '' },
  { path: '/actuator/configprops', title: '配置属性', component: '' },
  { path: '/actuator/metrics', title: '指标', component: '' },
  { path: '/actuator/trace', title: '链路追踪', component: '' },
  { path: '/actuator/loggers', title: '日志级别', component: '' },
  { path: '/actuator/scheduledtasks', title: '定时任务', component: '' },
  { path: '/actuator/threaddump', title: '线程转储', component: '' },
  { path: '/actuator/heapdump', title: '堆转储', component: '' },
  { path: '/actuator/prometheus', title: 'Prometheus', component: '' },
  { path: '/actuator/service-registry', title: '服务注册', component: '' },
  { path: '/nacos', title: 'Nacos', component: '' },
  { path: '/nacos/v1/ns/service/list', title: 'Nacos服务列表', component: '' },
  { path: '/nacos/v1/ns/instance/list', title: 'Nacos实例列表', component: '' },
  { path: '/nacos/v1/cs/configs', title: 'Nacos配置', component: '' },
  { path: '/nacos/v1/cs/configs?dataId=&group=&tenant=', title: 'Nacos配置查询', component: '' },
  { path: '/sentinel/dashboard', title: 'Sentinel控制台', component: '' },
  { path: '/swagger-ui.html', title: 'Swagger UI', component: '' },
  { path: '/v3/api-docs', title: 'OpenAPI 3', component: '' },
  { path: '/v2/api-docs', title: 'Swagger 2', component: '' },
  { path: '/v3/api-docs/swagger-config', title: 'Swagger配置', component: '' },
  { path: '/doc.html', title: 'Knife4j', component: '' },
  { path: '/seata', title: 'Seata', component: '' },
];

// ====== MaR Dynamic Route Scan ======

async function marScanDynamicRoutes() {
  const resultsEl = utils.get('mar-scan-results');
  utils.setStatus('mar-scan-status', '扫描动态路由中...');
  if (resultsEl) resultsEl.innerHTML = '';

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.setStatus('mar-scan-status', '无法获取当前标签页');
      return;
    }

    // Step 1: Get external script URLs + inline scripts
    const scriptData =
      (await utils.execInTabData(tab.id, function () {
        const urls = [];
        document.querySelectorAll('script[src]').forEach(function (s) {
          urls.push(s.src);
        });
        const inlineTexts = [];
        document.querySelectorAll('script:not([src])').forEach(function (s) {
          const t = s.textContent || '';
          if (t.length > 10 && t.length < 500000) inlineTexts.push(t);
        });
        return { urls: urls, inlineTexts: inlineTexts };
      })) || {};
    const scriptUrls = scriptData.urls || [];
    const inlineTexts = scriptData.inlineTexts || [];

    utils.setStatus(
      'mar-scan-status',
      `扫描 ${scriptUrls.length} 个外部JS + ${inlineTexts.length} 个内联脚本...`
    );

    // Step 2: Fetch all external JS content
    const CONCURRENCY = 5;
    let allJsContents = [];

    inlineTexts.forEach(function (t, i) {
      allJsContents.push({ url: `inline#${i + 1}`, data: t });
    });

    for (let bi = 0; bi < scriptUrls.length; bi += CONCURRENCY) {
      const batch = scriptUrls.slice(bi, bi + CONCURRENCY);

      const batchResults =
        (await utils.execInTabData(
          tab.id,
          function (urls) {
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
          { args: [batch] }
        )) || [];
      batchResults.forEach(function (r) {
        if (r && r.data) allJsContents.push(r);
      });

      const fetched = Math.min(bi + CONCURRENCY, scriptUrls.length);
      utils.setStatus('mar-scan-status', `获取JS中... ${fetched}/${scriptUrls.length}`);
    }

    const totalJs = allJsContents.length;
    let totalBytes = 0;
    allJsContents.forEach(function (r) {
      totalBytes += (r.data || '').length;
    });

    if (totalJs === 0) {
      utils.setStatus('mar-scan-status', '未找到任何 JS 文件');
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('当前页面未加载任何 JS 脚本。');
      return;
    }

    utils.setStatus(
      'mar-scan-status',
      `已获取 ${totalJs} 个JS (${Math.round(totalBytes / 1024)}KB)，正在扫描路由定义...`
    );

    // Step 3: Scan ALL JS for route patterns
    let ruoyiRouteJs = null;
    let ruoyiRouteContent = null;
    let extractedRoutes = [];
    let seenPaths = {};
    let seenComps = {};
    let dynRouteVarName = null;

    const fRegex = /([a-zA-Z_$][a-zA-Z0-9_$]{0,30}=[^,]{0,200})\/system\/user-auth/;
    const ruoyiMarkers = [
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

    const pathRegex = /path\s*:\s*["'`]([/"`][^"'`]+)["'`]/g;
    const compRegex = /component\s*:\s*(?:["'`]([^"'`]+)["'`]|import\(["'`]([^"'`]+)["'`]\))/g;
    const barePathRegex =
      /["'`](\/(?:system|monitor|tool|auth|resource|infra|gen)\/[a-zA-Z0-9_\-/]+)["'`]/g;

    for (let si = 0; si < allJsContents.length; si++) {
      const jsItem = allJsContents[si];
      const text = jsItem.data || '';

      if (text.length < 50) continue;

      const jsUrl = (jsItem.url || '').toLowerCase();
      if (
        /\/(jquery|bootstrap|lodash|axios|echarts|element-ui|element-plus|vue|react|core-js|babel|webpack|sockjs)\b/i.test(
          jsUrl
        )
      )
        continue;

      if (!ruoyiRouteContent) {
        let isRuoYiRoute = false;
        for (let mi = 0; mi < ruoyiMarkers.length; mi++) {
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

      pathRegex.lastIndex = 0;
      let m;
      while ((m = pathRegex.exec(text)) !== null) {
        const p = m[1];
        if (!seenPaths[p] && p.length > 1 && p.startsWith('/')) {
          seenPaths[p] = true;
          extractedRoutes.push({
            path: p,
            type: 'path-def',
            source: jsItem.url,
          });
        }
      }

      compRegex.lastIndex = 0;
      while ((m = compRegex.exec(text)) !== null) {
        const comp = m[1] || m[2];
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

      barePathRegex.lastIndex = 0;
      while ((m = barePathRegex.exec(text)) !== null) {
        const bp = m[1];
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

    // Step 4: Extract dynamic routes variable name
    if (ruoyiRouteContent) {
      const fMatch = fRegex.exec(ruoyiRouteContent);
      if (fMatch) {
        const context = fMatch[1];
        const sRegex = /([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*)=\[/;
        const sMatch = sRegex.exec(context);
        if (sMatch) {
          dynRouteVarName = sMatch[1];
        }
      }
      if (!dynRouteVarName) {
        const varPatterns = [
          /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[[\s\S]*?path\s*:\s*["']\/system/,
          /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[[\s\S]*?path\s*:\s*["']\/monitor/,
        ];
        for (let vpi = 0; vpi < varPatterns.length && !dynRouteVarName; vpi++) {
          const vpm = varPatterns[vpi].exec(ruoyiRouteContent);
          if (vpm) dynRouteVarName = vpm[1];
        }
      }
    }

    // Step 5: Merge in RuoYi known routes dictionary
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

    // Step 5b: Detect cloud variant and merge cloud routes
    const detectedVariant = state ? state.detectedVariant : null;
    const hasGatewayRoutes =
      state && state.capturedGatewayRoutes && state.capturedGatewayRoutes.length > 0;
    const hasNacosServices = state && state.nacosServices && state.nacosServices.length > 0;
    if (
      detectedVariant === 'cloud' ||
      detectedVariant === 'microservice' ||
      hasGatewayRoutes ||
      hasNacosServices
    ) {
      if (!detectedVariant && (hasGatewayRoutes || hasNacosServices)) {
        if (state) state.detectedVariant = 'cloud';
      }
      CLOUD_KNOWN_ROUTES.forEach(function (cr) {
        if (!seenPaths[cr.path]) {
          seenPaths[cr.path] = true;
          extractedRoutes.push({
            path: cr.path,
            type: 'cloud-dict',
            source: 'Cloud端点',
            title: cr.title,
            component: cr.component,
          });
        }
      });
    }

    if (extractedRoutes.length === 0) {
      utils.setStatus('mar-scan-status', '未发现任何路由');
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('未发现路由定义');
      return;
    }

    // Step 6: Compare with captured router data to find hidden routes
    let capturedPaths = [];
    const capturedRouterData = state ? state.capturedRouterData : null;
    if (capturedRouterData) {
      if (state && state.hooks && typeof state.hooks.extractPathsFromData === 'function') {
        state.hooks.extractPathsFromData(capturedRouterData.data || capturedRouterData, capturedPaths);
      }
    }

    const routerInfo =
      (await utils.execInTabData(tab.id, function () {
        const hook = window.__VK_RUOYI_HOOK__;
        if (hook && typeof hook.getRouterInfo === 'function') {
          return hook.getRouterInfo();
        }
        return { found: false, routes: [], currentRoutes: [] };
      })) || {};

    if (routerInfo.currentRoutes) {
      routerInfo.currentRoutes.forEach(function (rp) {
        if (capturedPaths.indexOf(rp) === -1) capturedPaths.push(rp);
      });
    }

    const marDynamicRoutes = extractedRoutes;
    let marHiddenRoutes = extractedRoutes.filter(function (r) {
      if (r.type === 'component-ref') return true;
      return (
        r.path &&
        capturedPaths.indexOf(r.path) === -1 &&
        r.path !== '/' &&
        r.path !== '/login' &&
        r.path !== '*'
      );
    });

    // Deduplicate
    const dedupSeen = {};
    marHiddenRoutes = marHiddenRoutes.filter(function (r) {
      const key = r.path || r.component;
      if (dedupSeen[key]) return false;
      dedupSeen[key] = true;
      return true;
    });

    if (state) {
      state.marDynamicRoutes = marDynamicRoutes;
      state.marHiddenRoutes = marHiddenRoutes;
    }

    marRenderScanResults(
      resultsEl,
      extractedRoutes,
      marHiddenRoutes,
      dynRouteVarName,
      ruoyiRouteJs,
      routerInfo
    );
  } catch (e) {
    utils.setStatus('mar-scan-status', `扫描失败: ${e.message}`);
    utils.showToast(`MaR扫描失败: ${e.message}`, 'error');
  }
}

function marRenderScanResults(resultsEl, allRoutes, hiddenRoutes, varName, jsUrl, routerInfo) {
  if (!resultsEl) return;

  let html = '';

  html += '<div class="mar-info-section">';
  html += `<div class="mar-info-row"><span class="mar-label">JS文件:</span> `;
  let shortUrl = jsUrl || '';
  if (shortUrl.length > 60) shortUrl = `...${shortUrl.substring(shortUrl.length - 57)}`;
  html += `<span class="mar-value">${utils.escapeHtml(shortUrl)}</span></div>`;
  if (varName) {
    html += `<div class="mar-info-row"><span class="mar-label">动态路由变量:</span> <span class="mar-value mar-highlight">${utils.escapeHtml(varName)}</span></div>`;
  }
  if (routerInfo.found) {
    html += `<div class="mar-info-row"><span class="mar-label">Vue Router:</span> <span class="mar-value">已找到 (${routerInfo.routeCount} 条路由, ${utils.escapeHtml(routerInfo.mode || '')})</span></div>`;
  } else {
    html += `<div class="mar-info-row"><span class="mar-label">Vue Router:</span> <span class="mar-value mar-warn">未找到</span></div>`;
  }
  html += '</div>';

  const routeCount = allRoutes.filter(function (r) {
    return r.type === 'path-def' || r.type === 'bare-string';
  }).length;
  const compCount = allRoutes.filter(function (r) {
    return r.type === 'component-ref';
  }).length;
  const dictCount = allRoutes.filter(function (r) {
    return r.type === 'known-dict';
  }).length;

  html += `<div class="mar-stats">`;
  html += `<span class="mar-stat-item">JS路径: ${routeCount}</span>`;
  html += `<span class="mar-stat-item">组件: ${compCount}</span>`;
  if (dictCount > 0) {
    html += `<span class="mar-stat-item mar-stat-dict">字典: ${dictCount}</span>`;
  }
  html += `<span class="mar-stat-item mar-stat-hidden">未注册: ${hiddenRoutes.length}</span>`;
  html += '</div>';

  if (hiddenRoutes.length === 0) {
    html += utils.emptyHtml('所有路由均已注册，无需额外加载');
    utils.setStatus('mar-scan-status', '扫描完成 — 未发现隐藏路由');
    resultsEl.innerHTML = html;
    return;
  }

  html += `<div class="mar-routes-header">`;
  html += `<span>发现 ${hiddenRoutes.length} 条未注册路由（可选择注入到 Vue Router）</span>`;
  html += '</div>';

  html += '<div class="mar-route-list">';
  hiddenRoutes.forEach(function (r, i) {
    const displayPath = r.path || r.component;
    let typeLabel = '';
    if (r.type === 'component-ref') typeLabel = '[组件] ';
    else if (r.type === 'known-dict') typeLabel = '[字典] ';
    else if (r.type === 'bare-string') typeLabel = '[字符串] ';
    const titleSuffix = r.title ? ` — ${r.title}` : '';
    html += `<div class="mar-route-item"><label><input type="checkbox" class="mar-route-check" data-idx="${i}" checked> <span class="mar-route-path">${utils.escapeHtml(typeLabel + displayPath)}</span>`;
    if (titleSuffix) {
      html += `<span class="mar-route-title">${utils.escapeHtml(titleSuffix)}</span>`;
    }
    html += '</label></div>';
  });
  html += '</div>';

  resultsEl.innerHTML = html;
  utils.setStatus(
    'mar-scan-status',
    `扫描完成 — ${allRoutes.length} 条路由，${hiddenRoutes.length} 条未注册`
  );
}

// ====== Inject to Vue Router ======

async function marInjectToRouter() {
  const marHiddenRoutes = state ? state.marHiddenRoutes : [];
  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'warning');
      return;
    }

    let selected = [];
    document.querySelectorAll('.mar-route-check:checked').forEach(function (cb) {
      const idx = parseInt(cb.dataset.idx, 10);
      if (marHiddenRoutes[idx]) selected.push(marHiddenRoutes[idx]);
    });

    if (selected.length === 0) {
      utils.showToast('请至少选择一条路由', 'warning');
      return;
    }

    let routesToInject = [];
    selected.forEach(function (r) {
      if (r.type === 'known-dict') {
        routesToInject.push({
          path: r.path,
          name: (r.path || '').replace(/^\/+/, '').replace(/\//g, '-') || r.path,
          component: r.component || '',
          meta: { title: r.title || r.path },
        });
      } else if (r.type === 'component-ref') {
        const compPath = (r.component || '').replace(/^@\//, 'views/').replace(/\.\w+$/, '');
        const segs = compPath.replace(/^(views|pages|src)\//i, '').split('/');
        routesToInject.push({
          path: `/${segs.join('/')}`,
          name: segs[segs.length - 1] || 'unknown',
          component: r.component,
          meta: { title: segs[segs.length - 1] || r.component },
        });
      } else if (r.path) {
        const segs2 = r.path.replace(/^\/+/, '').split('/');
        routesToInject.push({
          path: r.path,
          name: segs2.join('-') || r.path,
          meta: { title: r.path },
        });
      }
    });

    // Step 1: Check if Vue Router exists
    const pageState =
      (await utils.execInTabData(tab.id, function () {
        const hook = window.__VK_RUOYI_HOOK__;
        const router =
          hook && typeof hook.findVueRouter === 'function' ? hook.findVueRouter() : null;
        return {
          hasVue: !!window.Vue || !!window.__vue_app__,
          hasRouter: !!router,
          routerMode: router ? router.mode || 'unknown' : null,
          currentPath: location.pathname + location.hash,
        };
      })) || {};

    if (!pageState.hasRouter) {
      let origin;
      try {
        origin = new URL(tab.url).origin;
      } catch (e) {
        utils.showToast('无法解析页面URL', 'error');
        return;
      }

      const paths = routesToInject.map(function (r) {
        return r.path;
      });

      const isThymeleaf = !pageState.hasVue;
      const hint = isThymeleaf
        ? '当前为非 Vue 应用 (Thymeleaf/jQuery)，直接访问 URL 测试权限绕过'
        : 'Vue 应用未加载，请先登录后重试，或直接访问 URL';

      utils.setStatus('mar-scan-status', hint);

      const urls = paths.map(function (p) {
        return origin + p;
      });
      utils.copyText(urls.join('\n'));

      if (urls.length > 0) {
        chrome.tabs.create({ url: urls[0] });
      }

      utils.showToast(`已复制 ${urls.length} 条 URL，并在新标签页打开第一条`, 'success');
      return;
    }

    // Step 2: Vue Router found — inject routes via hook
    const result =
      (await utils.execInTabData(
        tab.id,
        function (routes) {
          const hook = window.__VK_RUOYI_HOOK__;
          if (hook && typeof hook.injectRoutesToVueRouter === 'function') {
            return hook.injectRoutesToVueRouter(routes);
          }
          return { injected: 0, skipped: 0, errors: ['Hook not available'], routerFound: false };
        },
        { args: [routesToInject] }
      )) || {};

    if (!result.routerFound) {
      utils.setStatus('mar-scan-status', '注入失败: Vue Router 未找到');
      utils.showToast('Vue Router 未找到', 'error');
      return;
    }

    let msg = `成功注入 ${result.injected} 条路由到 Vue Router`;
    if (result.skipped > 0) msg += `，跳过 ${result.skipped} 条已存在`;
    if (result.errors.length > 0) msg += `，${result.errors.length} 个错误`;

    utils.setStatus('mar-scan-status', msg);
    utils.showToast(msg, result.injected > 0 ? 'success' : 'warning');
  } catch (e) {
    utils.setStatus('mar-scan-status', `注入失败: ${e.message}`);
    utils.showToast(`注入失败: ${e.message}`, 'error');
  }
}

function marToggleSelectAll() {
  commonToggleAll('.mar-route-check');
}

function marCopyHiddenPaths() {
  commonCopyPaths(state ? state.marHiddenRoutes : [], '没有隐藏路由');
}

// ====== Init ======

function init(stateRef) {
  state = stateRef;
}

export {
  init,
  marScanDynamicRoutes,
  marInjectToRouter,
  marToggleSelectAll,
  marCopyHiddenPaths,
};
