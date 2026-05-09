// 灵眸 - RuoYi Detect Sub-module
// Framework detection, auto-capture, and CVE lookup
import { utils, updateWorkflowStep } from './vk-ruoyi-common.js';
import * as CveDb from './vk-ruoyi-cve-db.js';

let state = null;

function buildEvidenceList(evidence) {
  if (!Array.isArray(evidence)) return '';
  return `<div class="ruoyi-evidence-list">${evidence
    .map(function (e) {
      return `<span class="ruoyi-evidence-item">${utils.escapeHtml(e)}</span>`;
    })
    .join('')}</div>`;
}

function buildDetectHtml(badge, label, evidence) {
  return `<div class="ruoyi-detect-info"><div class="ruoyi-detect-badge ${badge}">${utils.escapeHtml(label)}</div>${buildEvidenceList(evidence)}</div>`;
}

// ====== Framework Detection ======

async function detectRuoYi() {
  const resultsEl = utils.get('ruoyi-results');
  utils.setStatus('ruoyi-status', '检测中...');
  if (resultsEl) resultsEl.innerHTML = '';

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.setStatus('ruoyi-status', '无法获取当前标签页');
      return;
    }

    let data = await utils.execInTabData(tab.id, function () {
      const evidence = [];
      let variant = null;
      let version = null;

      // --- Script filenames ---
      const scripts = document.querySelectorAll('script[src]');
      const scriptSrcs = [];
      scripts.forEach(function (s) {
        const src = s.src || '';
        scriptSrcs.push(src);
        if (/\/request\.js/i.test(src)) evidence.push('script:request.js');
        if (/\/auth\.js/i.test(src)) evidence.push('script:auth.js');
        if (/\/permission\.js/i.test(src)) evidence.push('script:permission.js');
        if (/\/validate\.js/i.test(src)) evidence.push('script:validate.js');
        if (/\/ruoyi/i.test(src)) evidence.push('script:ruoyi');
        if (/\/router\/index\.js/i.test(src)) evidence.push('script:router/index.js');
        if (/\/store\/modules\/(user|permission|app)\.js/i.test(src)) evidence.push('script:store');
        if (/\/gateway\/js\//i.test(src)) {
          variant = variant || 'cloud';
          evidence.push('script:gateway');
        }
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
      const title = document.title || '';
      if (/若依|RuoYi|管理系统/i.test(title)) evidence.push('title:若依/RuoYi');

      // --- UI Framework ---
      const hasEl = !!window.ELEMENT || !!window.ElPlus || document.querySelector('[class*="el-"]');
      if (hasEl) evidence.push('ui:element');

      // --- Version detection ---
      if (window.ELEMENT) {
        version = (window.ELEMENT.version || '').replace(/^[^0-9]*/, '') || null;
        if (version) evidence.push(`version:element-ui-${version}`);
      }
      if (window.ElPlus) {
        version = (window.ElPlus.version || '').replace(/^[^0-9]*/, '') || null;
        if (version) evidence.push(`version:element-plus-${version}`);
      }

      // Check Vue version for variant identification
      if (window.Vue) {
        const vv = window.Vue.version;
        if (vv) evidence.push(`version:vue-${vv}`);
        if (/^3\./.test(vv)) variant = variant || 'vue3';
        else if (/^2\./.test(vv)) variant = variant || 'vue';
      } else if (hasEl) {
        const vueEl = document.querySelector('#app[data-v-app], #app.__vue_app__');
        if (vueEl || document.querySelector('#app')) {
          const hasVue3Chunk = scriptSrcs.some(function (s) {
            return /chunk-vendors|chunk-libs/i.test(s);
          });
          if (!variant) variant = 'vue';
          evidence.push('ui:vue-spa');
        }
      }

      // --- Global objects ---
      if (window.__CONFIG__) evidence.push('global:__CONFIG__');
      if (window.__APP_BASE_API__) evidence.push('global:__APP_BASE_API__');

      // --- Cookie token ---
      const cookies = document.cookie || '';
      if (/Admin-Token/i.test(cookies)) evidence.push('cookie:Admin-Token');
      if (/token=|JSESSIONID/i.test(cookies)) evidence.push('cookie:session-token');

      // --- RuoYi variant markers ---
      if (variant !== 'cloud' && variant !== 'app') {
        const metaGen = document.querySelector('meta[name="generator"]');
        if (metaGen && /ruoyi/i.test(metaGen.content)) {
          evidence.push('meta:generator-ruoyi');
        }
        if (document.querySelector('[class*="micro"]') || /microservice/i.test(title)) {
          variant = 'microservice';
          evidence.push('layout:microservice');
        }
        if (!variant && !window.Vue && window.jQuery) {
          const hasThymeleaf =
            document.querySelector('link[href*="bootstrap"]') || document.querySelector('iframe');
          const hasRuoYiJs = scriptSrcs.some(function (s) {
            return /\/ruoyi\/js\//i.test(s);
          });
          if (hasThymeleaf && hasRuoYiJs) {
            variant = 'thymeleaf';
            evidence.push('layout:thymeleaf');
          }
        }
      }

      // --- Inline script patterns ---
      const inline = document.querySelectorAll('script:not([src])');
      inline.forEach(function (s) {
        const t = s.textContent || '';
        if (/getRouters|getUserInfo|permission\.js|store\.dispatch.*permission/i.test(t)) {
          if (evidence.indexOf('code:ruoyi-pattern') === -1) evidence.push('code:ruoyi-pattern');
        }
        if (/\/auth\/login|\/auth\/logout|\/auth\/getInfo/i.test(t)) {
          if (evidence.indexOf('code:cloud-auth') === -1) {
            evidence.push('code:cloud-auth');
            variant = variant || 'cloud';
          }
        }
      });

      // --- Cloud-specific signals ---
      const pageText = document.documentElement.innerText || '';
      const pageSource = document.documentElement.outerHTML || '';
      if (/actuator\/gateway/i.test(pageText) || /Spring Cloud Gateway/i.test(pageText)) {
        if (evidence.indexOf('cloud:gateway') === -1) {
          evidence.push('cloud:gateway');
          variant = variant || 'cloud';
        }
      }
      if (/nacos/i.test(pageText)) {
        if (evidence.indexOf('cloud:nacos') === -1) {
          evidence.push('cloud:nacos');
          variant = variant || 'cloud';
        }
      }
      if (/sentinel/i.test(pageText) || /X-Sentinel/i.test(pageSource)) {
        if (evidence.indexOf('cloud:sentinel') === -1) evidence.push('cloud:sentinel');
      }
      if (/spring-cloud/i.test(pageText) || /SpringCloud/i.test(pageSource)) {
        if (evidence.indexOf('cloud:spring-cloud') === -1) {
          evidence.push('cloud:spring-cloud');
          variant = variant || 'cloud';
        }
      }
      if (/@FeignClient/i.test(pageSource) || /feign\.client/i.test(pageSource)) {
        if (evidence.indexOf('cloud:feign') === -1) {
          evidence.push('cloud:feign');
          variant = variant || 'cloud';
        }
      }
      if (/kubernetes|k8s/i.test(pageText) || /docker/i.test(pageSource)) {
        if (evidence.indexOf('cloud:container') === -1) {
          evidence.push('cloud:container');
          variant = variant || 'cloud';
        }
      }
      if (/seata/i.test(pageText) || /spring-cloud-alibaba/i.test(pageSource)) {
        if (evidence.indexOf('cloud:alibaba') === -1) {
          evidence.push('cloud:alibaba');
          variant = variant || 'cloud';
        }
      }
      scriptSrcs.forEach(function (src) {
        if (/actuator/i.test(src) && evidence.indexOf('cloud:actuator-script') === -1) {
          evidence.push('cloud:actuator-script');
        }
        if (/gateway/i.test(src) && evidence.indexOf('cloud:gateway-script') === -1) {
          evidence.push('cloud:gateway-script');
          variant = variant || 'cloud';
        }
        if (/nacos/i.test(src) && evidence.indexOf('cloud:nacos-script') === -1) {
          evidence.push('cloud:nacos-script');
          variant = variant || 'cloud';
        }
        if (/sentinel/i.test(src) && evidence.indexOf('cloud:sentinel-script') === -1) {
          evidence.push('cloud:sentinel-script');
        }
      });

      if (!variant && evidence.length >= 2) variant = 'unknown';

      return {
        detected: evidence.length >= 2,
        evidence: evidence,
        variant: variant,
        version: version,
        cookieToken: /Admin-Token/i.test(cookies),
      };
    });

    data = data || {
      detected: false,
      evidence: [],
      variant: null,
      version: null,
      cookieToken: false,
    };

    if (data.detected) {
      if (state) state.detectedVariant = data.variant;
      updateWorkflowStep(1);
      const variantLabel = data.variant ? ` [${data.variant.toUpperCase()}]` : '';
      let html = buildDetectHtml(
        'ruoyi-badge-ok',
        `RuoYi 框架已检测到${variantLabel}`,
        data.evidence
      );

      if (data.cookieToken) {
        html +=
          '<div class="ruoyi-detect-extra"><span class="ruoyi-detect-tag tag-token">Admin-Token Cookie 存在</span></div>';
      }
      if (data.version) {
        const cveUrl = `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(`RuoYi ${data.version}`)}&results_type=overview`;
        html += `<div class="ruoyi-detect-extra"><span class="ruoyi-detect-tag tag-version">Element ${utils.escapeHtml(data.version)}</span> <a href="${cveUrl}" target="_blank" class="ruoyi-cve-link">CVE 查询</a></div>`;
      }

      if (resultsEl) resultsEl.innerHTML = html;
      utils.setStatus('ruoyi-status', `检测到 RuoYi 框架 (${data.evidence.length} 个特征)`);
      utils.showToast('检测到 RuoYi 框架', 'success');

      setTimeout(function () {
        autoCaptureRoutes(tab.id, data.cookieToken);
      }, 300);
    } else if (data.evidence.length > 0) {
      updateWorkflowStep(0);
      if (resultsEl)
        resultsEl.innerHTML = buildDetectHtml(
          'ruoyi-badge-warn',
          `疑似 RuoYi (${data.evidence.length} 个特征)`,
          data.evidence
        );
      utils.setStatus('ruoyi-status', `疑似 RuoYi (${data.evidence.length} 个特征)`);
    } else {
      updateWorkflowStep(0);
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('当前页面未检测到 RuoYi 框架特征');
      utils.setStatus('ruoyi-status', '未检测到 RuoYi');
    }
  } catch (e) {
    updateWorkflowStep(0);
    utils.setStatus('ruoyi-status', '检测出错');
    utils.showToast(`检测失败: ${e.message}`, 'error');
  }
}

// ====== Auto Capture ======

async function autoCaptureRoutes(tabId, hasToken) {
  const panelEl = utils.get('ruoyi-captured-panel');
  try {
    const status = await utils.execInTabData(tabId, function () {
      const hook = window.__VK_RUOYI_HOOK__;
      return {
        installed: !!hook,
        captured: hook ? !!hook.capturedRouters : false,
      };
    });

    if (status && status.captured) {
      utils.setStatus('ruoyi-hook-status', '已捕获路由数据 (被动捕获模式)');
      await fetchCapturedRoutes();
      return;
    }

    if (hasToken) {
      const cookies =
        (await utils.execInTabData(tabId, function () {
          return document.cookie || '';
        })) || '';
      const cookieHeader = cookies ? { Cookie: cookies } : {};

      const routerPaths = [
        '/getRouters',
        '/system/menu/getRouters',
        '/prod-api/getRouters',
        '/api/getRouters',
      ];
      const tab = await chrome.tabs.get(tabId).catch(function () {
        return null;
      });
      const origin = tab && tab.url ? new URL(tab.url).origin : '';

      for (let i = 0; i < routerPaths.length; i++) {
        const probeUrl = origin + routerPaths[i];
        const resp = await chrome.runtime
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
          await utils.execInTab(
            tabId,
            function (body) {
              if (window.__VK_RUOYI_HOOK__) {
                window.__VK_RUOYI_HOOK__.capturedRouters = body;
              }
            },
            { args: [resp.body] }
          );
          utils.setStatus('ruoyi-hook-status', '已主动获取路由数据');
          await fetchCapturedRoutes();
          return;
        }
      }

      // Cloud: probe gateway routes
      const gatewayPaths = [
        '/actuator/gateway/routes',
        '/gateway/routes',
        '/actuator/gateway/routes.json',
      ];
      for (let gi = 0; gi < gatewayPaths.length; gi++) {
        const gwUrl = origin + gatewayPaths[gi];
        const gwResp = await chrome.runtime
          .sendMessage({
            type: 'FETCH_PROBE',
            url: gwUrl,
            method: 'GET',
            timeout: 8000,
            followRedirect: false,
            includeBody: true,
            headers: cookieHeader,
          })
          .catch(function () {
            return null;
          });

        if (gwResp && gwResp.status === 200 && gwResp.body) {
          try {
            const gwRoutes = JSON.parse(gwResp.body);
            const routeList = Array.isArray(gwRoutes) ? gwRoutes : [];
            if (routeList.length > 0) {
              const cloudRoutes = routeList.map(function (r) {
                const rd = r.route_definition || r;
                return {
                  path: rd.uri || r.route_id || r.route_name || '',
                  predicate: Array.isArray(rd.predicates)
                    ? rd.predicates
                        .map(function (p) {
                          return p._genkey_ || p;
                        })
                        .join(', ')
                    : rd.predicate || '',
                  filters: Array.isArray(rd.filters)
                    ? rd.filters
                        .map(function (f) {
                          return f._genkey_ || f.name || f;
                        })
                        .join(', ')
                    : rd.filters || '',
                  id: r.route_id || r.route_name || '',
                  order: typeof rd.order === 'number' ? rd.order : r.order || 0,
                  enabled: typeof rd.enabled === 'boolean' ? rd.enabled : true,
                };
              });
              const backendUris = cloudRoutes
                .map(function (cr) {
                  return cr.path;
                })
                .filter(function (u) {
                  return u && u.startsWith('lb://');
                })
                .map(function (u) {
                  return u.replace('lb://', '');
                })
                .filter(function (u, i, arr) {
                  return arr.indexOf(u) === i;
                });
              if (state) state.capturedGatewayRoutes = cloudRoutes;
              if (state) state.cloudBackendServices = backendUris;
              if (panelEl) {
                const gwHtml = `<div class="ruoyi-detect-extra"><span class="ruoyi-detect-tag tag-token">Gateway Routes (${cloudRoutes.length})</span>${
                  backendUris.length > 0
                    ? `<span class="ruoyi-detect-tag tag-version">后端服务: ${backendUris
                        .map(function (u) {
                          return utils.escapeHtml(u);
                        })
                        .join(', ')}</span>`
                    : ''
                }</div>`;
                panelEl.innerHTML += gwHtml;
              }
              utils.setStatus(
                'ruoyi-hook-status',
                `发现 ${cloudRoutes.length} 条 Gateway 路由${backendUris.length > 0 ? `，${backendUris.length} 个后端服务` : ''}`
              );
              utils.showToast(`发现 Gateway 路由: ${cloudRoutes.length} 条`, 'success');
            }
          } catch (e) {
            /* ignore */
          }

          // Cloud: probe Nacos service discovery
          const nacosPaths = [
            '/nacos/v1/ns/service/list?pageNo=1&pageSize=100',
            '/nacos/v1/ns/instance/list?serviceName=ruoyi-gateway',
          ];
          let discoveredServices = [];
          for (let ni = 0; ni < nacosPaths.length; ni++) {
            const nacosUrl = origin + nacosPaths[ni];
            const nacosResp = await chrome.runtime
              .sendMessage({
                type: 'FETCH_PROBE',
                url: nacosUrl,
                method: 'GET',
                timeout: 6000,
                followRedirect: false,
                includeBody: true,
                headers: {},
              })
              .catch(function () {
                return null;
              });

            if (nacosResp && nacosResp.status === 200 && nacosResp.body) {
              try {
                const nacosData = JSON.parse(nacosResp.body);
                if (nacosResp.url.indexOf('/service/list') !== -1 && nacosData.count > 0) {
                  const serviceNames =
                    typeof nacosData.domains === 'string'
                      ? nacosData.domains.split(',').filter(function (s) {
                          return s.length > 0;
                        })
                      : Array.isArray(nacosData.domains)
                        ? nacosData.domains
                        : [];
                  discoveredServices = discoveredServices.concat(serviceNames);
                }
                if (nacosData.hosts && Array.isArray(nacosData.hosts)) {
                  const instances = nacosData.hosts.map(function (h) {
                    return {
                      ip: h.ip || '',
                      port: h.port || 0,
                      serviceName: h.serviceName || '',
                      enabled: h.enabled !== false,
                      healthy: h.healthy !== false,
                      metadata: h.metadata || {},
                    };
                  });
                  if (instances.length > 0 && state) {
                    state.nacosInstances = (state.nacosInstances || []).concat(instances);
                  }
                }
              } catch (e) {
                /* ignore */
              }
            }
          }

          if (discoveredServices.length > 0) {
            if (state) state.nacosServices = discoveredServices;
            if (panelEl) {
              const nacosHtml = `<div class="ruoyi-detect-extra"><span class="ruoyi-detect-tag tag-token">Nacos 服务 (${discoveredServices.length}): ${discoveredServices
                .slice(0, 8)
                .map(function (s) {
                  return utils.escapeHtml(s);
                })
                .join(', ')}${discoveredServices.length > 8 ? '...' : ''}</span></div>`;
              panelEl.innerHTML += nacosHtml;
            }
            utils.setStatus('ruoyi-hook-status', `发现 ${discoveredServices.length} 个 Nacos 服务`);
            utils.showToast(`发现 Nacos 服务: ${discoveredServices.length} 个`, 'success');
          }
        }
      }
    }

    utils.setStatus(
      'ruoyi-hook-status',
      hasToken ? '钩子已注入，正在监听 /getRouters...' : '请先登录 RuoYi 系统，钩子将自动捕获路由'
    );
    if (panelEl) {
      panelEl.innerHTML = utils.emptyHtml(
        hasToken
          ? '钩子已就绪，刷新页面或重新登录以触发 /getRouters 请求'
          : '请先登录 RuoYi 系统，登录后钩子会自动捕获路由数据'
      );
    }
  } catch (e) {
    utils.setStatus('ruoyi-hook-status', `自动捕获检查失败: ${e.message}`);
  }
}

// ====== CVE Lookup ======

function lookupCve(version) {
  version = utils.requireInput(version, '未检测到版本信息');
  if (!version) return;

  const resultsEl = utils.get('ruoyi-results');
  let matches = CveDb.searchByVersion(version);

  if (matches.length === 0) {
    matches = CveDb.searchCve('RuoYi');
  }

  let html = '<div class="ruoyi-cve-panel">';
  html += `<div class="ruoyi-cve-header">RuoYi ${utils.escapeHtml(version)} CVE 数据库 (${matches.length} 条)</div>`;

  if (matches.length === 0) {
    html += '<div class="ruoyi-cve-empty">未找到匹配的已知漏洞</div>';
  } else {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    matches.sort(function (a, b) {
      return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    });
    matches.forEach(function (cve) {
      html += `<div class="ruoyi-cve-item ruoyi-cve-${cve.severity}">
<div class="ruoyi-cve-title"><span class="ruoyi-cve-severity ${cve.severity}">${cve.severity.toUpperCase()}</span> ${utils.escapeHtml(cve.id)}</div>
<div class="ruoyi-cve-desc">${utils.escapeHtml(cve.title)}</div>
<div class="ruoyi-cve-detail">${utils.escapeHtml(cve.description)}</div>
<div class="ruoyi-cve-affected">影响版本: ${cve.affected
        .map(function (a) {
          return utils.escapeHtml(a);
        })
        .join(', ')}</div>${
        cve.refs && cve.refs.length > 0
          ? `<div class="ruoyi-cve-refs">${cve.refs
              .map(function (ref) {
                return `<a href="${utils.escapeHtml(ref)}" target="_blank" class="ruoyi-cve-link">NVD 详情</a>`;
              })
              .join('')}</div>`
          : ''
      }
</div>`;
    });
  }

  const nvdUrl = `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(`RuoYi ${version}`)}&results_type=overview`;
  html += `<div class="ruoyi-cve-footer"><a href="${nvdUrl}" target="_blank" class="ruoyi-cve-link">在 NVD 中搜索更多</a></div>`;
  html += '</div>';

  if (resultsEl) resultsEl.innerHTML = html;
  utils.setStatus('ruoyi-status', `CVE 查询完成: ${matches.length} 条结果`);
}

// ====== Fetch Captured Routes (shared with hook module) ======

async function fetchCapturedRoutes() {
  const panelEl = utils.get('ruoyi-captured-panel');
  try {
    return utils.withTab(async function (tab) {
      const data = await utils.execInTabData(tab.id, function () {
        if (!window.__VK_RUOYI_HOOK__ || !window.__VK_RUOYI_HOOK__.capturedRouters) return null;
        try {
          return JSON.parse(window.__VK_RUOYI_HOOK__.capturedRouters);
        } catch (e) {
          return { _raw: window.__VK_RUOYI_HOOK__.capturedRouters, _parseError: true };
        }
      });
      if (!data) return;
      if (state) state.capturedRouterData = data;
      // Delegate rendering to hook module via state reference
      if (state && state.hooks && typeof state.hooks.renderRouterData === 'function') {
        state.hooks.renderRouterData(data, panelEl);
      }
    });
  } catch (e) {
    utils.showToast(`获取捕获数据失败: ${e.message}`, 'error');
  }
}

// ====== Init ======

function init(stateRef) {
  state = stateRef;
}

export { init, detectRuoYi, autoCaptureRoutes, lookupCve, fetchCapturedRoutes };
