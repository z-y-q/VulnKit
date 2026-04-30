// VulnKit - RuoYi Detect Sub-module
// Framework detection, auto-capture, and CVE lookup
window.VulnKitRuoYiDetect = (function () {
  'use strict';

  var state = null;
  var common = window.VulnKitRuoYiCommon;
  var utils = common ? common.utils : {};
  var getActiveTab = common ? common.getActiveTab : null;

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

  var updateWorkflowStep = common ? common.updateWorkflowStep : null;

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
            var vueEl = document.querySelector('#app[data-v-app], #app.__vue_app__');
            if (vueEl || document.querySelector('#app')) {
              var hasVue3Chunk = scriptSrcs.some(function (s) {
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
          var cookies = document.cookie || '';
          if (/Admin-Token/i.test(cookies)) evidence.push('cookie:Admin-Token');
          if (/token=|JSESSIONID/i.test(cookies)) evidence.push('cookie:session-token');

          // --- RuoYi variant markers ---
          if (variant !== 'cloud' && variant !== 'app') {
            var metaGen = document.querySelector('meta[name="generator"]');
            if (metaGen && /ruoyi/i.test(metaGen.content)) {
              evidence.push('meta:generator-ruoyi');
            }
            if (document.querySelector('[class*="micro"]') || /microservice/i.test(title)) {
              variant = 'microservice';
              evidence.push('layout:microservice');
            }
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
            if (/\/auth\/login|\/auth\/logout|\/auth\/getInfo/i.test(t)) {
              if (evidence.indexOf('code:cloud-auth') === -1) {
                evidence.push('code:cloud-auth');
                variant = variant || 'cloud';
              }
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
        updateWorkflowStep(1);
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
          var cveUrl =
            'https://nvd.nist.gov/vuln/search/results?query=' +
            encodeURIComponent('RuoYi ' + data.version) +
            '&results_type=overview';
          html +=
            '<div class="ruoyi-detect-extra">' +
            '<span class="ruoyi-detect-tag tag-version">Element ' +
            utils.escapeHtml(data.version) +
            '</span>' +
            ' <a href="' +
            cveUrl +
            '" target="_blank" class="ruoyi-cve-link">CVE 查询</a>' +
            '</div>';
        }

        if (resultsEl) resultsEl.innerHTML = html;
        if (statusEl)
          statusEl.textContent = '检测到 RuoYi 框架 (' + data.evidence.length + ' 个特征)';
        utils.showToast('检测到 RuoYi 框架', 'success');

        setTimeout(function () {
          autoCaptureRoutes(tab.id, data.cookieToken);
        }, 300);
      } else if (data.evidence.length > 0) {
        updateWorkflowStep(0);
        if (resultsEl)
          resultsEl.innerHTML = buildDetectHtml(
            'ruoyi-badge-warn',
            '疑似 RuoYi (' + data.evidence.length + ' 个特征)',
            data.evidence
          );
        if (statusEl) statusEl.textContent = '疑似 RuoYi (' + data.evidence.length + ' 个特征)';
      } else {
        updateWorkflowStep(0);
        if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('当前页面未检测到 RuoYi 框架特征');
        if (statusEl) statusEl.textContent = '未检测到 RuoYi';
      }
    } catch (e) {
      updateWorkflowStep(0);
      if (statusEl) statusEl.textContent = '检测出错';
      utils.showToast('检测失败: ' + e.message, 'error');
    }
  }

  // ====== Auto Capture ======

  async function autoCaptureRoutes(tabId, hasToken) {
    var hookStatusEl = utils.get('ruoyi-hook-status');
    var panelEl = utils.get('ruoyi-captured-panel');
    try {
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
        if (hookStatusEl) hookStatusEl.textContent = '已捕获路由数据 (被动捕获模式)';
        await fetchCapturedRoutes();
        return;
      }

      if (hasToken) {
        var cookieResult = await chrome.scripting.executeScript({
          target: { tabId: tabId },
          world: 'MAIN',
          func: function () {
            return document.cookie || '';
          },
        });
        var cookies = (cookieResult && cookieResult[0] && cookieResult[0].result) || '';
        var cookieHeader = cookies ? { Cookie: cookies } : {};

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

      if (hookStatusEl) {
        if (hasToken) {
          hookStatusEl.textContent = '钩子已注入，正在监听 /getRouters...';
        } else {
          hookStatusEl.textContent = '请先登录 RuoYi 系统，钩子将自动捕获路由';
        }
      }
      if (panelEl) {
        panelEl.innerHTML = utils.emptyHtml(
          hasToken
            ? '钩子已就绪，刷新页面或重新登录以触发 /getRouters 请求'
            : '请先登录 RuoYi 系统，登录后钩子会自动捕获路由数据'
        );
      }
    } catch (e) {
      if (hookStatusEl) hookStatusEl.textContent = '自动捕获检查失败: ' + e.message;
    }
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

  // ====== Fetch Captured Routes (shared with hook module) ======

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
      if (state) state.capturedRouterData = data;
      // Delegate rendering to hook module if available
      if (
        window.VulnKitRuoYiHook &&
        typeof window.VulnKitRuoYiHook.renderRouterData === 'function'
      ) {
        window.VulnKitRuoYiHook.renderRouterData(data, panelEl);
      }
    } catch (e) {
      utils.showToast('获取捕获数据失败: ' + e.message, 'error');
    }
  }

  // ====== Init ======

  function init(stateRef) {
    state = stateRef;
  }

  return {
    init: init,
    detectRuoYi: detectRuoYi,
    autoCaptureRoutes: autoCaptureRoutes,
    lookupCve: lookupCve,
    fetchCapturedRoutes: fetchCapturedRoutes,
  };
})();
