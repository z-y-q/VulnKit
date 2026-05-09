// vk-init-detectors.js - Security detection/scanning panel initializations
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

import * as vue from './vk-vue.js';
import {
  restoreVueRuntime,
  navigateVueRoute,
  jumpToRoute,
  filterRouteTree,
} from './vk-vue-detect.js';
import {
  ruoyiState,
  detectRuoYi,
  installRouteHook,
  removeRouteHook,
  checkHookStatus,
  analyzeJsRoutes,
  applyExtraRoutes,
  clearExtraRoutes,
  setAugmentMode,
  switchRuoYiSubTab,
  copyRouteJson,
  copyExtraPaths,
  toggleSelectAllRoutes,
  exportCurlCommands,
  exportHtmlReport,
  batchProbeRoutes,
  stopProbe,
  exportProbeResults,
  loadApiTraffic,
  clearApiTraffic,
  exportApiTraffic,
  filterApiTraffic,
  marScanDynamicRoutes,
  marInjectToRouter,
  marToggleSelectAll,
  marCopyHiddenPaths,
} from './vk-ruoyi.js';
import {
  switchJsCtrlTab,
  updateJsToggleStatus,
  disableJs,
  enableJs,
  scanAntiDebug,
  bypassAntiDebug,
  clearScriptBlock,
  removeCopyRestrictions,
  setJsBlocked,
} from './vk-jsctrl.js';
import {
  scanWaf,
  copyResults as wafCopyResults,
  exportResults as wafExportResults,
  filterByStatus as wafFilterByStatus,
  searchResults as wafSearchResults,
} from './vk-waf.js';
import {
  auditCookies,
  copyResults as cookieAuditCopy,
  exportResults as cookieAuditExport,
  filterBySeverity as cookieFilterBySeverity,
  searchResults as cookieSearchResults,
} from './vk-cookie-audit.js';
import {
  detectReact,
  copyResults as reactCopyResults,
  exportResults as reactExportResults,
  initSubTabs as initReactSubTabs,
  initStoreExplorerEvents,
  handleStoreRead,
  handleRouterRead,
  handleRouterCopy,
  copyReactStoreJson,
} from './vk-react.js';
import {
  detectAngular,
  copyResults as angularCopyResults,
  exportResults as angularExportResults,
} from './vk-angular.js';
import {
  scanCors,
  copyResults as corsCopyResults,
  exportJson as corsExportJson,
  filterBySeverity as corsFilterBySeverity,
  searchResults as corsSearchResults,
} from './vk-cors.js';
import {
  collectSubdomains,
  extractFromPage,
  bruteForceDns,
  copyResults as subdomainCopyResults,
  exportResults as subdomainExportResults,
  filterBySource as subdomainFilterBySource,
  searchResults as subdomainSearchResults,
  runAllScans,
} from './vk-subdomain.js';
import {
  loadToSources,
  copyResults as slCopyResults,
  clearResults as slClearResults,
} from './vk-source-loader.js';
import * as gather from './vk-gather.js';
import * as links from './vk-links.js';
import {
  runSniffScan,
  sniffCopyResults,
  sniffExportResults,
  renderSniffResults,
  renderLeakResults,
  clearLeakResults,
  leakCopyResults,
  leakExportResults,
  leakState,
} from './vk-sniff.js';
import { runDeepLeakScan } from './vk-leakscan-scanner.js';

const { getActiveTab } = utils;

function initVuePermissions() {
  utils.bindClick('vue-detect-btn', vue.detectVue);
  utils.bindClick('vue-export-routes-btn', vue.exportVueRoutes);
  utils.bindClick('vue-bypass-guards-btn', vue.bypassVueGuards);
  utils.bindClick('vue-disable-auth-btn', vue.disableRouteAuth);
  utils.bindClick('vue-restore-btn', restoreVueRuntime);
  utils.bindClick('vue-copy-btn', () => {
    if (!vue.vueState.lastVueResult) {
      utils.showToast('没有可复制的内容', 'warning');
      return;
    }
    utils.copyAndToast(vue.vueState.lastVueResult);
  });
  utils.on('vue-route-search', 'input', function () {
    filterRouteTree(this.value.trim());
  });

  const vueResultsEl = utils.on('vue-results', 'click', function (e) {
    if (e.target.classList.contains('vue-route-jump-btn')) {
      navigateVueRoute(e.target.dataset.path);
      return;
    }
    if (e.target.classList.contains('vue-route-open-btn')) {
      chrome.tabs.create({ url: e.target.dataset.url });
      return;
    }
    if (
      e.target.classList.contains('vue-copy-hist-btn') ||
      e.target.classList.contains('vue-copy-hash-btn')
    ) {
      if (!vue.vueState.lastVueResult) {
        utils.showToast('请先检测 Vue', 'warning');
        return;
      }
      try {
        const data = JSON.parse(vue.vueState.lastVueResult);
        if (!data.routes || !data.routes.length) {
          utils.showToast('无路由数据', 'warning');
          return;
        }
        const mode = e.target.classList.contains('vue-copy-hist-btn') ? 'history' : 'hash';
        const base = (data.routerInfo && data.routerInfo.base) || '/';
        const paths = vue.collectAllPaths(data.routes, '', base, mode);
        if (paths.length === 0) {
          utils.showToast('无静态路由路径', 'warning');
          return;
        }
        utils.copyText(paths.map(p => p.url).join('\n'));
        utils.showToast(`已复制 ${paths.length} 条 ${mode} URL`, 'success');
      } catch (err) {
        utils.showToast('复制失败', 'error');
      }
    }
  });
  utils.bindTabSwitch('vue-stab', 'vstab', vue.switchVueSubTab);

  utils.bindClick('vue-store-read-btn', vue.exploreVueStore);
  utils.bindClick('vue-store-copy-btn', vue.copyFullStoreJson);
  utils.bindClick('vue-store-refresh-btn', vue.exploreVueStore);
  vue.initStoreExplorerEvents();

  utils.bindClick('perm-start-btn', vue.startPermInterception);
  utils.bindClick('perm-stop-btn', vue.stopPermInterception);
  utils.bindClick('perm-refresh-btn', vue.refreshPermCaptured);
  utils.on('perm-filter', 'input', vue.renderPermList);
  utils.on('perm-type-filter', 'change', vue.renderPermList);
  utils.bindPersist('perm-type-filter');
  utils.bindClick('perm-detail-back', () => {
    vue.vueState.permViewMode = 'list';
    const permList = utils.get('perm-captured-list');
    if (permList) permList.classList.remove('hidden');
    const filterRow = utils.get('perm-filter-row');
    if (filterRow) filterRow.classList.remove('hidden');
    const permDetail = utils.get('perm-detail');
    if (permDetail) permDetail.classList.add('hidden');
  });
  utils.bindClick('perm-open-all', vue.permOpenAll);
  utils.bindClick('perm-change-admin', vue.permChangeAdmin);
  utils.bindClick('perm-apply-btn', vue.applyPermOverride);
  utils.bindClick('perm-copy-json', () => {
    const editorEl = utils.get('perm-json-editor');
    let val = editorEl ? editorEl.value : '';
    val = utils.requireInput(val, '没有数据');
    if (!val) return;
    utils.copyAndToast(val);
  });

  utils.bindClick('perm-expand-ids', vue.permExpandMenuIds);

  utils.bindClick('compare-inject-btn', () => {
    vue.switchVueSubTab('perm');
    if (vue.vueState.permSelectedIndex < 0 && vue.vueState.permCapturedData.length > 0) {
      vue.vueState.permSelectedIndex = 0;
      vue.showPermDetail(0);
    } else if (vue.vueState.permSelectedIndex >= 0) {
      vue.showPermDetail(vue.vueState.permSelectedIndex);
    }
    vue.autoInjectHiddenRoutes();
  });
}

function initJsSearchAndTraverse() {
  const doJsSearch = function () {
    vue.searchJsKeywords(utils.get('jssearch-keyword').value.trim());
  };
  utils.bindClick('jssearch-btn', doJsSearch);
  utils.bindEnterKey('jssearch-keyword', doJsSearch);
  utils.bindTabSwitch('jssearch-preset', 'kw', function (kw) {
    const input = utils.get('jssearch-keyword');
    if (input) input.value = kw;
    vue.searchJsKeywords(kw);
  });

  utils.bindClick('compare-btn', vue.compareRoutesAndMenu);
  utils.bindClick('compare-copy-hidden', () => {
    const items = utils.get('compare-results').querySelectorAll('.compare-route-path');
    const hiddenPaths = [];
    items.forEach(el => {
      const parentItem = el.closest('.compare-route-item');
      if (parentItem && parentItem.querySelector('.compare-route-hidden')) {
        hiddenPaths.push(el.textContent);
      }
    });
    if (hiddenPaths.length === 0) {
      utils.showToast('没有隐藏路由', 'warning');
      return;
    }
    utils.copyText(hiddenPaths.join('\n'));
    utils.showToast(`已复制 ${hiddenPaths.length} 条隐藏路由`, 'success');
  });

  utils.bindClick('traverse-start-btn', vue.startTraverseRoutes);
  utils.bindClick('traverse-stop-btn', vue.stopTraverse);

  utils.bindTabSwitch('jsctrl-tab', 'ctrl', switchJsCtrlTab);
  utils.bindClick('js-disable-btn', disableJs);
  utils.bindClick('js-enable-btn', enableJs);
  utils.bindClick('antidebug-scan-btn', scanAntiDebug);
  utils.bindClick('antidebug-bypass-btn', bypassAntiDebug);
  utils.bindClick('antidebug-clear-btn', clearScriptBlock);

  utils.bindClick('uncopy-btn', removeCopyRestrictions);
}

function initSecurityDetectors() {
  utils.bindTabSwitch('ruoyi-stab', 'rstab', switchRuoYiSubTab);

  utils.bindClick('ruoyi-detect-btn', detectRuoYi);

  utils.bindClick('ruoyi-hook-install-btn', installRouteHook);
  utils.bindClick('ruoyi-hook-remove-btn', removeRouteHook);
  utils.bindClick('ruoyi-hook-check-btn', checkHookStatus);
  utils.on('ruoyi-augment-mode', 'change', function () {
    setAugmentMode(this.value);
  });

  utils.bindClick('ruoyi-copy-json-btn', copyRouteJson);
  utils.bindClick('ruoyi-export-curl-btn', exportCurlCommands);
  utils.bindClick('ruoyi-export-html-btn', exportHtmlReport);

  utils.bindClick('ruoyi-analyze-btn', analyzeJsRoutes);
  utils.bindClick('ruoyi-apply-btn', applyExtraRoutes);
  utils.bindClick('ruoyi-clear-btn', clearExtraRoutes);
  utils.bindClick('ruoyi-selectall-btn', toggleSelectAllRoutes);
  utils.bindClick('ruoyi-copy-paths-btn', copyExtraPaths);

  utils.bindClick('ruoyi-probe-btn', batchProbeRoutes);
  utils.bindClick('ruoyi-probe-stop-btn', stopProbe);
  utils.bindClick('ruoyi-probe-export-btn', exportProbeResults);

  utils.bindClick('ruoyi-traffic-load-btn', loadApiTraffic);
  utils.bindClick('ruoyi-traffic-clear-btn', clearApiTraffic);
  utils.bindClick('ruoyi-traffic-export-btn', exportApiTraffic);
  utils.on('ruoyi-traffic-filter', 'input', filterApiTraffic);

  utils.bindClick('waf-scan-btn', scanWaf);
  utils.bindClick('waf-copy-btn', wafCopyResults);
  utils.bindClick('waf-export-btn', wafExportResults);
  utils.on('waf-search', 'input', function () {
    wafSearchResults(this.value.trim());
  });
  document.querySelectorAll('[data-wfilter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('[data-wfilter]').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      wafFilterByStatus(btn.dataset.wfilter);
    });
  });

  utils.bindClick('cookie-audit-btn', auditCookies);
  utils.bindClick('cookie-audit-copy-btn', cookieAuditCopy);
  utils.bindClick('cookie-audit-export-btn', cookieAuditExport);
  utils.on('cookie-audit-search', 'input', function () {
    cookieSearchResults(this.value.trim());
  });
  document.querySelectorAll('[data-cafilter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('[data-cafilter]').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      cookieFilterBySeverity(btn.dataset.cafilter);
    });
  });

  initReactSubTabs();
  utils.bindClick('react-detect-btn', detectReact);
  utils.bindClick('react-copy-btn', reactCopyResults);
  utils.bindClick('react-export-btn', reactExportResults);

  utils.bindClick('react-store-read-btn', handleStoreRead);
  utils.bindClick('react-store-copy-btn', copyReactStoreJson);
  utils.bindClick('react-store-refresh-btn', handleStoreRead);
  initStoreExplorerEvents();

  utils.bindClick('react-router-read-btn', handleRouterRead);
  utils.bindClick('react-router-copy-btn', handleRouterCopy);

  utils.bindClick('angular-detect-btn', detectAngular);
  utils.bindClick('angular-copy-btn', angularCopyResults);
  utils.bindClick('angular-export-btn', angularExportResults);
}

function initNetworkTools() {
  utils.bindClick('cors-scan-btn', scanCors);
  utils.bindClick('cors-copy-btn', corsCopyResults);
  utils.bindClick('cors-export-btn', corsExportJson);
  utils.on('cors-search', 'input', function () {
    corsSearchResults(this.value.trim());
  });
  document.querySelectorAll('[data-cfilter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('[data-cfilter]').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      corsFilterBySeverity(btn.dataset.cfilter);
    });
  });

  utils.bindClick('subdomain-scan-btn', collectSubdomains);
  utils.bindClick('subdomain-page-btn', extractFromPage);
  utils.bindClick('subdomain-dns-btn', bruteForceDns);
  utils.bindClick('subdomain-all-btn', runAllScans);
  utils.bindClick('subdomain-copy-btn', subdomainCopyResults);
  utils.bindClick('subdomain-export-btn', subdomainExportResults);
  utils.on('subdomain-search', 'input', function () {
    subdomainSearchResults(this.value.trim());
  });
  document.querySelectorAll('[data-sfilter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('[data-sfilter]').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      subdomainFilterBySource(btn.dataset.sfilter);
    });
  });

  utils.bindClick('source-loader-load-btn', loadToSources);
  utils.bindClick('source-loader-copy-btn', slCopyResults);
  utils.bindClick('source-loader-clear-btn', slClearResults);

  utils.bindClick('mar-scan-btn', marScanDynamicRoutes);
  utils.bindClick('mar-inject-btn', marInjectToRouter);
  utils.bindClick('mar-selectall-btn', marToggleSelectAll);
  utils.bindClick('mar-copy-btn', marCopyHiddenPaths);
}

function initSniff() {
  utils.bindTabSwitch('sniff-stab', 'sstab', function (tab) {
    utils.switchSubTabs('sniff-stab', 'sstab', 'sstab', tab);
  });

  utils.bindClick('sniff-scan-btn', async function () {
    utils.setStatus('sniff-status', '正在嗅探识别...');
    utils.get('sniff-scan-btn').disabled = true;

    try {
      var results = await runSniffScan();
      if (!results || results.length === 0) {
        utils.setStatus('sniff-status', '未检测到技术特征');
        utils.get('sniff-copy-btn').style.display = 'none';
        utils.get('sniff-export-btn').style.display = 'none';
        renderSniffResults([]);
        return;
      }
      utils.setStatus('sniff-status', '识别完成 — ' + results.length + ' 项技术');
      utils.get('sniff-copy-btn').style.display = '';
      utils.get('sniff-export-btn').style.display = '';
      renderSniffResults(results);
    } catch (err) {
      utils.setStatus('sniff-status', '嗅探失败: ' + (err.message || '未知错误'));
    } finally {
      utils.get('sniff-scan-btn').disabled = false;
    }
  });

  utils.bindClick('sniff-copy-btn', sniffCopyResults);
  utils.bindClick('sniff-export-btn', sniffExportResults);

  utils.bindClick('leak-scan-btn', async function () {
    if (leakState.scanning) return;
    leakState.scanning = true;
    utils.setStatus('leak-status', '正在深度泄露扫描...');
    utils.get('leak-scan-btn').disabled = true;
    clearLeakResults();

    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        utils.setStatus('leak-status', '无法获取当前标签页');
        return;
      }

      var results = await runDeepLeakScan({ 'API Traffic': [] }, tab.id);
      leakState.lastResults = results;

      if (!results || results.length === 0) {
        utils.setStatus('leak-status', '未发现敏感信息泄漏');
        utils.get('leak-copy-btn').style.display = 'none';
        utils.get('leak-export-btn').style.display = 'none';
        renderLeakResults([]);
        return;
      }

      var critCount = results.filter(function (r) {
        return r.severity === 'critical';
      }).length;
      var highCount = results.filter(function (r) {
        return r.severity === 'high';
      }).length;
      var statusText = '扫描完成 — 发现 ' + results.length + ' 项';
      if (critCount > 0) statusText += '（严重 ' + critCount + '）';
      else if (highCount > 0) statusText += '（高危 ' + highCount + '）';
      utils.setStatus('leak-status', statusText);
      utils.get('leak-copy-btn').style.display = '';
      utils.get('leak-export-btn').style.display = '';
      renderLeakResults(results);
    } catch (err) {
      utils.setStatus('leak-status', '泄露扫描失败: ' + (err.message || '未知错误'));
    } finally {
      utils.get('leak-scan-btn').disabled = false;
      leakState.scanning = false;
    }
  });

  utils.bindClick('leak-copy-btn', leakCopyResults);
  utils.bindClick('leak-export-btn', leakExportResults);
}

function initStateRestoration() {
  function restoreTabState(storageKey, onMatch) {
    chrome.storage.local.get([storageKey], function (result) {
      if (result[storageKey]) {
        getActiveTab().then(function (tab) {
          if (tab && tab.id === result[storageKey]) {
            onMatch();
          } else {
            chrome.storage.local.remove(storageKey);
          }
        });
      }
    });
  }

  restoreTabState('permInterceptTabId', function () {
    utils.requireTabId().then(function (tab) {
      if (!tab) {
        chrome.storage.local.remove('permInterceptTabId');
        return;
      }
      utils
        .execInTabData(tab.id, function () {
          return !!(window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active);
        })
        .then(function (active) {
          if (active) {
            vue.vueState.permInterceptActive = true;
            utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', true);
            utils.setStatus('perm-status', '拦截中...');
            vue.refreshPermCaptured();
          } else {
            chrome.storage.local.remove('permInterceptTabId');
          }
        })
        .catch(function () {
          chrome.storage.local.remove('permInterceptTabId');
        });
    });
  });

  chrome.runtime.sendMessage({ type: 'QUERY_JS_BLOCK' }, function (resp) {
    if (chrome.runtime.lastError) {
      chrome.storage.local.remove('js_blocked_tabId');
      return;
    }
    if (resp && resp.blocked) {
      setJsBlocked(true);
      updateJsToggleStatus();
    } else {
      chrome.storage.local.remove('js_blocked_tabId');
    }
  });

  chrome.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin', 'ruoyiHookTabId'], result => {
    getActiveTab().then(tab => {
      if (!tab) return;

      let tabOrigin = tab.url ? new URL(tab.url).origin : '';
      const hookEnabled = result.ruoyiHookEnabled && result.ruoyiHookOrigin;

      if (hookEnabled && tabOrigin === result.ruoyiHookOrigin) {
        ruoyiState.ruoyiHookActive = true;
        ruoyiState.ruoyiTabId = tab.id;
        utils.toggleBtnPair('ruoyi-hook-install-btn', 'ruoyi-hook-remove-btn', true);
        checkHookStatus();
      } else if (tab.url && /^https?:/.test(tab.url)) {
        checkHookStatus();
      }
    });
  });

  getActiveTab().then(tab => {
    const currentUrl = tab?.url || '';
    gather.restoreData(currentUrl);
    chrome.storage.local.get(['allLinks', 'allLinksUrl'], result => {
      if (result.allLinks && result.allLinksUrl === currentUrl) {
        links.setAllLinks(result.allLinks);
        links.renderLinks();
        utils.setStatus('links-count', `已恢复，共 ${result.allLinks.length} 个链接`);
      }
    });
  });
}

export {
  initVuePermissions,
  initJsSearchAndTraverse,
  initSecurityDetectors,
  initNetworkTools,
  initSniff,
  initStateRestoration,
};
