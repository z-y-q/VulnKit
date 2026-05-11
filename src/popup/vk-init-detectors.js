// vk-init-detectors.js - Security detection/scanning panel initializations (lazy-loaded)
// No static imports — each init function loads its own dependencies dynamically.
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const { getActiveTab } = utils;

function initVuePermissions() {
  Promise.all([import('./vk-vue.js'), import('./vk-vue-detect.js')]).then(function (mods) {
    var vue = mods[0];
    var vueDetect = mods[1];

    utils.bindClick('vue-detect-btn', vue.detectVue);
    utils.bindClick('vue-export-routes-btn', vue.exportVueRoutes);
    utils.bindClick('vue-bypass-guards-btn', vue.bypassVueGuards);
    utils.bindClick('vue-disable-auth-btn', vue.disableRouteAuth);
    utils.bindClick('vue-restore-btn', vueDetect.restoreVueRuntime);
    utils.bindClick('vue-copy-btn', function () {
      if (!vue.vueState.lastVueResult) {
        utils.showToast('没有可复制的内容', 'warning');
        return;
      }
      utils.copyAndToast(vue.vueState.lastVueResult);
    });
    utils.on('vue-route-search', 'input', function () {
      vueDetect.filterRouteTree(this.value.trim());
    });

    var vueResultsEl = utils.on('vue-results', 'click', function (e) {
      if (e.target.classList.contains('vue-route-jump-btn')) {
        vueDetect.navigateVueRoute(e.target.dataset.path);
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
          var data = JSON.parse(vue.vueState.lastVueResult);
          if (!data.routes || !data.routes.length) {
            utils.showToast('无路由数据', 'warning');
            return;
          }
          var mode = e.target.classList.contains('vue-copy-hist-btn') ? 'history' : 'hash';
          var base = (data.routerInfo && data.routerInfo.base) || '/';
          var paths = vue.collectAllPaths(data.routes, '', base, mode);
          if (paths.length === 0) {
            utils.showToast('无静态路由路径', 'warning');
            return;
          }
          utils.copyText(
            paths
              .map(function (p) {
                return p.url;
              })
              .join('\n')
          );
          utils.showToast('已复制 ' + paths.length + ' 条 ' + mode + ' URL', 'success');
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
    utils.bindClick('perm-detail-back', function () {
      vue.vueState.permViewMode = 'list';
      var permList = utils.get('perm-captured-list');
      if (permList) permList.classList.remove('hidden');
      var filterRow = utils.get('perm-filter-row');
      if (filterRow) filterRow.classList.remove('hidden');
      var permDetail = utils.get('perm-detail');
      if (permDetail) permDetail.classList.add('hidden');
    });
    utils.bindClick('perm-open-all', vue.permOpenAll);
    utils.bindClick('perm-change-admin', vue.permChangeAdmin);
    utils.bindClick('perm-apply-btn', vue.applyPermOverride);
    utils.bindClick('perm-copy-json', function () {
      var editorEl = utils.get('perm-json-editor');
      var val = editorEl ? editorEl.value : '';
      val = utils.requireInput(val, '没有数据');
      if (!val) return;
      utils.copyAndToast(val);
    });

    utils.bindClick('perm-expand-ids', vue.permExpandMenuIds);

    utils.bindClick('compare-inject-btn', function () {
      vue.switchVueSubTab('perm');
      if (vue.vueState.permSelectedIndex < 0 && vue.vueState.permCapturedData.length > 0) {
        vue.vueState.permSelectedIndex = 0;
        vue.showPermDetail(0);
      } else if (vue.vueState.permSelectedIndex >= 0) {
        vue.showPermDetail(vue.vueState.permSelectedIndex);
      }
      vue.autoInjectHiddenRoutes();
    });

    // Restore perm interception state for current tab
    restorePermState(vue, vueDetect);
  });
}

function restorePermState(vue, vueDetect) {
  chrome.storage.local.get(['permInterceptTabId'], function (result) {
    if (!result.permInterceptTabId) return;
    getActiveTab().then(function (tab) {
      if (tab && tab.id === result.permInterceptTabId) {
        utils.requireTabId().then(function (tabInfo) {
          if (!tabInfo) {
            chrome.storage.local.remove('permInterceptTabId');
            return;
          }
          utils
            .execInTabData(tabInfo.id, function () {
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
      } else {
        chrome.storage.local.remove('permInterceptTabId');
      }
    });
  });
}

function initJsSearchAndTraverse() {
  Promise.all([import('./vk-vue.js'), import('./vk-jsctrl.js')]).then(function (mods) {
    var vue = mods[0];
    var jsctrl = mods[1];

    var doJsSearch = function () {
      vue.searchJsKeywords(utils.get('jssearch-keyword').value.trim());
    };
    utils.bindClick('jssearch-btn', doJsSearch);
    utils.bindEnterKey('jssearch-keyword', doJsSearch);
    utils.bindTabSwitch('jssearch-preset', 'kw', function (kw) {
      var input = utils.get('jssearch-keyword');
      if (input) input.value = kw;
      vue.searchJsKeywords(kw);
    });

    utils.bindClick('compare-btn', vue.compareRoutesAndMenu);
    utils.bindClick('compare-copy-hidden', function () {
      var items = utils.get('compare-results').querySelectorAll('.compare-route-path');
      var hiddenPaths = [];
      items.forEach(function (el) {
        var parentItem = el.closest('.compare-route-item');
        if (parentItem && parentItem.querySelector('.compare-route-hidden')) {
          hiddenPaths.push(el.textContent);
        }
      });
      if (hiddenPaths.length === 0) {
        utils.showToast('没有隐藏路由', 'warning');
        return;
      }
      utils.copyText(hiddenPaths.join('\n'));
      utils.showToast('已复制 ' + hiddenPaths.length + ' 条隐藏路由', 'success');
    });

    utils.bindClick('traverse-start-btn', vue.startTraverseRoutes);
    utils.bindClick('traverse-stop-btn', vue.stopTraverse);

    utils.bindTabSwitch('jsctrl-tab', 'ctrl', jsctrl.switchJsCtrlTab);
    utils.bindClick('js-disable-btn', jsctrl.disableJs);
    utils.bindClick('js-enable-btn', jsctrl.enableJs);
    utils.bindClick('antidebug-scan-btn', jsctrl.scanAntiDebug);
    utils.bindClick('antidebug-bypass-btn', jsctrl.bypassAntiDebug);
    utils.bindClick('antidebug-clear-btn', jsctrl.clearScriptBlock);

    utils.bindClick('uncopy-btn', jsctrl.removeCopyRestrictions);
  });
}

function initSecurityDetectors() {
  Promise.all([
    import('./vk-ruoyi.js'),
    import('./vk-waf.js'),
    import('./vk-cookie-audit.js'),
    import('./vk-react.js'),
    import('./vk-angular.js'),
  ]).then(function (mods) {
    var ruoyi = mods[0];
    var waf = mods[1];
    var cookieAudit = mods[2];
    var react = mods[3];
    var angular = mods[4];

    utils.bindTabSwitch('ruoyi-stab', 'rstab', ruoyi.switchRuoYiSubTab);

    utils.bindClick('ruoyi-detect-btn', ruoyi.detectRuoYi);

    utils.bindClick('ruoyi-hook-install-btn', ruoyi.installRouteHook);
    utils.bindClick('ruoyi-hook-remove-btn', ruoyi.removeRouteHook);
    utils.bindClick('ruoyi-hook-check-btn', ruoyi.checkHookStatus);
    utils.on('ruoyi-augment-mode', 'change', function () {
      ruoyi.setAugmentMode(this.value);
    });

    utils.bindClick('ruoyi-copy-json-btn', ruoyi.copyRouteJson);
    utils.bindClick('ruoyi-export-curl-btn', ruoyi.exportCurlCommands);
    utils.bindClick('ruoyi-export-html-btn', ruoyi.exportHtmlReport);

    utils.bindClick('ruoyi-analyze-btn', ruoyi.analyzeJsRoutes);
    utils.bindClick('ruoyi-apply-btn', ruoyi.applyExtraRoutes);
    utils.bindClick('ruoyi-clear-btn', ruoyi.clearExtraRoutes);
    utils.bindClick('ruoyi-selectall-btn', ruoyi.toggleSelectAllRoutes);
    utils.bindClick('ruoyi-copy-paths-btn', ruoyi.copyExtraPaths);

    utils.bindClick('ruoyi-probe-btn', ruoyi.batchProbeRoutes);
    utils.bindClick('ruoyi-probe-stop-btn', ruoyi.stopProbe);
    utils.bindClick('ruoyi-probe-export-btn', ruoyi.exportProbeResults);

    utils.bindClick('ruoyi-traffic-load-btn', ruoyi.loadApiTraffic);
    utils.bindClick('ruoyi-traffic-clear-btn', ruoyi.clearApiTraffic);
    utils.bindClick('ruoyi-traffic-export-btn', ruoyi.exportApiTraffic);
    utils.on('ruoyi-traffic-filter', 'input', ruoyi.filterApiTraffic);

    utils.bindClick('waf-scan-btn', waf.scanWaf);
    utils.bindClick('waf-copy-btn', waf.copyResults);
    utils.bindClick('waf-export-btn', waf.exportResults);
    utils.on('waf-search', 'input', function () {
      waf.searchResults(this.value.trim());
    });
    document.querySelectorAll('[data-wfilter]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('[data-wfilter]').forEach(function (b) {
          b.classList.remove('active');
        });
        btn.classList.add('active');
        waf.filterByStatus(btn.dataset.wfilter);
      });
    });

    utils.bindClick('cookie-audit-btn', cookieAudit.auditCookies);
    utils.bindClick('cookie-audit-copy-btn', cookieAudit.copyResults);
    utils.bindClick('cookie-audit-export-btn', cookieAudit.exportResults);
    utils.on('cookie-audit-search', 'input', function () {
      cookieAudit.searchResults(this.value.trim());
    });
    document.querySelectorAll('[data-cafilter]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('[data-cafilter]').forEach(function (b) {
          b.classList.remove('active');
        });
        btn.classList.add('active');
        cookieAudit.filterBySeverity(btn.dataset.cafilter);
      });
    });

    react.initSubTabs();
    utils.bindClick('react-detect-btn', react.detectReact);
    utils.bindClick('react-copy-btn', react.copyResults);
    utils.bindClick('react-export-btn', react.exportResults);

    utils.bindClick('react-store-read-btn', react.handleStoreRead);
    utils.bindClick('react-store-copy-btn', react.copyReactStoreJson);
    utils.bindClick('react-store-refresh-btn', react.handleStoreRead);
    react.initStoreExplorerEvents();

    utils.bindClick('react-router-read-btn', react.handleRouterRead);
    utils.bindClick('react-router-copy-btn', react.handleRouterCopy);

    utils.bindClick('angular-detect-btn', angular.detectAngular);
    utils.bindClick('angular-copy-btn', angular.copyResults);
    utils.bindClick('angular-export-btn', angular.exportResults);

    // Restore RuoYi hook state for current tab
    restoreRuoYiHookState(ruoyi);
  });
}

function restoreRuoYiHookState(ruoyi) {
  chrome.storage.local.get(
    ['ruoyiHookEnabled', 'ruoyiHookOrigin', 'ruoyiHookTabId'],
    function (result) {
      getActiveTab().then(function (tab) {
        if (!tab) return;
        var tabOrigin = tab.url ? new URL(tab.url).origin : '';
        var hookEnabled = result.ruoyiHookEnabled && result.ruoyiHookOrigin;

        if (hookEnabled && tabOrigin === result.ruoyiHookOrigin) {
          ruoyi.ruoyiState.ruoyiHookActive = true;
          ruoyi.ruoyiState.ruoyiTabId = tab.id;
          utils.toggleBtnPair('ruoyi-hook-install-btn', 'ruoyi-hook-remove-btn', true);
          ruoyi.checkHookStatus();
        } else if (tab.url && /^https?:/.test(tab.url)) {
          ruoyi.checkHookStatus();
        }
      });
    }
  );
}

function initNetworkTools() {
  Promise.all([
    import('./vk-cors.js'),
    import('./vk-subdomain.js'),
    import('./vk-source-loader.js'),
    import('./vk-ruoyi.js'),
    import('./vk-graphql.js'),
  ]).then(function (mods) {
    var cors = mods[0];
    var subdomain = mods[1];
    var sourceLoader = mods[2];
    var ruoyi = mods[3];
    var graphql = mods[4];

    utils.bindClick('cors-scan-btn', cors.scanCors);
    utils.bindClick('cors-copy-btn', cors.copyResults);
    utils.bindClick('cors-export-btn', cors.exportJson);
    utils.on('cors-search', 'input', function () {
      cors.searchResults(this.value.trim());
    });
    document.querySelectorAll('[data-cfilter]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('[data-cfilter]').forEach(function (b) {
          b.classList.remove('active');
        });
        btn.classList.add('active');
        cors.filterBySeverity(btn.dataset.cfilter);
      });
    });

    utils.bindClick('subdomain-scan-btn', subdomain.collectSubdomains);
    utils.bindClick('subdomain-page-btn', subdomain.extractFromPage);
    utils.bindClick('subdomain-dns-btn', subdomain.bruteForceDns);
    utils.bindClick('subdomain-all-btn', subdomain.runAllScans);
    utils.bindClick('subdomain-copy-btn', subdomain.copyResults);
    utils.bindClick('subdomain-export-btn', subdomain.exportResults);
    utils.bindClick('subdomain-certspotter-btn', subdomain.collectFromCertspotter);
    utils.bindClick('subdomain-archive-btn', subdomain.collectFromWebArchive);
    utils.bindClick('subdomain-dnsrec-btn', subdomain.collectFromDnsRecords);
    utils.on('subdomain-search', 'input', function () {
      subdomain.searchResults(this.value.trim());
    });
    document.querySelectorAll('[data-sfilter]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('[data-sfilter]').forEach(function (b) {
          b.classList.remove('active');
        });
        btn.classList.add('active');
        subdomain.filterBySource(btn.dataset.sfilter);
      });
    });

    utils.bindClick('source-loader-load-btn', sourceLoader.loadToSources);
    utils.bindClick('source-loader-copy-btn', sourceLoader.copyResults);
    utils.bindClick('source-loader-clear-btn', sourceLoader.clearResults);

    utils.bindClick('mar-scan-btn', ruoyi.marScanDynamicRoutes);
    utils.bindClick('mar-inject-btn', ruoyi.marInjectToRouter);
    utils.bindClick('mar-selectall-btn', ruoyi.marToggleSelectAll);
    utils.bindClick('mar-copy-btn', ruoyi.marCopyHiddenPaths);

    utils.bindClick('graphql-scan-btn', graphql.scanGraphQL);
    utils.bindClick('graphql-exec-btn', graphql.executeCustomQuery);
    utils.bindClick('graphql-copy-btn', graphql.copyResults);
    utils.bindClick('graphql-export-btn', graphql.exportResults);
  });
}

function initSniff() {
  Promise.all([import('./vk-sniff.js'), import('./vk-leakscan-scanner.js')]).then(function (mods) {
    var sniff = mods[0];
    var leakscan = mods[1];

    utils.bindTabSwitch('sniff-stab', 'sstab', function (tab) {
      utils.switchSubTabs('sniff-stab', 'sstab', 'sstab', tab);
    });

    utils.bindClick('sniff-scan-btn', async function () {
      utils.setStatus('sniff-status', '正在嗅探识别...');
      utils.get('sniff-scan-btn').disabled = true;

      try {
        var results = await sniff.runSniffScan();
        if (!results || results.length === 0) {
          utils.setStatus('sniff-status', '未检测到技术特征');
          utils.get('sniff-copy-btn').style.display = 'none';
          utils.get('sniff-export-btn').style.display = 'none';
          sniff.renderSniffResults([]);
          return;
        }
        utils.setStatus('sniff-status', '识别完成 — ' + results.length + ' 项技术');
        utils.get('sniff-copy-btn').style.display = '';
        utils.get('sniff-export-btn').style.display = '';
        sniff.renderSniffResults(results);
      } catch (err) {
        utils.setStatus('sniff-status', '嗅探失败: ' + (err.message || '未知错误'));
      } finally {
        utils.get('sniff-scan-btn').disabled = false;
      }
    });

    utils.bindClick('sniff-copy-btn', sniff.sniffCopyResults);
    utils.bindClick('sniff-export-btn', sniff.sniffExportResults);

    utils.bindClick('leak-scan-btn', async function () {
      if (sniff.leakState.scanning) return;
      sniff.leakState.scanning = true;
      utils.setStatus('leak-status', '正在深度泄露扫描...');
      utils.get('leak-scan-btn').disabled = true;
      sniff.clearLeakResults();

      try {
        var tab = await utils.requireTabId();
        if (!tab) {
          utils.setStatus('leak-status', '无法获取当前标签页');
          return;
        }

        var results = await leakscan.runDeepLeakScan({ 'API Traffic': [] }, tab.id);
        sniff.leakState.lastResults = results;

        if (!results || results.length === 0) {
          utils.setStatus('leak-status', '未发现敏感信息泄漏');
          utils.get('leak-copy-btn').style.display = 'none';
          utils.get('leak-export-btn').style.display = 'none';
          sniff.renderLeakResults([]);
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
        sniff.renderLeakResults(results);
      } catch (err) {
        utils.setStatus('leak-status', '泄露扫描失败: ' + (err.message || '未知错误'));
      } finally {
        utils.get('leak-scan-btn').disabled = false;
        sniff.leakState.scanning = false;
      }
    });

    utils.bindClick('leak-copy-btn', sniff.leakCopyResults);
    utils.bindClick('leak-export-btn', sniff.leakExportResults);
  });
}

// initStateRestoration is now handled in vk-init.js for JS block state.
// Vue perm and RuoYi hook restoration are deferred to their panel init functions.
// Gather/Links state restoration is triggered on their first tab click.
function initStateRestoration() {
  Promise.all([import('./vk-gather.js'), import('./vk-links.js')]).then(function (mods) {
    var gather = mods[0];
    var links = mods[1];

    getActiveTab().then(function (tab) {
      var currentUrl = tab ? tab.url || '' : '';
      gather.restoreData(currentUrl);
      chrome.storage.local.get(['allLinks', 'allLinksUrl'], function (result) {
        if (result.allLinks && result.allLinksUrl === currentUrl) {
          links.setAllLinks(result.allLinks);
          links.renderLinks();
          utils.setStatus('links-count', '已恢复，共 ' + result.allLinks.length + ' 个链接');
        }
      });
    });
  });
}

function initStorageChecker() {
  import('./vk-storage-check.js').then(function (sc) {
    utils.bindTabSwitch('sc-stab', 'scstab', function (tab) {
      utils.switchSubTabs('sc-stab', 'scstab', 'scstab', tab);
    });

    sc.bindFilterSearch('local');
    sc.bindFilterSearch('session');
    sc.bindEventDelegation('local');
    sc.bindEventDelegation('session');

    utils.bindClick('sc-local-read-btn', async function () {
      utils.setStatus('sc-local-status', '正在读取 localStorage...');
      utils.get('sc-local-read-btn').disabled = true;
      try {
        var items = await sc.readWebStorage('local');
        sc.renderStorageResults('local');
        sc.renderStats('local', items);
        utils.setStatus('sc-local-status', '读取完成 — ' + items.length + ' 项');
        utils.get('sc-local-copy-btn').style.display = items.length > 0 ? '' : 'none';
        utils.get('sc-local-filter').style.display = items.length > 0 ? '' : 'none';
      } catch (err) {
        utils.setStatus('sc-local-status', '读取失败: ' + (err.message || '未知错误'));
      } finally {
        utils.get('sc-local-read-btn').disabled = false;
      }
    });

    utils.bindClick('sc-session-read-btn', async function () {
      utils.setStatus('sc-session-status', '正在读取 sessionStorage...');
      utils.get('sc-session-read-btn').disabled = true;
      try {
        var items = await sc.readWebStorage('session');
        sc.renderStorageResults('session');
        sc.renderStats('session', items);
        utils.setStatus('sc-session-status', '读取完成 — ' + items.length + ' 项');
        utils.get('sc-session-copy-btn').style.display = items.length > 0 ? '' : 'none';
        utils.get('sc-session-filter').style.display = items.length > 0 ? '' : 'none';
      } catch (err) {
        utils.setStatus('sc-session-status', '读取失败: ' + (err.message || '未知错误'));
      } finally {
        utils.get('sc-session-read-btn').disabled = false;
      }
    });

    utils.bindClick('sc-idb-read-btn', async function () {
      utils.setStatus('sc-idb-status', '正在读取 IndexedDB...');
      utils.get('sc-idb-read-btn').disabled = true;
      try {
        var info = await sc.readIndexedDB();
        sc.renderIDBResults();
        var dbCount = info.databases ? info.databases.length : 0;
        utils.setStatus(
          'sc-idb-status',
          info.error ? '读取失败: ' + info.error : '读取完成 — ' + dbCount + ' 个数据库'
        );
        utils.get('sc-idb-copy-btn').style.display = dbCount > 0 ? '' : 'none';
      } catch (err) {
        utils.setStatus('sc-idb-status', '读取失败: ' + (err.message || '未知错误'));
      } finally {
        utils.get('sc-idb-read-btn').disabled = false;
      }
    });

    utils.bindClick('sc-local-clear-btn', function () {
      sc.clearStorage('local');
    });
    utils.bindClick('sc-session-clear-btn', function () {
      sc.clearStorage('session');
    });
    utils.bindClick('sc-local-copy-btn', function () {
      sc.copyAllData('local');
    });
    utils.bindClick('sc-session-copy-btn', function () {
      sc.copyAllData('session');
    });
    utils.bindClick('sc-idb-copy-btn', sc.copyIDBData);
  });
}

export {
  initVuePermissions,
  initJsSearchAndTraverse,
  initSecurityDetectors,
  initNetworkTools,
  initSniff,
  initStorageChecker,
  initStateRestoration,
};
