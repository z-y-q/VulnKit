// vk-init-panel-tools.js - Tool panel inits (Links, Exif, Payload, XSS, Report)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const { getCurrentDomain } = utils;

function initLinksHistoryMultiUrl() {
  Promise.all([
    import('./vk-links.js'),
    import('./vk-multiurl.js'),
    import('./vk-tabsave.js'),
    import('./vk-history.js'),
  ]).then(function (mods) {
    var links = mods[0];
    var multiurl = mods[1];
    var tabSave = mods[2];
    var history = mods[3];

    utils.bindClick('links-extract-btn', links.extractLinks);
    utils.bindClick('links-copy-btn', links.copyFilteredUrls);
    utils.bindClick('links-export-btn', links.exportLinks);
    utils.bindClick('links-send-multiurl-btn', links.sendToMultiUrl);
    utils.on('links-filter', 'input', links.renderLinks);
    utils.on('links-filter-type', 'change', links.renderLinks);
    utils.bindPersist('links-filter-type');
    utils.bindPersist('history-match-type');
    utils.bindPersist('history-output-type');

    utils.on('multiurl-input', 'input', function () {
      multiurl.updateMultiurlInfo(multiurl.parseUrls().length);
    });
    utils.bindClick('multiurl-open-btn', multiurl.handleMultiurlOpen);
    utils.bindClick('multiurl-dedup-btn', multiurl.handleMultiurlDedup);
    utils.bindClick('multiurl-copy-btn', multiurl.copyAllUrls);
    utils.bindClick('multiurl-clear-btn', function () {
      var multiurlInput = utils.get('multiurl-input');
      if (multiurlInput) multiurlInput.value = '';
      multiurl.updateMultiurlInfo(0);
    });

    utils.bindClick('tabsave-grab-btn', tabSave.grabAllTabs);
    utils.bindClick('tabsave-copy-btn', tabSave.copySavedTabUrls);
    utils.bindClick('tabsave-export-btn', tabSave.exportSavedTabUrls);

    utils.bindClick('history-query-btn', history.queryHistory);

    utils.bindClick('history-copy-url-btn', async function () {
      var historyDomainInput = utils.get('history-domain');
      var raw = historyDomainInput ? historyDomainInput.value.trim() : '';
      if (!raw) {
        var d = await getCurrentDomain();
        if (!d) {
          utils.showToast('请输入域名或打开一个网页', 'warning');
          return;
        }
        raw = d;
      }
      var domain = history.extractDomain(raw);
      if (historyDomainInput) historyDomainInput.value = domain;
      var cdxUrl = history.buildCdxUrl(domain);
      utils.copyAndToast(cdxUrl, '查询URL已复制');
    });

    utils.bindEnterKey('history-domain', history.queryHistory);
    utils.on('history-domain', 'blur', function () {
      var val = this.value.trim();
      if (val) history.showHistoryQuickLinks(val);
    });

    utils.bindClick('history-copy-result-btn', function () {
      if (history.lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      var text = history.lastHistoryResults
        .map(function (i) {
          return i.raw || i.url;
        })
        .join('\n');
      utils.copyAndToast(text, '已复制 ' + history.lastHistoryResults.length + ' 条');
    });
    utils.bindClick('history-export-btn', history.exportData);
    utils.bindClick('history-send-fuzz-btn', history.sendWaybackToFuzz);

    utils.on('history-type-filter', 'input', function () {
      if (history.allHistoryResults.length === 0) return;
      var filtered = history.filterByType(history.allHistoryResults, this.value);
      history.renderHistoryResults(filtered, true);
      var historyStatus = utils.get('history-status');
      if (historyStatus)
        historyStatus.textContent =
          '筛选: ' + filtered.length + ' / ' + history.allHistoryResults.length + ' 条';
    });

    utils.bindClick('history-copy-filtered-btn', function () {
      if (history.lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      var tfEl = utils.get('history-type-filter');
      var typeFilter = tfEl ? tfEl.value : '';
      var filtered = history.filterByType(history.lastHistoryResults, typeFilter);
      if (filtered.length === 0) {
        utils.showToast('没有匹配的结果', 'warning');
        return;
      }
      var text = filtered
        .map(function (i) {
          return i.raw || i.url;
        })
        .join('\n');
      utils.copyAndToast(text, '已复制 ' + filtered.length + ' 条');
    });

    utils.bindClick('history-send-links-btn', function () {
      if (history.lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      var urls = history.lastHistoryResults
        .map(function (i) {
          return i.url;
        })
        .filter(function (u) {
          return u && !u.startsWith('mailto:');
        });
      if (urls.length === 0) {
        utils.showToast('没有可用的URL', 'warning');
        return;
      }
      var multiurlInput = utils.get('multiurl-input');
      if (multiurlInput) multiurlInput.value = urls.join('\n');
      multiurl.updateMultiurlInfo(urls.length);
      document.querySelectorAll('.tab-btn').forEach(function (b) {
        b.classList.toggle('active', b.dataset.panel === 'multiurl');
      });
      document.querySelectorAll('.panel').forEach(function (p) {
        p.classList.remove('active');
      });
      var multiurlPanel = utils.get('panel-multiurl');
      if (multiurlPanel) multiurlPanel.classList.add('active');
      utils.showToast('已发送 ' + urls.length + ' 个链接', 'success');
    });
  });
}

function initExifAndSpoofing() {
  Promise.all([import('./vk-exif.js'), import('./vk-spoof.js')]).then(function (mods) {
    var exif = mods[0];
    var spoof = mods[1];

    exif.initExifDragDrop();
    exif.checkExifPending();

    utils.bindTabSwitch('exif-mode-btn', 'mode', exif.switchExifMode);

    var exifFetchHandler = function () {
      var urlEl = utils.get('exif-url-input');
      var url = urlEl ? urlEl.value.trim() : '';
      url = utils.requireInput(url, '请输入图片URL');
      if (!url) return;
      exif.fetchExifFromUrl(url);
    };
    utils.bindClick('exif-fetch-btn', exifFetchHandler);
    utils.bindEnterKey('exif-url-input', exifFetchHandler);

    utils.bindClick('exif-scan-page-btn', exif.scanPageImages);

    utils.bindClick('exif-copy-all-btn', function () {
      if (!exif.lastExifData) {
        utils.showToast('没有元数据', 'warning');
        return;
      }
      var text = Object.entries(exif.lastExifData)
        .map(function (kv) {
          return kv[0] + ': ' + kv[1];
        })
        .join('\n');
      utils.copyAndToast(text, '已复制全部元数据');
    });
    utils.bindClick('exif-copy-json-btn', exif.copyExifData);
    utils.bindClick('exif-clear-btn', exif.clearExif);

    utils.bindTabSwitch('spoof-tab', 'spoof', spoof.switchSpoofTab);

    utils.on('ua-category', 'change', function () {
      spoof.renderUaList(this.value);
    });
    utils.bindPersist('ua-category');
    spoof.renderUaList('desktop');

    utils.bindClick('spoof-ua-apply', spoof.applyUserAgent);
    utils.bindClick('spoof-ua-reset', spoof.resetUserAgent);

    utils.bindClick('cookie-refresh-btn', spoof.loadCookies);
    utils.bindClick('cookie-add-btn', spoof.showCookieAddEditor);
    utils.bindClick('cookie-import-btn', spoof.showCookieFileImportDialog);
    utils.bindClick('cookie-export-btn', spoof.exportCookies);
    utils.bindClick('cookie-clear-btn', spoof.clearAllCookies);
    utils.on('cookie-search', 'input', function () {
      spoof.filterCookies(this.value);
    });

    utils.bindClick('header-apply', spoof.applyHeaders);
    utils.bindClick('header-reset', spoof.resetHeaders);
    utils.bindClick('custom-header-add', spoof.addCustomHeaderRow);

    var initialRemoveBtn = document.querySelector('.custom-header-remove');
    if (initialRemoveBtn)
      initialRemoveBtn.addEventListener('click', function () {
        this.closest('.custom-header-row').remove();
      });

    utils.on('referer-preset', 'change', function () {
      var v = this.value;
      var refererInput = utils.get('header-referer');
      if (!refererInput) return;
      if (v === 'none') refererInput.value = '';
      else if (v === 'google') refererInput.value = 'https://www.google.com/';
      else if (v === 'baidu') refererInput.value = 'https://www.baidu.com/';
      else if (v === 'same') refererInput.value = '';
    });

    chrome.storage.local.get(['pentest_spoof'], function (result) {
      var saved = result.pentest_spoof;
      if (saved) {
        if (saved.ua) Object.assign(spoof.spoofState.ua, saved.ua);
        if (saved.headers) Object.assign(spoof.spoofState.headers, saved.headers);
        spoof.updateUaStatus();
      }
    });
  });
}

function initPayload() {
  Promise.all([import('./vk-payload.js'), import('./vk-payload-remote.js')]).then(function (mods) {
    var payload = mods[0];
    var payloadRemote = mods[1];

    utils.bindTabSwitch('payload-tab', 'ptab', payload.switchPayloadTab);

    payload.renderPayloadCategories('xss-categories', payload.XSS_DATA, false);
    payload.renderSqliPayloads();
    payload.renderPayloadCategories('lfi-categories', payload.LFI_DATA, false);
    payload.renderPayloadCategories('webshell-categories', payload.WEBSHELL_DATA, false);
    payload.renderPayloadCategories('cmdref-categories', payload.CMDREF_DATA, false);
    payload.renderAllReverseShells();

    utils.on('payload-search', 'input', function () {
      payload.applySearch(this.value.trim());
    });

    utils.bindClick('revshell-gen-btn', payload.generateReverseShell);
    utils.bindClick('revshell-copy-btn', function () {
      var output = utils.get('revshell-output');
      if (output && output.value) {
        utils.copyAndToast(output.value, '已复制命令', 'success', 1000);
      }
    });
    utils.on('revshell-type', 'change', payload.generateReverseShell);
    utils.bindPersist('revshell-type');
    utils.on('revshell-ip', 'input', payload.generateReverseShell);
    utils.on('revshell-port', 'input', payload.generateReverseShell);

    utils.bindClick('sqli-regen-btn', payload.renderSqliPayloads);

    payload.initRemotePayloads();

    utils.bindClick('payload-remote-config-btn', function () {
      var config = utils.get('payload-remote-config');
      if (!config) return;
      config.classList.toggle('hidden');
      if (!config.classList.contains('hidden')) {
        var input = utils.get('payload-remote-url');
        if (input) {
          payloadRemote.getRemoteUrl(function (url) {
            input.value = url;
          });
        }
      }
    });

    utils.bindClick('payload-remote-save-btn', function () {
      var input = utils.get('payload-remote-url');
      if (!input) return;
      payloadRemote.setRemoteUrl(input.value.trim());
      utils.showToast('远程地址已保存', 'success');
      var config = utils.get('payload-remote-config');
      if (config) config.classList.add('hidden');
    });

    utils.bindClick('payload-remote-reset-btn', function () {
      payloadRemote.setRemoteUrl('');
      var input = utils.get('payload-remote-url');
      if (input) input.value = '';
      utils.showToast('已恢复默认', 'success');
    });

    utils.bindClick('payload-update-btn', async function () {
      var btn = this;
      var statusEl = utils.get('payload-remote-status');
      btn.disabled = true;
      btn.textContent = '更新中...';
      try {
        var stats = await payloadRemote.updatePayloads(function (msg) {
          if (statusEl) statusEl.textContent = msg;
        });
        if (!stats.ok) {
          if (statusEl) statusEl.textContent = '失败: ' + stats.error;
          utils.showToast('更新失败: ' + stats.error, 'error');
        } else {
          payload.initRemotePayloads();
          payload.refreshPayloadDisplay();
          if (statusEl) statusEl.textContent = '已更新至 v' + (stats.version || 'unknown');
          utils.showToast('Payload 已更新', 'success');
        }
      } catch (e) {
        if (statusEl) statusEl.textContent = '失败: ' + e.message;
        utils.showToast('更新失败', 'error');
      }
      btn.disabled = false;
      btn.textContent = '更新远程 Payload';
    });
    utils.on('sqli-columns', 'change', payload.renderSqliPayloads);
    utils.on('sqli-table', 'input', payload.renderSqliPayloads);
  });
}

function initXssAndSourcemap(bindFilterSearch) {
  Promise.all([import('./vk-xss.js'), import('./vk-sourcemap.js')]).then(function (mods) {
    var xss = mods[0];
    var sourcemap = mods[1];

    xss.initXssScanPayloadSelect();
    utils.bindPersist('xssscan-payload-select');
    utils.bindPersist('xssscan-encoding');
    utils.bindClick('xssscan-harvest-btn', xss.handleXssHarvest);
    utils.bindClick('xssscan-start-intercept-btn', xss.startXssIntercept);
    utils.bindClick('xssscan-stop-intercept-btn', xss.stopXssIntercept);
    utils.bindClick('xssscan-clear-btn', function () {
      xss.clearResults();
      utils.showToast('已清空', 'info');
    });
    bindFilterSearch('.xssscan-filter-btn', 'xssscan-search', xss, { filterAttr: 'data-xfilter' });
    utils.bindClick('xssscan-selectall-btn', function () {
      var checks = document.querySelectorAll('.xssscan-point-check');
      var allChecked = Array.from(checks).every(function (cb) {
        return cb.checked;
      });
      checks.forEach(function (cb) {
        cb.checked = !allChecked;
      });
    });
    utils.bindClick('xssscan-batchopen-btn', xss.handleBatchOpenXss);
    utils.bindClick('xssscan-verify-btn', xss.handleVerifyReflection);
    utils.bindClick('xssscan-open-reflected-btn', xss.handleOpenReflected);
    utils.bindClick('xssscan-copyall-btn', xss.handleCopyXssUrls);
    utils.bindClick('xssscan-copy-md-btn', xss.copyMarkdown);
    utils.bindClick('xssscan-export-btn', xss.xssExportData);
    utils.bindClick('xss-send-console-btn', xss.sendToConsole);
    utils.bindClick('xssscan-sink-btn', xss.analyzeDomSinks);
    utils.bindClick('xssscan-autofuzz-btn', xss.handleAutoFuzz);
    utils.bindClick('xssscan-autofuzz-stop-btn', xss.handleStopAutoFuzz);
    utils.bindClick('xssscan-autofuzz-export-btn', xss.handleAutoFuzzExport);
    utils.bindClick('xssscan-poc-btn', xss.handleGeneratePoc);
    utils.on('xssscan-sort', 'change', function () {
      xss.sortResults(this.value);
    });
    utils.bindClick('xssscan-sink-clear-btn', function () {
      utils.setEmpty('xssscan-sink-results', '暂无分析结果');
      var st = utils.get('xssscan-sink-status');
      if (st) {
        st.textContent = '点击「分析 DOM 汇点」扫描页面中的危险 Sink';
        st.style.color = '';
      }
    });

    utils.bindClick('sourcemap-scan-btn', sourcemap.scanWebpackModules);
    utils.bindClick('sourcemap-copy-all-btn', sourcemap.copyAllSourcemapPaths);
    utils.bindClick('sourcemap-copy-tree-btn', sourcemap.generateSourcemapTree);
    utils.bindClick('sourcemap-load-sources-btn', sourcemap.loadSourcesToDevTools);
    utils.bindClick('sourcemap-download-all-btn', sourcemap.downloadAllSourcemapSources);
    utils.bindClick('sourcemap-detail-back', sourcemap.backToSourcemapList);
    utils.bindClick('sourcemap-copy-src-btn', sourcemap.copyModuleSource);
    utils.bindClick('sourcemap-download-btn', function () {
      if (sourcemap.smState.sourcemapCurrentModule !== null)
        sourcemap.downloadSingleModule(sourcemap.smState.sourcemapCurrentModule);
    });
    var smSearchTimer = null;
    utils.on('sourcemap-search-input', 'input', function () {
      var val = this.value;
      clearTimeout(smSearchTimer);
      smSearchTimer = setTimeout(function () {
        sourcemap.smState.sourcemapSearchTerm = val.trim().toLowerCase();
        sourcemap.renderSourcemapModules();
      }, 200);
    });
    utils.bindClick('sourcemap-analyze-btn', sourcemap.analyzeSourcemaps);
    utils.bindClick('sm-analysis-close', function () {
      var card = utils.get('sm-analysis-card');
      if (card) card.classList.add('hidden');
    });

    utils.bindClick('sourcemap-api-btn', sourcemap.showApiEndpoints);
    utils.bindClick('sm-api-close', function () {
      var card = utils.get('sm-api-card');
      if (card) card.classList.add('hidden');
    });
    utils.bindClick('sourcemap-export-json-btn', sourcemap.exportModulesJSON);
    utils.bindClick('sourcemap-export-csv-btn', sourcemap.exportModulesCSV);
  });
}

function initReport() {
  Promise.all([import('./vk-report.js'), import('./vk-scan-history.js')]).then(function (mods) {
    var report = mods[0];
    var scanHistory = mods[1];
    scanHistory.renderHistoryContainer();

    utils.bindClick('report-collect-btn', report.handleCollectFindings);

    utils.bindClick('report-audit-btn', async function () {
      var btn = utils.get('report-audit-btn');
      if (btn) btn.disabled = true;
      var progressTextEl = utils.get('report-progress-text');
      if (progressTextEl) progressTextEl.style.display = '';
      try {
        await report.runFullAudit();
      } finally {
        if (btn) btn.disabled = false;
      }
    });

    utils.bindClick('report-export-html-btn', function () {
      var collected = report.getLastFindings();
      var findings = collected ? collected.findings : null;
      if (!findings || findings.length === 0) {
        utils.showToast('没有可导出的结果', 'warning');
        return;
      }
      report.exportHtml(findings);
    });

    utils.bindClick('report-export-md-btn', function () {
      var collected = report.getLastFindings();
      var findings = collected ? collected.findings : null;
      if (!findings || findings.length === 0) {
        utils.showToast('没有可导出的结果', 'warning');
        return;
      }
      report.exportMarkdown(findings);
    });

    utils.bindClick('report-export-json-btn', function () {
      var collected = report.getLastFindings();
      if (!collected || !collected.findings || collected.findings.length === 0) {
        utils.showToast('没有可导出的结果', 'warning');
        return;
      }
      report.exportJson(collected);
    });
  });
}

export {
  initLinksHistoryMultiUrl,
  initExifAndSpoofing,
  initPayload,
  initXssAndSourcemap,
  initReport,
};
