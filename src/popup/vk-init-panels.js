// vk-init-panels.js - Panel initialization functions (ES module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

import * as encoding from './vk-encoding.js';
import * as jwt from './vk-jwt.js';
import * as crypto from './vk-crypto.js';
import * as favicon from './vk-favicon.js';
import * as asset from './vk-asset.js';
import * as multiurl from './vk-multiurl.js';
import * as tabSave from './vk-tabsave.js';
import * as gather from './vk-gather.js';
import * as haeRules from './vk-hae-rules.js';
import * as links from './vk-links.js';
import * as exif from './vk-exif.js';
import * as history from './vk-history.js';
import * as spoof from './vk-spoof.js';
import * as vue from './vk-vue.js';
import { ruoyiState, detectRuoYi, installRouteHook, removeRouteHook, checkHookStatus,
  analyzeJsRoutes, applyExtraRoutes, clearExtraRoutes, setAugmentMode,
  switchRuoYiSubTab, copyRouteJson, copyExtraPaths, toggleSelectAllRoutes,
  exportCurlCommands, exportHtmlReport, batchProbeRoutes, stopProbe, exportProbeResults,
  loadApiTraffic, clearApiTraffic, exportApiTraffic, filterApiTraffic,
  marScanDynamicRoutes, marInjectToRouter, marToggleSelectAll, marCopyHiddenPaths,
} from './vk-ruoyi.js';
import { switchJsCtrlTab, updateJsToggleStatus, disableJs, enableJs,
  scanAntiDebug, bypassAntiDebug, clearScriptBlock, removeCopyRestrictions,
  setJsBlocked,
} from './vk-jsctrl.js';
import { startXssIntercept, stopXssIntercept, renderXssPoints,
  handleXssHarvest, handleBatchOpenXss, handleVerifyReflection, handleCopyXssUrls,
  initXssScanPayloadSelect, clearResults as xssClearResults, exportData as xssExportData,
  setXssSearchText, analyzeDomSinks, xssFilterType, setXssFilterType,
} from './vk-xss.js';
import { XSS_DATA, LFI_DATA, WEBSHELL_DATA, CMDREF_DATA,
  renderPayloadCategories, switchPayloadTab, generateReverseShell,
  renderAllReverseShells, renderSqliPayloads, applySearch as payloadApplySearch,
} from './vk-payload.js';
import { scanWaf, copyResults as wafCopyResults, exportResults as wafExportResults,
  filterByStatus as wafFilterByStatus, searchResults as wafSearchResults,
} from './vk-waf.js';
import { auditCookies, copyResults as cookieAuditCopy, exportResults as cookieAuditExport,
  filterBySeverity as cookieFilterBySeverity, searchResults as cookieSearchResults,
} from './vk-cookie-audit.js';
import { detectReact, copyResults as reactCopyResults, exportResults as reactExportResults,
} from './vk-react.js';
import { detectAngular, copyResults as angularCopyResults, exportResults as angularExportResults,
} from './vk-angular.js';
import { scanCors, copyResults as corsCopyResults, exportJson as corsExportJson,
  filterBySeverity as corsFilterBySeverity, searchResults as corsSearchResults,
} from './vk-cors.js';
import { collectSubdomains, extractFromPage, bruteForceDns,
  copyResults as subdomainCopyResults, exportResults as subdomainExportResults,
  filterBySource as subdomainFilterBySource, searchResults as subdomainSearchResults,
} from './vk-subdomain.js';
import { loadToSources, copyResults as slCopyResults, clearResults as slClearResults,
} from './vk-source-loader.js';
import { smState, scanWebpackModules, copyAllSourcemapPaths, generateSourcemapTree,
  loadSourcesToDevTools, downloadAllSourcemapSources, backToSourcemapList,
  copyModuleSource, renderSourcemapModules, analyzeSourcemaps, downloadSingleModule,
  showApiEndpoints, exportModulesJSON, exportModulesCSV,
} from './vk-sourcemap.js';

const { getCurrentDomain, getActiveTab } = utils;

// ====== Shared pagination state ======
let tabBtns, tabsPerPage, totalPages, currentPage;
let scrollLeftBtn, scrollRightBtn;

function showTabPage(page) {
  currentPage = page;
  tabBtns.forEach((btn, i) => {
    if (i >= page * tabsPerPage && i < (page + 1) * tabsPerPage) {
      btn.classList.remove('hidden-tab');
    } else {
      btn.classList.add('hidden-tab');
    }
  });
  if (scrollLeftBtn) scrollLeftBtn.disabled = page === 0;
  if (scrollRightBtn) scrollRightBtn.disabled = page >= totalPages - 1;
  let pageIndicator = utils.get('tab-page-indicator');
  if (pageIndicator) pageIndicator.textContent = `${page + 1}/${totalPages}`;
}

function initTabPagination() {
  tabBtns = Array.from(document.querySelectorAll('.tab-btn:not(.toolbar-hidden)'));
  tabsPerPage = 8;
  const totalTabs = tabBtns.length;
  totalPages = Math.ceil(totalTabs / tabsPerPage);
  currentPage = 0;

  const pageIndicator = utils.get('tab-page-indicator');
  if (totalPages <= 1) {
    if (pageIndicator) pageIndicator.style.display = 'none';
  }

  scrollLeftBtn = utils.bindClick('tab-scroll-left', function () {
    if (currentPage > 0) showTabPage(currentPage - 1);
  });
  scrollRightBtn = utils.bindClick('tab-scroll-right', function () {
    if (currentPage < totalPages - 1) showTabPage(currentPage + 1);
  });
  showTabPage(0);
}

function initMainTabs() {
  const onTabClick = function onTabClick() {
    const panel = this.dataset.panel;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    this.classList.add('active');
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const target = utils.get(`panel-${panel}`);
    if (target) target.classList.add('active');
    utils.get('status-text').textContent = this.textContent;

    if (panel === 'history') {
      const historyDomainInput = utils.get('history-domain');
      if (historyDomainInput && !historyDomainInput.value.trim()) {
        getCurrentDomain().then(d => {
          if (d && !historyDomainInput.value.trim()) historyDomainInput.value = d;
        });
      }
    }

    if (panel === 'exif' && !onTabClick._exifLoaded) {
      onTabClick._exifLoaded = true;
      utils.loadLibs(['lib/exifr.full.js']).catch(function () {});
    }
  };
  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', onTabClick);
  });
}

function initEncodingJwtCrypto() {
  utils.bindTabSwitch('sub-tab-btn', 'type', encoding.switchEncodingTab);

  const encodingBindings = [
    { id: 'encode-btn', handler: encoding.handleEncode },
    { id: 'decode-btn', handler: encoding.handleDecode },
    { id: 'clear-encoding-btn', handler: encoding.clearEncodingFields },
    { id: 'copy-encoding-btn', handler: encoding.copyOutput },
    { id: 'encoding-swap-btn', handler: encoding.swapFields },
  ];
  encodingBindings.forEach(({ id, handler }) => utils.bindClick(id, handler));

  const jwtDecodeBtn = utils.get('jwt-decode-btn');
  if (jwtDecodeBtn)
    jwtDecodeBtn.addEventListener('click', function () {
      let input = (utils.get('jwt-input') || {}).value;
      input = utils.requireInput(input, '请输入 JWT Token');
      if (!input) return;
      jwt.decodeJwt(input);
    });
  utils.bindClick('jwt-clear-btn', jwt.clearJwt);
  utils.bindClick('jwt-copy-header-btn', jwt.copyJwtHeader);
  utils.bindClick('jwt-copy-payload-btn', jwt.copyJwtPayload);
  utils.bindClick('jwt-verify-btn', jwt.verifyJwtSignature);

  utils.bindTabSwitch('crypto-algo-btn', 'algo', crypto.switchCryptoAlgo);

  utils.bindClick('crypto-enc-btn', crypto.doCryptoEncrypt);
  utils.bindClick('crypto-dec-btn', crypto.doCryptoDecrypt);
  utils.bindClick('crypto-verify-btn', crypto.doCryptoVerify);
  utils.on('hash-hmac', 'change', crypto.toggleHashHmac);
  utils.bindClick('crypto-clear-btn', function () {
    const ci = utils.get('crypto-input');
    if (ci) ci.value = '';
    const co = utils.get('crypto-output');
    if (co) co.value = '';
  });
  utils.bindClick('copy-crypto-btn', function () {
    const v = (utils.get('crypto-output') || {}).value;
    if (v) utils.copyAndToast(v);
  });

  utils.on('aes-mode', 'change', () => crypto.toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode'));
  utils.on('des-mode', 'change', () => crypto.toggleIvVisibility('des', 'des-iv-group', 'des-mode'));
  utils.on('sm4-mode', 'change', function () {
    const ivG = utils.get('sm4-iv-group');
    if (ivG) {
      if (this.value === 'cbc') ivG.classList.remove('hidden');
      else ivG.classList.add('hidden');
    }
  });

  utils.bindClick('sm2-genkey-btn', function () {
    if (typeof window.sm2 === 'undefined') {
      utils.showToast('SM2 库加载中，请稍候...', 'info');
      return;
    }
    try {
      const kp = window.sm2.generateKeyPairHex();
      const pubEl = utils.get('sm2-pubkey');
      if (pubEl) pubEl.value = kp.publicKey;
      const priEl = utils.get('sm2-prikey');
      if (priEl) priEl.value = kp.privateKey;
      utils.showToast('密钥对已生成', 'success');
    } catch (e) {
      utils.showToast(`生成失败: ${e.message}`, 'error');
    }
  });

  crypto.toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
  crypto.toggleIvVisibility('des', 'des-iv-group', 'des-mode');
  crypto.switchCryptoAlgo('aes');

  const defaultEncoding = utils.getSetting('defaultEncoding', 'base64');
  if (defaultEncoding && encoding.ENCODING_NAMES[defaultEncoding]) {
    encoding.switchEncodingTab(defaultEncoding);
  }
  const defaultHash = utils.getSetting('defaultHash', 'SHA256');
  if (defaultHash) {
    const hashAlgoEl = utils.get('hash-algo');
    if (hashAlgoEl) hashAlgoEl.value = defaultHash;
  }
}

function initRsaFaviconAsset() {
  utils.bindClick('rsa-genkey-btn', crypto.rsaGenerateKeyPair);

  utils.bindClick('extract-favicon-btn', favicon.extractFavicon);
  utils.bindClick('copy-favicon-url-btn', favicon.copyFaviconUrl);
  utils.bindClick('copy-favicon-hash-btn', favicon.copyFaviconHash);

  utils.bindTabSwitch('source-btn', 'source', asset.switchAssetSource);
  chrome.storage.local.get(['pentest_ui_state'], function (r) {
    if (r.pentest_ui_state && r.pentest_ui_state['asset-source']) {
      asset.switchAssetSource(r.pentest_ui_state['asset-source']);
    }
  });

  utils.bindClick('asset-scan-btn', asset.handleAssetScan);
  utils.bindClick('asset-scan-all-btn', asset.scanAllEngines);
  utils.bindEnterKey('asset-query', function () {
    asset.handleAssetScan();
  });
  utils.bindClick('asset-custom-toggle', function () {
    asset.toggleCustomQueryMode(!this.classList.contains('active'));
  });
  utils.bindClick('asset-export-btn', asset.exportData);
  utils.bindPersist('asset-size');
  utils.bindPersist('ruoyi-probe-concurrency');
  utils.bindPersist('ruoyi-probe-method');
  utils.bindPersist('ruoyi-augment-mode');

  utils.on('asset-search', 'input', function () {
    asset.applySearchFilter(this.value.trim());
  });

  utils.bindClick('shodan-host-btn', asset.shodanHostLookup);
  utils.bindEnterKey('shodan-host-input', function () {
    asset.shodanHostLookup();
  });

  utils.bindClick('save-keys-btn', asset.saveApiKeys);
  utils.bindClick('clear-keys-btn', asset.clearApiKeys);

  asset.loadApiKeys();
}

function initGatherAndRules() {
  utils.bindClick('gather-btn', gather.gatherInfo);
  utils.on('gather-search', 'input', function () {
    gather.applySearchFilter(this.value.trim());
  });
  utils.bindClick('gather-copy-btn', gather.copyAllData);
  utils.bindClick('gather-export-btn', gather.exportAllData);

  utils.bindClick('gather-api-start-btn', gather.startApiTraffic);
  utils.bindClick('gather-api-stop-btn', gather.stopApiTraffic);

  const apiFilterMethod = utils.get('api-filter-method');
  const apiFilterStatus = utils.get('api-filter-status');
  if (apiFilterMethod) {
    apiFilterMethod.addEventListener('change', function () {
      gather.setApiFilter('method', this.value);
    });
  }
  if (apiFilterStatus) {
    apiFilterStatus.addEventListener('change', function () {
      gather.setApiFilter('status', this.value);
    });
  }

  const rulesBtn = utils.get('gather-rules-btn');
  const rulesModal = utils.get('rules-modal');
  const rulesModalClose = utils.get('rules-modal-close');
  const rulesImportBtn = utils.get('rules-import-btn');
  const rulesResetBtn = utils.get('rules-reset-btn');
  const rulesFileInput = utils.get('rules-file-input');

  function renderRulesList() {
    const container = utils.get('rules-list');
    if (!container) return;
    const rules = gather.getActiveRules();
    let html = '';
    rules.forEach(group => {
      html += '<div class="rules-group">';
      html += `<div class="rules-group-header">${utils.escapeHtml(group.group)}</div>`;
      (group.rules || []).forEach(rule => {
        const checked = rule.loaded ? ' checked' : '';
        const scopeLabel =
          ['response body', 'response', 'any'].indexOf(rule.scope) !== -1
            ? ''
            : ' <span class="rules-scope-na">[不适用]</span>';
        html += `<label class="rules-item">
          <input type="checkbox"${checked} data-group="${utils.escapeHtml(group.group)}" data-rule="${utils.escapeHtml(rule.name)}">
          <span class="rules-item-name type-${rule.color || 'gray'}">${utils.escapeHtml(rule.name)}</span>
          <span class="rules-item-scope">${utils.escapeHtml(rule.scope)}${scopeLabel}</span>
        </label>`;
      });
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', () => {
        const updated = haeRules.toggleRule(rules, cb.dataset.group, cb.dataset.rule);
        gather.updateRules(updated);
      });
    });
  }

  if (rulesBtn && rulesModal) {
    rulesBtn.addEventListener('click', () => {
      renderRulesList();
      rulesModal.style.display = 'flex';
    });
  }
  if (rulesModalClose && rulesModal) {
    const closeRulesModal = () => {
      rulesModal.style.display = 'none';
    };
    rulesModalClose.addEventListener('click', closeRulesModal);
    rulesModal.querySelector('.modal-overlay').addEventListener('click', closeRulesModal);
  }
  const applyRules = (rules, msg) => {
    gather.updateRules(rules);
    renderRulesList();
    utils.showToast(msg, 'success');
  };
  if (rulesImportBtn && rulesFileInput) {
    rulesImportBtn.addEventListener('click', () => {
      rulesFileInput.click();
    });
    rulesFileInput.addEventListener('change', () => {
      const file = rulesFileInput.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const imported = haeRules.importRules(reader.result);
        if (imported && imported.length > 0) {
          applyRules(
            imported,
            `已导入 ${imported.reduce((s, g) => s + (g.rules || []).length, 0)} 条规则`
          );
        } else {
          utils.showToast('规则文件解析失败', 'error');
        }
      };
      reader.readAsText(file);
      rulesFileInput.value = '';
    });
  }
  if (rulesResetBtn) {
    rulesResetBtn.addEventListener('click', () => {
      applyRules(haeRules.getDefaultRules(), '已恢复默认规则');
    });
  }
}

function initLinksHistoryMultiUrl() {
  utils.bindClick('links-extract-btn', links.extractLinks);
  utils.bindClick('links-copy-btn', links.copyFilteredUrls);
  utils.bindClick('links-export-btn', links.exportLinks);
  utils.bindClick('links-send-multiurl-btn', links.sendToMultiUrl);
  utils.on('links-filter', 'input', links.renderLinks);
  utils.on('links-filter-type', 'change', links.renderLinks);
  utils.bindPersist('links-filter-type');
  utils.bindPersist('history-match-type');
  utils.bindPersist('history-output-type');

  utils.on('multiurl-input', 'input', () => multiurl.updateMultiurlInfo(multiurl.parseUrls().length));
  utils.bindClick('multiurl-open-btn', multiurl.handleMultiurlOpen);
  utils.bindClick('multiurl-dedup-btn', multiurl.handleMultiurlDedup);
  utils.bindClick('multiurl-copy-btn', multiurl.copyAllUrls);
  utils.bindClick('multiurl-clear-btn', () => {
    utils.get('multiurl-input').value = '';
    multiurl.updateMultiurlInfo(0);
  });

  utils.bindClick('tabsave-grab-btn', tabSave.grabAllTabs);
  utils.bindClick('tabsave-copy-btn', tabSave.copySavedTabUrls);
  utils.bindClick('tabsave-export-btn', tabSave.exportSavedTabUrls);

  utils.bindClick('history-query-btn', history.queryHistory);

  utils.bindClick('history-copy-url-btn', async () => {
    let raw = utils.get('history-domain').value.trim();
    if (!raw) {
      const d = await getCurrentDomain();
      if (!d) {
        utils.showToast('请输入域名或打开一个网页', 'warning');
        return;
      }
      raw = d;
    }
    const domain = history.extractDomain(raw);
    utils.get('history-domain').value = domain;
    const cdxUrl = history.buildCdxUrl(domain);
    utils.copyAndToast(cdxUrl, '查询URL已复制');
  });

  utils.bindEnterKey('history-domain', history.queryHistory);
  utils.on('history-domain', 'blur', function () {
    const val = this.value.trim();
    if (val) history.showHistoryQuickLinks(val);
  });

  utils.bindClick('history-copy-result-btn', () => {
    if (history.lastHistoryResults.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    const text = history.lastHistoryResults.map(i => i.raw || i.url).join('\n');
    utils.copyAndToast(text, `已复制 ${history.lastHistoryResults.length} 条`);
  });
  utils.bindClick('history-export-btn', history.exportData);

  utils.on('history-type-filter', 'input', function () {
    if (history.allHistoryResults.length === 0) return;
    const filtered = history.filterByType(history.allHistoryResults, this.value);
    history.renderHistoryResults(filtered, true);
    utils.get('history-status').textContent =
      `筛选: ${filtered.length} / ${history.allHistoryResults.length} 条`;
  });

  utils.bindClick('history-copy-filtered-btn', () => {
    if (history.lastHistoryResults.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    const tfEl = utils.get('history-type-filter');
    const typeFilter = tfEl ? tfEl.value : '';
    const filtered = history.filterByType(history.lastHistoryResults, typeFilter);
    if (filtered.length === 0) {
      utils.showToast('没有匹配的结果', 'warning');
      return;
    }
    const text = filtered.map(i => i.raw || i.url).join('\n');
    utils.copyAndToast(text, `已复制 ${filtered.length} 条`);
  });

  utils.bindClick('history-send-links-btn', () => {
    if (history.lastHistoryResults.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    const urls = history.lastHistoryResults.map(i => i.url).filter(u => u && !u.startsWith('mailto:'));
    if (urls.length === 0) {
      utils.showToast('没有可用的URL', 'warning');
      return;
    }
    utils.get('multiurl-input').value = urls.join('\n');
    multiurl.updateMultiurlInfo(urls.length);
    document
      .querySelectorAll('.tab-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.panel === 'multiurl'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const multiurlPanel = utils.get('panel-multiurl');
    if (multiurlPanel) multiurlPanel.classList.add('active');
    utils.showToast(`已发送 ${urls.length} 个链接`, 'success');
  });
}

function initExifAndSpoofing() {
  exif.initExifDragDrop();
  exif.checkExifPending();

  utils.bindTabSwitch('exif-mode-btn', 'mode', exif.switchExifMode);

  const exifFetchHandler = function () {
    const urlEl = utils.get('exif-url-input');
    let url = urlEl ? urlEl.value.trim() : '';
    url = utils.requireInput(url, '请输入图片URL');
    if (!url) return;
    exif.fetchExifFromUrl(url);
  };
  utils.bindClick('exif-fetch-btn', exifFetchHandler);
  utils.bindEnterKey('exif-url-input', exifFetchHandler);

  utils.bindClick('exif-scan-page-btn', exif.scanPageImages);

  utils.bindClick('exif-copy-all-btn', () => {
    if (!exif.lastExifData) {
      utils.showToast('没有元数据', 'warning');
      return;
    }
    const text = Object.entries(exif.lastExifData)
      .map(([k, v]) => `${k}: ${v}`)
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

  const initialRemoveBtn = document.querySelector('.custom-header-remove');
  if (initialRemoveBtn)
    initialRemoveBtn.addEventListener('click', function () {
      this.closest('.custom-header-row').remove();
    });

  utils.on('referer-preset', 'change', function () {
    const v = this.value;
    const refererInput = utils.get('header-referer');
    if (!refererInput) return;
    if (v === 'none') refererInput.value = '';
    else if (v === 'google') refererInput.value = 'https://www.google.com/';
    else if (v === 'baidu') refererInput.value = 'https://www.baidu.com/';
    else if (v === 'same') refererInput.value = '';
  });

  chrome.storage.local.get(['pentest_spoof'], result => {
    const saved = result.pentest_spoof;
    if (saved) {
      if (saved.ua) Object.assign(spoof.spoofState.ua, saved.ua);
      if (saved.headers) Object.assign(spoof.spoofState.headers, saved.headers);
      spoof.updateUaStatus();
    }
  });
}

function initVuePermissions() {
  utils.bindClick('vue-detect-btn', vue.detectVue);
  utils.bindClick('vue-export-routes-btn', vue.exportVueRoutes);
  utils.bindClick('vue-bypass-guards-btn', vue.bypassVueGuards);
  utils.bindClick('vue-disable-auth-btn', vue.disableRouteAuth);
  utils.bindClick('vue-copy-btn', () => {
    if (!vue.vueState.lastVueResult) {
      utils.showToast('没有可复制的内容', 'warning');
      return;
    }
    utils.copyAndToast(vue.vueState.lastVueResult);
  });

  const vueResultsEl = utils.on('vue-results', 'click', function (e) {
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
    let val = utils.get('perm-json-editor').value;
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

  utils.bindClick('react-detect-btn', detectReact);
  utils.bindClick('react-copy-btn', reactCopyResults);
  utils.bindClick('react-export-btn', reactExportResults);

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

function initThemeAndPayload() {
  const themes = ['light', 'dark'];
  const savedTheme = localStorage.getItem('pentest-theme');
  if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
  utils.bindClick('settings-btn', () => {
    chrome.runtime.openOptionsPage();
  });

  utils.bindClick('theme-toggle', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = themes[(themes.indexOf(current) + 1) % themes.length];
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('pentest-theme', next);
  });

  utils.bindTabSwitch('payload-tab', 'ptab', switchPayloadTab);

  renderPayloadCategories('xss-categories', XSS_DATA, false);
  renderSqliPayloads();
  renderPayloadCategories('lfi-categories', LFI_DATA, false);
  renderPayloadCategories('webshell-categories', WEBSHELL_DATA, false);
  renderPayloadCategories('cmdref-categories', CMDREF_DATA, false);
  renderAllReverseShells();

  utils.on('payload-search', 'input', function () {
    payloadApplySearch(this.value.trim());
  });

  utils.bindClick('revshell-gen-btn', generateReverseShell);
  utils.bindClick('revshell-copy-btn', () => {
    const output = utils.get('revshell-output');
    if (output && output.value) {
      utils.copyAndToast(output.value, '已复制命令', 'success', 1000);
    }
  });
  utils.on('revshell-type', 'change', generateReverseShell);
  utils.bindPersist('revshell-type');
  utils.on('revshell-ip', 'input', generateReverseShell);
  utils.on('revshell-port', 'input', generateReverseShell);

  utils.bindClick('sqli-regen-btn', renderSqliPayloads);
  utils.on('sqli-columns', 'change', renderSqliPayloads);
  utils.on('sqli-table', 'input', renderSqliPayloads);
}

function initXssAndSourcemap() {
  initXssScanPayloadSelect();
  utils.bindPersist('xssscan-payload-select');
  utils.bindPersist('xssscan-encoding');
  utils.bindClick('xssscan-harvest-btn', handleXssHarvest);
  utils.bindClick('xssscan-start-intercept-btn', startXssIntercept);
  utils.bindClick('xssscan-stop-intercept-btn', stopXssIntercept);
  utils.bindClick('xssscan-clear-btn', function () {
    xssClearResults();
    utils.showToast('已清空', 'info');
  });
  document.querySelectorAll('.xssscan-filter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      setXssFilterType(btn.dataset.xfilter);
      document.querySelectorAll('.xssscan-filter-btn').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      renderXssPoints();
    });
  });
  utils.on('xssscan-search', 'input', function () {
    setXssSearchText(this.value);
  });
  utils.bindClick('xssscan-selectall-btn', function () {
    const checks = document.querySelectorAll('.xssscan-point-check');
    const allChecked = Array.from(checks).every(function (cb) {
      return cb.checked;
    });
    checks.forEach(function (cb) {
      cb.checked = !allChecked;
    });
  });
  utils.bindClick('xssscan-batchopen-btn', handleBatchOpenXss);
  utils.bindClick('xssscan-verify-btn', handleVerifyReflection);
  utils.bindClick('xssscan-copyall-btn', handleCopyXssUrls);
  utils.bindClick('xssscan-export-btn', xssExportData);
  utils.bindClick('xssscan-sink-btn', analyzeDomSinks);
  utils.bindClick('xssscan-sink-clear-btn', function () {
    utils.setEmpty('xssscan-sink-results', '暂无分析结果');
    const st = utils.get('xssscan-sink-status');
    if (st) {
      st.textContent = '点击「分析 DOM 汇点」扫描页面中的危险 Sink';
      st.style.color = '';
    }
  });

  utils.bindClick('sourcemap-scan-btn', scanWebpackModules);
  utils.bindClick('sourcemap-copy-all-btn', copyAllSourcemapPaths);
  utils.bindClick('sourcemap-copy-tree-btn', generateSourcemapTree);
  utils.bindClick('sourcemap-load-sources-btn', loadSourcesToDevTools);
  utils.bindClick('sourcemap-download-all-btn', downloadAllSourcemapSources);
  utils.bindClick('sourcemap-detail-back', backToSourcemapList);
  utils.bindClick('sourcemap-copy-src-btn', copyModuleSource);
  utils.bindClick('sourcemap-download-btn', function () {
    if (smState.sourcemapCurrentModule !== null) downloadSingleModule(smState.sourcemapCurrentModule);
  });
  let smSearchTimer = null;
  utils.on('sourcemap-search-input', 'input', function () {
    const val = this.value;
    clearTimeout(smSearchTimer);
    smSearchTimer = setTimeout(function () {
      smState.sourcemapSearchTerm = val.trim().toLowerCase();
      renderSourcemapModules();
    }, 200);
  });
  utils.bindClick('sourcemap-analyze-btn', analyzeSourcemaps);
  utils.bindClick('sm-analysis-close', function () {
    let card = utils.get('sm-analysis-card');
    if (card) card.classList.add('hidden');
  });

  utils.bindClick('sourcemap-api-btn', showApiEndpoints);
  utils.bindClick('sm-api-close', function () {
    const card = utils.get('sm-api-card');
    if (card) card.classList.add('hidden');
  });
  utils.bindClick('sourcemap-export-json-btn', exportModulesJSON);
  utils.bindClick('sourcemap-export-csv-btn', exportModulesCSV);
}

function initStatusBarAndKeyboard() {
  const statusTime = utils.get('status-time');
  if (statusTime) {
    const update = () => {
      const now = new Date();
      statusTime.textContent = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    };
    update();
    setInterval(update, 30000);
  }

  document.addEventListener('keydown', function (e) {
    if (!e.altKey) return;
    const num = parseInt(e.key, 10);
    if (num >= 1 && num <= tabsPerPage) {
      e.preventDefault();
      const idx = currentPage * tabsPerPage + (num - 1);
      if (idx < tabBtns.length) {
        tabBtns[idx].click();
      }
      return;
    }
    if (e.key === 'ArrowLeft' && currentPage > 0) {
      e.preventDefault();
      showTabPage(currentPage - 1);
    } else if (e.key === 'ArrowRight' && currentPage < totalPages - 1) {
      e.preventDefault();
      showTabPage(currentPage + 1);
    }
  });
}

export {
  initTabPagination,
  initMainTabs,
  initEncodingJwtCrypto,
  initRsaFaviconAsset,
  initGatherAndRules,
  initLinksHistoryMultiUrl,
  initExifAndSpoofing,
  initVuePermissions,
  initJsSearchAndTraverse,
  initSecurityDetectors,
  initNetworkTools,
  initStateRestoration,
  initThemeAndPayload,
  initXssAndSourcemap,
  initStatusBarAndKeyboard,
};
