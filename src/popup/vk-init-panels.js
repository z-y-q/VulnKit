// vk-init-panels.js - Panel initialization functions (ES module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { TAB_TO_CATEGORY } from './vk-categories.js';

import * as encoding from './vk-encoding.js';
import * as jwt from './vk-jwt.js';
import * as crypto from './vk-crypto.js';
import * as favicon from './vk-favicon.js';
import * as asset from './vk-asset.js';
import * as multiurl from './vk-multiurl.js';
import * as tabSave from './vk-tabsave.js';
import * as gather from './vk-gather.js';
import * as haeRules from './vk-hae-rules.js';
import { setSourceUrls } from './vk-source-loader.js';
import * as links from './vk-links.js';
import * as exif from './vk-exif.js';
import * as history from './vk-history.js';
import * as spoof from './vk-spoof.js';
import {
  startXssIntercept,
  stopXssIntercept,
  renderXssPoints,
  handleXssHarvest,
  handleBatchOpenXss,
  handleVerifyReflection,
  handleOpenReflected,
  handleCopyXssUrls,
  initXssScanPayloadSelect,
  clearResults as xssClearResults,
  exportData as xssExportData,
  setXssSearchText,
  analyzeDomSinks,
  xssFilterType,
  setXssFilterType,
} from './vk-xss.js';
import {
  XSS_DATA,
  LFI_DATA,
  WEBSHELL_DATA,
  CMDREF_DATA,
  renderPayloadCategories,
  switchPayloadTab,
  generateReverseShell,
  renderAllReverseShells,
  renderSqliPayloads,
  applySearch as payloadApplySearch,
  refreshPayloadDisplay,
  initRemotePayloads,
} from './vk-payload.js';
import * as payloadRemote from './vk-payload-remote.js';
import {
  smState,
  scanWebpackModules,
  copyAllSourcemapPaths,
  generateSourcemapTree,
  loadSourcesToDevTools,
  downloadAllSourcemapSources,
  backToSourcemapList,
  copyModuleSource,
  renderSourcemapModules,
  analyzeSourcemaps,
  downloadSingleModule,
  showApiEndpoints,
  exportModulesJSON,
  exportModulesCSV,
} from './vk-sourcemap.js';
import * as headers from './vk-headers.js';
import * as redirect from './vk-redirect.js';
import * as fuzz from './vk-fuzz.js';

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
  var pageIndicator = utils.get('tab-page-indicator');
  if (pageIndicator) pageIndicator.textContent = totalPages <= 1 ? '' : page + 1 + '/' + totalPages;
}

function getVisibleTabBtns() {
  return Array.from(
    document.querySelectorAll('.tab-btn:not(.toolbar-hidden):not(.category-filtered)')
  );
}

function recalcPagination() {
  var visible = getVisibleTabBtns();
  tabBtns = visible;
  totalPages = Math.max(1, Math.ceil(visible.length / tabsPerPage));
  if (currentPage >= totalPages) currentPage = totalPages - 1;
  var pageIndicator = utils.get('tab-page-indicator');
  if (pageIndicator) pageIndicator.style.display = totalPages <= 1 ? 'none' : '';
}

function initTabPagination() {
  tabBtns = Array.from(document.querySelectorAll('.tab-btn:not(.toolbar-hidden)'));
  tabsPerPage = 8;
  totalPages = Math.max(1, Math.ceil(tabBtns.length / tabsPerPage));
  currentPage = 0;

  tabBtns.forEach(function (btn) {
    var cat = TAB_TO_CATEGORY[btn.dataset.panel];
    if (cat) btn.style.setProperty('--cat-color', cat.color);
  });

  var pageIndicator = utils.get('tab-page-indicator');
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

function initCategoryFilter() {
  var chips = document.querySelectorAll('.category-chip');
  if (chips.length === 0) return;

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (c) {
        c.classList.remove('active');
      });
      chip.classList.add('active');

      var category = chip.dataset.category;
      var allBtns = document.querySelectorAll('.tab-btn:not(.toolbar-hidden)');

      if (category === 'all') {
        allBtns.forEach(function (btn) {
          btn.classList.remove('category-filtered');
        });
      } else {
        var catConfig = TAB_TO_CATEGORY[Object.keys(TAB_TO_CATEGORY)[0]];
        allBtns.forEach(function (btn) {
          var tabCat = TAB_TO_CATEGORY[btn.dataset.panel];
          if (tabCat && tabCat.id === category) {
            btn.classList.remove('category-filtered');
          } else {
            btn.classList.add('category-filtered');
          }
        });
      }

      recalcPagination();
      showTabPage(0);

      var activeBtn = document.querySelector(
        '.tab-btn.active:not(.toolbar-hidden):not(.category-filtered)'
      );
      if (!activeBtn) {
        var firstVisible = document.querySelector(
          '.tab-btn:not(.toolbar-hidden):not(.category-filtered)'
        );
        if (firstVisible) firstVisible.click();
      }
    });
  });
}

function initMainTabs() {
  const onTabClick = function onTabClick() {
    const panel = this.dataset.panel;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    this.classList.add('active');
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const target = utils.get(`panel-${panel}`);
    if (target) target.classList.add('active');
    const statusText = utils.get('status-text');
    if (statusText) statusText.textContent = this.textContent;

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
      utils.loadLibs(['lib/exifr.full.js']).catch(function (e) {
        console.debug('exifr load failed', e);
      });
    }
  };
  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', onTabClick);
  });
}

function initEncodingJwtCrypto(savedState) {
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

  utils.on('aes-mode', 'change', () =>
    crypto.toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode')
  );
  utils.on('des-mode', 'change', () =>
    crypto.toggleIvVisibility('des', 'des-iv-group', 'des-mode')
  );
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
  const hasSavedSubtab = savedState && savedState['encoding-subtab'];
  if (!hasSavedSubtab && defaultEncoding && encoding.ENCODING_NAMES[defaultEncoding]) {
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
  gather.init();
  utils.bindClick('gather-btn', gather.gatherInfo);
  utils.on('gather-search', 'input', function () {
    gather.applySearchFilter(this.value.trim());
  });
  utils.bindClick('gather-copy-btn', gather.copyAllData);
  utils.bindClick('gather-copy-all-btn', gather.copyAllGroupsData);
  utils.bindClick('gather-export-btn', gather.exportAllData);
  utils.bindClick('gather-export-json-btn', gather.exportAllDataJson);
  utils.bindClick('gather-to-source-btn', function () {
    var urls = gather.getScriptUrls();
    if (urls.length === 0) {
      utils.showToast('没有收集到 JS/CSS 链接', 'warning');
      return;
    }
    setSourceUrls(urls);
    utils.showToast(`已发送 ${urls.length} 个链接到源码加载面板`, 'success');
  });

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
    const overlay = rulesModal.querySelector('.modal-overlay');
    if (overlay) overlay.addEventListener('click', closeRulesModal);
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

  utils.on('multiurl-input', 'input', () =>
    multiurl.updateMultiurlInfo(multiurl.parseUrls().length)
  );
  utils.bindClick('multiurl-open-btn', multiurl.handleMultiurlOpen);
  utils.bindClick('multiurl-dedup-btn', multiurl.handleMultiurlDedup);
  utils.bindClick('multiurl-copy-btn', multiurl.copyAllUrls);
  utils.bindClick('multiurl-clear-btn', () => {
    const multiurlInput = utils.get('multiurl-input');
    if (multiurlInput) multiurlInput.value = '';
    multiurl.updateMultiurlInfo(0);
  });

  utils.bindClick('tabsave-grab-btn', tabSave.grabAllTabs);
  utils.bindClick('tabsave-copy-btn', tabSave.copySavedTabUrls);
  utils.bindClick('tabsave-export-btn', tabSave.exportSavedTabUrls);

  utils.bindClick('history-query-btn', history.queryHistory);

  utils.bindClick('history-copy-url-btn', async () => {
    const historyDomainInput = utils.get('history-domain');
    let raw = historyDomainInput ? historyDomainInput.value.trim() : '';
    if (!raw) {
      const d = await getCurrentDomain();
      if (!d) {
        utils.showToast('请输入域名或打开一个网页', 'warning');
        return;
      }
      raw = d;
    }
    const domain = history.extractDomain(raw);
    if (historyDomainInput) historyDomainInput.value = domain;
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
    const historyStatus = utils.get('history-status');
    if (historyStatus)
      historyStatus.textContent = `筛选: ${filtered.length} / ${history.allHistoryResults.length} 条`;
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
    const urls = history.lastHistoryResults
      .map(i => i.url)
      .filter(u => u && !u.startsWith('mailto:'));
    if (urls.length === 0) {
      utils.showToast('没有可用的URL', 'warning');
      return;
    }
    const multiurlInput = utils.get('multiurl-input');
    if (multiurlInput) multiurlInput.value = urls.join('\n');
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

  initRemotePayloads();

  utils.bindClick('payload-remote-config-btn', function () {
    const config = utils.get('payload-remote-config');
    if (!config) return;
    config.classList.toggle('hidden');
    if (!config.classList.contains('hidden')) {
      const input = utils.get('payload-remote-url');
      if (input) {
        payloadRemote.getRemoteUrl(function (url) {
          input.value = url;
        });
      }
    }
  });

  utils.bindClick('payload-remote-save-btn', function () {
    const input = utils.get('payload-remote-url');
    if (!input) return;
    payloadRemote.setRemoteUrl(input.value.trim());
    utils.showToast('远程地址已保存', 'success');
    const config = utils.get('payload-remote-config');
    if (config) config.classList.add('hidden');
  });

  utils.bindClick('payload-remote-reset-btn', function () {
    payloadRemote.setRemoteUrl('');
    const input = utils.get('payload-remote-url');
    if (input) input.value = '';
    utils.showToast('已恢复默认', 'success');
  });

  utils.bindClick('payload-update-btn', async function () {
    const btn = this;
    const statusEl = utils.get('payload-remote-status');
    btn.disabled = true;
    btn.textContent = '更新中...';
    try {
      const stats = await payloadRemote.updatePayloads(function (msg) {
        if (statusEl) statusEl.textContent = msg;
      });
      if (!stats.ok) {
        if (statusEl) statusEl.textContent = '失败: ' + stats.error;
        utils.showToast('更新失败: ' + stats.error, 'error');
      } else {
        initRemotePayloads();
        refreshPayloadDisplay();
        const keys = Object.keys(stats).filter(function (k) {
          return k !== 'version' && k !== 'ok';
        });
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
  utils.bindClick('xssscan-open-reflected-btn', handleOpenReflected);
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
    if (smState.sourcemapCurrentModule !== null)
      downloadSingleModule(smState.sourcemapCurrentModule);
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

import {
  handleCollectFindings,
  runFullAudit,
  getLastFindings,
  exportHtml,
  exportMarkdown,
} from './vk-report.js';

function initReport() {
  utils.bindClick('report-collect-btn', handleCollectFindings);

  utils.bindClick('report-audit-btn', async function () {
    var btn = utils.get('report-audit-btn');
    if (btn) btn.disabled = true;
    var progressTextEl = utils.get('report-progress-text');
    if (progressTextEl) progressTextEl.style.display = '';
    try {
      await runFullAudit();
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  utils.bindClick('report-export-html-btn', function () {
    var findings = getLastFindings();
    if (!findings || findings.length === 0) {
      utils.showToast('没有可导出的结果', 'warning');
      return;
    }
    exportHtml(findings);
  });

  utils.bindClick('report-export-md-btn', function () {
    var findings = getLastFindings();
    if (!findings || findings.length === 0) {
      utils.showToast('没有可导出的结果', 'warning');
      return;
    }
    exportMarkdown(findings);
  });
}

// ====== Security Detectors 2: Headers + Redirect + Fuzz ======

function initSecurityDetectors2() {
  // --- Security Headers ---
  (function () {
    var urlInput = utils.get('headers-url');
    if (urlInput) {
      getActiveTab().then(function (tab) {
        if (tab && tab.url) urlInput.value = tab.url;
      });
    }

    utils.bindClick('headers-scan-btn', async function () {
      var url = (urlInput && urlInput.value) || '';
      if (!url || !/^https?:\/\//i.test(url)) {
        utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
        return;
      }
      var btn = utils.get('headers-scan-btn');
      if (btn) btn.disabled = true;
      try {
        var result = await headers.scanSecurityHeaders(url);
        if (result) headers.renderHeadersResults(result);
      } finally {
        if (btn) btn.disabled = false;
      }
    });

    utils.bindClick('headers-export-btn', function () {
      headers.exportHeadersResults();
    });
  })();

  // --- Open Redirect ---
  (function () {
    var urlInput = utils.get('redirect-url');
    if (urlInput) {
      getActiveTab().then(function (tab) {
        if (tab && tab.url) urlInput.value = tab.url;
      });
    }

    utils.bindClick('redirect-scan-btn', async function () {
      var url = (urlInput && urlInput.value) || '';
      if (!url || !/^https?:\/\//i.test(url)) {
        utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
        return;
      }
      var scanBtn = utils.get('redirect-scan-btn');
      var stopBtn = utils.get('redirect-stop-btn');
      var progressEl = utils.get('redirect-progress');
      var progressFill = utils.get('redirect-progress-fill');
      var progressText = utils.get('redirect-progress-text');
      if (scanBtn) scanBtn.style.display = 'none';
      if (stopBtn) stopBtn.style.display = '';
      if (progressEl) progressEl.style.display = 'flex';

      try {
        var result = await redirect.scanRedirects(url, function (p) {
          if (progressFill) progressFill.style.width = (p.completed / p.total) * 100 + '%';
          if (progressText) progressText.textContent = p.completed + '/' + p.total;
        });
        if (result) redirect.renderRedirectResults(result);
      } finally {
        if (scanBtn) scanBtn.style.display = '';
        if (stopBtn) stopBtn.style.display = 'none';
      }
    });

    utils.bindClick('redirect-stop-btn', function () {
      redirect.stopRedirectScan();
    });

    utils.bindClick('redirect-export-btn', function () {
      redirect.exportRedirectResults();
    });
  })();

  // --- Directory Fuzzing ---
  (function () {
    var urlInput = utils.get('fuzz-url');
    if (urlInput) {
      getActiveTab().then(function (tab) {
        if (tab && tab.url) urlInput.value = tab.url.replace(/\/+$/, '');
      });
    }

    utils.bindClick('fuzz-start-btn', async function () {
      var url = (urlInput && urlInput.value) || '';
      if (!url || !/^https?:\/\//i.test(url)) {
        utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
        return;
      }
      var wordlist = (utils.get('fuzz-wordlist') || {}).value || 'common';
      var concurrency = parseInt((utils.get('fuzz-concurrency') || {}).value || '5', 10);
      var startBtn = utils.get('fuzz-start-btn');
      var pauseBtn = utils.get('fuzz-pause-btn');
      var stopBtn = utils.get('fuzz-stop-btn');
      var progressEl = utils.get('fuzz-progress');
      var progressFill = utils.get('fuzz-progress-fill');
      var progressText = utils.get('fuzz-progress-text');
      if (startBtn) startBtn.style.display = 'none';
      if (pauseBtn) pauseBtn.style.display = '';
      if (stopBtn) stopBtn.style.display = '';
      if (progressEl) progressEl.style.display = 'flex';

      try {
        var result = await fuzz.runFuzzScan(
          url,
          wordlist,
          concurrency,
          function (s) {
            if (progressFill) progressFill.style.width = (s.completed / s.total) * 100 + '%';
            if (progressText)
              progressText.textContent = s.completed + '/' + s.total + ' (发现 ' + s.found + ')';
          },
          function (entry) {
            var container = utils.get('fuzz-results');
            if (container && container.querySelector('.empty-state')) {
              container.innerHTML = '';
            }
          }
        );
        if (result) fuzz.renderFuzzResults(result);
      } finally {
        if (startBtn) startBtn.style.display = '';
        if (pauseBtn) {
          pauseBtn.style.display = 'none';
          pauseBtn.textContent = '暂停';
        }
        if (stopBtn) stopBtn.style.display = 'none';
      }
    });

    utils.bindClick('fuzz-pause-btn', function () {
      var paused = fuzz.pauseFuzzScan();
      var pauseBtn = utils.get('fuzz-pause-btn');
      if (pauseBtn) pauseBtn.textContent = paused ? '继续' : '暂停';
    });

    utils.bindClick('fuzz-stop-btn', function () {
      fuzz.stopFuzzScan();
    });

    utils.bindClick('fuzz-export-btn', function () {
      fuzz.exportFuzzResults();
    });
  })();
}

export {
  initTabPagination,
  initMainTabs,
  initCategoryFilter,
  initEncodingJwtCrypto,
  initRsaFaviconAsset,
  initGatherAndRules,
  initLinksHistoryMultiUrl,
  initExifAndSpoofing,
  initThemeAndPayload,
  initXssAndSourcemap,
  initStatusBarAndKeyboard,
  initReport,
  initSecurityDetectors2,
};
