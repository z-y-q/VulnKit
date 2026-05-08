// 灵眸 Init
(function () {
  'use strict';

  const utils = window.VulnKitUtils.utilsProxy;

  // ====== Encoding Tools (loaded from vk-encoding.js) ======
  const encoding = window.VulnKitEncoding;
  const ENCODING_NAMES = encoding.ENCODING_NAMES;
  const handleEncode = encoding.handleEncode;
  const handleDecode = encoding.handleDecode;
  const clearEncodingFields = encoding.clearEncodingFields;
  const switchEncodingTab = encoding.switchEncodingTab;
  const copyEncodingOutput = encoding.copyOutput;
  const swapEncodingFields = encoding.swapFields;

  // ====== JWT (loaded from vk-jwt.js) ======
  const jwt = window.VulnKitJwt;
  const decodeJwt = jwt.decodeJwt;
  const clearJwt = jwt.clearJwt;
  const copyJwtHeader = jwt.copyJwtHeader;
  const copyJwtPayload = jwt.copyJwtPayload;
  const verifyJwtSignature = jwt.verifyJwtSignature;

  // ====== Crypto (AES/DES/RC4/SM2/SM4/Bcrypt) ======

  // ====== Crypto (loaded from vk-crypto.js) ======
  const crypto = window.VulnKitCrypto;
  const {
    switchCryptoAlgo,
    toggleIvVisibility,
    doCryptoEncrypt,
    doCryptoDecrypt,
    doCryptoVerify,
    computeHash,
    toggleHashHmac,
    rsaGenerateKeyPair,
  } = crypto;

  function exposeGlobal(name, obj, prop) {
    Object.defineProperty(window, name, {
      get() {
        return obj[prop];
      },
      set(v) {
        obj[prop] = v;
      },
      configurable: true,
    });
  }

  exposeGlobal('currentCryptoAlgo', crypto, 'currentCryptoAlgo');

  // ====== Favicon (loaded from vk-favicon.js) ======
  const { extractFavicon, copyFaviconUrl } = window.VulnKitFavicon;

  // ====== Asset Mapping (loaded from vk-asset.js) ======
  const {
    handleAssetScan,
    scanAllEngines,
    switchAssetSource,
    toggleCustomQueryMode,
    shodanHostLookup,
    saveApiKeys,
    loadApiKeys,
    clearApiKeys,
    exportData: assetExportData,
    applySearchFilter: assetApplySearchFilter,
  } = window.VulnKitAsset;
  exposeGlobal('currentAssetSource', window.VulnKitAsset, 'currentAssetSource');
  const getCurrentDomain = utils.getCurrentDomain;
  const getActiveTab = utils.getActiveTab;

  // ====== URL Multi-Open (loaded from vk-multiurl.js) ======
  const { parseUrls, updateMultiurlInfo, handleMultiurlOpen, handleMultiurlDedup, copyAllUrls } =
    window.VulnKitMultiUrl;

  // ====== Tab Save (loaded from vk-tabsave.js) ======
  const tabSave = window.VulnKitTabSave;
  const { grabAllTabs, copySavedTabUrls, exportSavedTabUrls } = tabSave;

  // ====== Info Gather (loaded from vk-gather.js) ======
  const gather = window.VulnKitGather;
  const haeRules = window.VulnKitHaeRules;
  const gatherInfo = gather.gatherInfo.bind(gather);
  const gatherStartApiTraffic = gather.startApiTraffic.bind(gather);
  const gatherStopApiTraffic = gather.stopApiTraffic.bind(gather);
  gather.init();

  // ====== Link Extract (loaded from vk-links.js) ======
  const { extractLinks, renderLinks, copyFilteredUrls, exportLinks, sendToMultiUrl } =
    window.VulnKitLinks;
  exposeGlobal('allLinks', window.VulnKitLinks, 'allLinks');

  // ====== EXIF Viewer (loaded from vk-exif.js) ======
  const {
    initExifDragDrop,
    switchExifMode,
    fetchExifFromUrl,
    scanPageImages,
    checkExifPending,
    copyExifData,
    clearExif,
  } = window.VulnKitExif;
  exposeGlobal('lastExifData', window.VulnKitExif, 'lastExifData');

  // ====== History Archive (loaded from vk-history.js) ======
  const {
    showHistoryQuickLinks,
    buildCdxUrl,
    filterByType,
    extractDomain,
    queryHistory,
    renderHistoryResults,
    exportData: historyExportData,
  } = window.VulnKitHistory;
  exposeGlobal('lastHistoryResults', window.VulnKitHistory, 'lastHistoryResults');
  exposeGlobal('allHistoryResults', window.VulnKitHistory, 'allHistoryResults');

  // ====== Request Spoofing (loaded from vk-spoof.js) ======
  const {
    switchSpoofTab,
    renderUaList,
    updateUaStatus,
    applyUserAgent,
    resetUserAgent,
    loadCookies,
    showCookieAddEditor,
    showCookieImportDialog,
    showCookieFileImportDialog,
    exportCookies,
    clearAllCookies,
    filterCookies,
    applyHeaders,
    addCustomHeaderRow,
    resetHeaders,
  } = window.VulnKitSpoof;
  const spoofState = window.VulnKitSpoof.spoofState;
  exposeGlobal('currentSpoofTab', window.VulnKitSpoof, 'currentSpoofTab');

  // ====== Vue Analysis (loaded from vk-vue.js) ======
  const vue = window.VulnKitVue;
  const {
    detectVue,
    exportVueRoutes,
    bypassVueGuards,
    disableRouteAuth,
    collectAllPaths: collectAllPathsFromVue,
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
  } = vue;

  exposeGlobal('lastVueResult', vue, 'lastVueResult');
  exposeGlobal('permInterceptActive', vue, 'permInterceptActive');
  exposeGlobal('permCapturedData', vue, 'permCapturedData');
  exposeGlobal('permSelectedIndex', vue, 'permSelectedIndex');
  exposeGlobal('permViewMode', vue, 'permViewMode');

  // ====== RuoYi Route (loaded from vk-ruoyi.js) ======
  const ruoyi = window.VulnKitRuoYi;
  const {
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
    toggleSelectAll,
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
  } = ruoyi;

  exposeGlobal('ruoyiHookActive', ruoyi, 'ruoyiHookActive');
  exposeGlobal('ruoyiTabId', ruoyi, 'ruoyiTabId');

  // ====== JS Control (loaded from vk-jsctrl.js) ======
  const jsCtrl = window.VulnKitJsCtrl;
  const {
    switchJsCtrlTab,
    updateJsToggleStatus,
    updateAntidebugIndicator,
    disableJs,
    enableJs,
    scanAntiDebug,
    bypassAntiDebug,
    clearScriptBlock,
    removeCopyRestrictions,
    updateUncopyIndicator,
  } = jsCtrl;

  exposeGlobal('jsBlocked', jsCtrl, 'jsBlocked');

  // ====== XSS Scan (loaded from vk-xss.js) ======
  const {
    startXssIntercept,
    stopXssIntercept,
    updateXssInterceptStatus,
    renderXssPoints,
    handleXssHarvest,
    handleBatchOpenXss,
    handleVerifyReflection,
    handleCopyXssUrls,
    initXssScanPayloadSelect,
    clearResults: xssClearResults,
    exportData: xssExportData,
    setXssSearchText,
    analyzeDomSinks,
  } = window.VulnKitXss;
  exposeGlobal('xssPoints', window.VulnKitXss, 'xssPoints');
  exposeGlobal('xssFilterType', window.VulnKitXss, 'xssFilterType');

  // ====== Payload Tools (loaded from vk-payload.js) ======
  const XSS_DATA = window.VulnKitPayload.XSS_DATA;
  const {
    LFI_DATA,
    WEBSHELL_DATA,
    CMDREF_DATA,
    REVERSE_SHELLS,
    renderPayloadCategories,
    switchPayloadTab,
    generateReverseShell,
    renderAllReverseShells,
    renderSqliPayloads,
    applySearch: payloadApplySearch,
  } = window.VulnKitPayload;

  // ====== WAF Fingerprint (loaded from vk-waf.js) ======
  const waf = window.VulnKitWaf;
  const {
    scanWaf,
    copyResults: wafCopyResults,
    exportResults: wafExportResults,
    filterByStatus: wafFilterByStatus,
    searchResults: wafSearchResults,
  } = waf;

  // ====== Cookie Security Audit (loaded from vk-cookie-audit.js) ======
  const cookieAudit = window.VulnKitCookieAudit;
  const {
    auditCookies,
    copyResults: cookieAuditCopy,
    exportResults: cookieAuditExport,
    filterBySeverity: cookieFilterBySeverity,
    searchResults: cookieSearchResults,
  } = cookieAudit;

  // ====== React Detection (loaded from vk-react.js) ======
  const reactDetect = window.VulnKitReact;
  const {
    detectReact,
    copyResults: reactCopyResults,
    exportResults: reactExportResults,
  } = reactDetect;

  // ====== Angular Detection (loaded from vk-angular.js) ======
  const angularDetect = window.VulnKitAngular;
  const {
    detectAngular,
    copyResults: angularCopyResults,
    exportResults: angularExportResults,
  } = angularDetect;

  // ====== CORS Detection (loaded from vk-cors.js) ======
  const corsDetect = window.VulnKitCors;
  const {
    scanCors,
    copyResults: corsCopyResults,
    exportJson: corsExportJson,
    filterBySeverity: corsFilterBySeverity,
    searchResults: corsSearchResults,
  } = corsDetect;

  // ====== Subdomain Collection (loaded from vk-subdomain.js) ======
  const subdomain = window.VulnKitSubdomain;
  const {
    collectSubdomains,
    extractFromPage,
    bruteForceDns,
    copyResults: subdomainCopyResults,
    exportResults: subdomainExportResults,
    filterBySource: subdomainFilterBySource,
    searchResults: subdomainSearchResults,
  } = subdomain;

  // ====== Source Loader (loaded from vk-source-loader.js) ======
  const {
    loadToSources,
    copyResults: slCopyResults,
    clearResults: slClearResults,
  } = window.VulnKitSourceLoader;

  // ====== Webpack Module Mapping (Source Map Scan v2) ======
  // Loaded from vk-sourcemap.js
  const sourcemap = window.VulnKitSourcemap;
  const {
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
  } = sourcemap;

  exposeGlobal('sourcemapSearchTerm', sourcemap, 'sourcemapSearchTerm');
  exposeGlobal('sourcemapCurrentModule', sourcemap, 'sourcemapCurrentModule');

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
    if (pageIndicator) pageIndicator.textContent = page + 1 + '/' + totalPages;
  }

  // ====== Panel init functions ======

  function initContextMenu() {
    chrome.storage.local.get(['contextSelection', 'contextAction'], function (data) {
      if (data.contextSelection) {
        var inputEl = utils.get('encoding-input');
        if (inputEl) inputEl.value = data.contextSelection;
        if (data.contextAction === 'decode') {
          setTimeout(function () {
            handleDecode();
          }, 100);
        } else if (data.contextAction === 'encode') {
          setTimeout(function () {
            handleEncode();
          }, 100);
        }
        chrome.storage.local.remove(['contextSelection', 'contextAction']);
        chrome.action.setBadgeText({ text: '' });
      }
    });
  }

  function initSettings(savedState) {
    if (savedState && savedState['encoding-subtab']) {
      switchEncodingTab(savedState['encoding-subtab']);
    }
    if (savedState && savedState['asset-source']) {
      switchAssetSource(savedState['asset-source']);
    }

    var toolbarConfig = utils.getSetting('toolbarConfig', null);
    var tabGrid = utils.get('tab-grid');
    if (toolbarConfig && Array.isArray(toolbarConfig) && tabGrid) {
      var allBtns = Array.from(tabGrid.querySelectorAll('.tab-btn'));
      var btnMap = {};
      allBtns.forEach(function (btn) {
        btnMap[btn.dataset.panel] = btn;
      });
      toolbarConfig.forEach(function (cfg) {
        var btn = btnMap[cfg.id];
        if (!btn) return;
        if (cfg.visible === false) {
          btn.classList.add('toolbar-hidden');
        } else {
          btn.classList.remove('toolbar-hidden');
          tabGrid.appendChild(btn);
        }
      });
      var activeTab = tabGrid.querySelector('.tab-btn.active');
      if (activeTab && activeTab.classList.contains('toolbar-hidden')) {
        var firstVisible = tabGrid.querySelector('.tab-btn:not(.toolbar-hidden)');
        if (firstVisible) firstVisible.click();
      }
    }
  }

  function initTabPagination() {
    tabBtns = Array.from(document.querySelectorAll('.tab-btn:not(.toolbar-hidden)'));
    tabsPerPage = 8;
    var totalTabs = tabBtns.length;
    totalPages = Math.ceil(totalTabs / tabsPerPage);
    currentPage = 0;

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

  function initMainTabs() {
    var onTabClick = function onTabClick() {
      const panel = this.dataset.panel;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      const target = utils.get('panel-' + panel);
      if (target) target.classList.add('active');
      utils.get('status-text').textContent = this.textContent;

      if (panel === 'history') {
        var historyDomainInput = utils.get('history-domain');
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
    utils.bindTabSwitch('sub-tab-btn', 'type', switchEncodingTab);

    const encodingBindings = [
      { id: 'encode-btn', handler: handleEncode },
      { id: 'decode-btn', handler: handleDecode },
      { id: 'clear-encoding-btn', handler: clearEncodingFields },
      { id: 'copy-encoding-btn', handler: copyEncodingOutput },
      { id: 'encoding-swap-btn', handler: swapEncodingFields },
    ];
    encodingBindings.forEach(({ id, handler }) => utils.bindClick(id, handler));

    var jwtDecodeBtn = utils.get('jwt-decode-btn');
    if (jwtDecodeBtn)
      jwtDecodeBtn.addEventListener('click', function () {
        var input = (utils.get('jwt-input') || {}).value;
        input = utils.requireInput(input, '请输入 JWT Token');
        if (!input) return;
        decodeJwt(input);
      });
    utils.bindClick('jwt-clear-btn', clearJwt);
    utils.bindClick('jwt-copy-header-btn', copyJwtHeader);
    utils.bindClick('jwt-copy-payload-btn', copyJwtPayload);
    utils.bindClick('jwt-verify-btn', verifyJwtSignature);

    utils.bindTabSwitch('crypto-algo-btn', 'algo', switchCryptoAlgo);

    utils.bindClick('crypto-enc-btn', doCryptoEncrypt);
    utils.bindClick('crypto-dec-btn', doCryptoDecrypt);
    utils.bindClick('crypto-verify-btn', doCryptoVerify);
    utils.on('hash-hmac', 'change', toggleHashHmac);
    utils.bindClick('crypto-clear-btn', function () {
      var ci = utils.get('crypto-input');
      if (ci) ci.value = '';
      var co = utils.get('crypto-output');
      if (co) co.value = '';
    });
    utils.bindClick('copy-crypto-btn', function () {
      var v = (utils.get('crypto-output') || {}).value;
      if (v) utils.copyAndToast(v);
    });

    utils.on('aes-mode', 'change', () => toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode'));
    utils.on('des-mode', 'change', () => toggleIvVisibility('des', 'des-iv-group', 'des-mode'));
    utils.on('sm4-mode', 'change', function () {
      var ivG = utils.get('sm4-iv-group');
      if (ivG) {
        if (this.value === 'cbc') ivG.classList.remove('hidden');
        else ivG.classList.add('hidden');
      }
    });

    utils.bindClick('sm2-genkey-btn', function () {
      if (typeof sm2 === 'undefined') {
        utils.showToast('SM2 库加载中，请稍候...', 'info');
        return;
      }
      try {
        var kp = sm2.generateKeyPairHex();
        var pubEl = utils.get('sm2-pubkey');
        if (pubEl) pubEl.value = kp.publicKey;
        var priEl = utils.get('sm2-prikey');
        if (priEl) priEl.value = kp.privateKey;
        utils.showToast('密钥对已生成', 'success');
      } catch (e) {
        utils.showToast('生成失败: ' + e.message, 'error');
      }
    });

    toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
    toggleIvVisibility('des', 'des-iv-group', 'des-mode');
    switchCryptoAlgo('aes');

    var defaultEncoding = utils.getSetting('defaultEncoding', 'base64');
    if (defaultEncoding && ENCODING_NAMES[defaultEncoding]) {
      switchEncodingTab(defaultEncoding);
    }
    var defaultHash = utils.getSetting('defaultHash', 'SHA256');
    if (defaultHash) {
      var hashAlgoEl = utils.get('hash-algo');
      if (hashAlgoEl) hashAlgoEl.value = defaultHash;
    }
  }

  function initRsaFaviconAsset() {
    utils.bindClick('rsa-genkey-btn', rsaGenerateKeyPair);

    utils.bindClick('extract-favicon-btn', extractFavicon);
    utils.bindClick('copy-favicon-url-btn', copyFaviconUrl);

    utils.bindClick('copy-favicon-hash-btn', () => {
      const hash = utils.get('favicon-hash').textContent;
      if (hash === '-') {
        utils.showToast('请先提取图标', 'warning');
        return;
      }
      utils.copyAndToast(hash, '已复制 Hash');
    });

    utils.bindTabSwitch('source-btn', 'source', switchAssetSource);
    chrome.storage.local.get(['pentest_ui_state'], function (r) {
      if (r.pentest_ui_state && r.pentest_ui_state['asset-source']) {
        switchAssetSource(r.pentest_ui_state['asset-source']);
      }
    });

    utils.bindClick('asset-scan-btn', handleAssetScan);
    utils.bindClick('asset-scan-all-btn', scanAllEngines);
    utils.bindEnterKey('asset-query', function () {
      handleAssetScan();
    });
    utils.bindClick('asset-custom-toggle', function () {
      toggleCustomQueryMode(!this.classList.contains('active'));
    });
    utils.bindClick('asset-export-btn', assetExportData);
    utils.bindPersist('asset-size');
    utils.bindPersist('ruoyi-probe-concurrency');
    utils.bindPersist('ruoyi-probe-method');
    utils.bindPersist('ruoyi-augment-mode');

    utils.on('asset-search', 'input', function () {
      assetApplySearchFilter(this.value.trim());
    });

    utils.bindClick('shodan-host-btn', shodanHostLookup);
    utils.bindEnterKey('shodan-host-input', function () {
      shodanHostLookup();
    });

    utils.bindClick('save-keys-btn', saveApiKeys);
    utils.bindClick('clear-keys-btn', clearApiKeys);

    loadApiKeys();
  }

  function initGatherAndRules() {
    utils.bindClick('gather-btn', gatherInfo);
    utils.on('gather-search', 'input', function () {
      gather.applySearchFilter(this.value.trim());
    });
    utils.bindClick('gather-copy-btn', gather.copyAllData);
    utils.bindClick('gather-export-btn', gather.exportAllData);

    utils.bindClick('gather-api-start-btn', gatherStartApiTraffic);
    utils.bindClick('gather-api-stop-btn', gatherStopApiTraffic);

    var apiFilterMethod = utils.get('api-filter-method');
    var apiFilterStatus = utils.get('api-filter-status');
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
      if (!container || !haeRules) return;
      const rules = gather.getActiveRules();
      let html = '';
      rules.forEach(group => {
        html += '<div class="rules-group">';
        html += '<div class="rules-group-header">' + utils.escapeHtml(group.group) + '</div>';
        (group.rules || []).forEach(rule => {
          const checked = rule.loaded ? ' checked' : '';
          const scopeLabel =
            ['response body', 'response', 'any'].indexOf(rule.scope) !== -1
              ? ''
              : ' <span class="rules-scope-na">[不适用]</span>';
          html += '<label class="rules-item">';
          html +=
            '<input type="checkbox"' +
            checked +
            ' data-group="' +
            utils.escapeHtml(group.group) +
            '" data-rule="' +
            utils.escapeHtml(rule.name) +
            '">';
          html +=
            '<span class="rules-item-name type-' +
            (rule.color || 'gray') +
            '">' +
            utils.escapeHtml(rule.name) +
            '</span>';
          html +=
            '<span class="rules-item-scope">' +
            utils.escapeHtml(rule.scope) +
            scopeLabel +
            '</span>';
          html += '</label>';
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
      var closeRulesModal = () => {
        rulesModal.style.display = 'none';
      };
      rulesModalClose.addEventListener('click', closeRulesModal);
      rulesModal.querySelector('.modal-overlay').addEventListener('click', closeRulesModal);
    }
    var applyRules = (rules, msg) => {
      gather.updateRules(rules);
      renderRulesList();
      utils.showToast(msg, 'success');
    };
    if (rulesImportBtn && rulesFileInput && haeRules) {
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
              '已导入 ' + imported.reduce((s, g) => s + (g.rules || []).length, 0) + ' 条规则'
            );
          } else {
            utils.showToast('规则文件解析失败', 'error');
          }
        };
        reader.readAsText(file);
        rulesFileInput.value = '';
      });
    }
    if (rulesResetBtn && haeRules) {
      rulesResetBtn.addEventListener('click', () => {
        applyRules(haeRules.getDefaultRules(), '已恢复默认规则');
      });
    }
  }

  function initLinksHistoryMultiUrl() {
    utils.bindClick('links-extract-btn', extractLinks);
    utils.bindClick('links-copy-btn', copyFilteredUrls);
    utils.bindClick('links-export-btn', exportLinks);
    utils.bindClick('links-send-multiurl-btn', sendToMultiUrl);
    utils.on('links-filter', 'input', renderLinks);
    utils.on('links-filter-type', 'change', renderLinks);
    utils.bindPersist('links-filter-type');
    utils.bindPersist('history-match-type');
    utils.bindPersist('history-output-type');

    utils.on('multiurl-input', 'input', () => updateMultiurlInfo(parseUrls().length));
    utils.bindClick('multiurl-open-btn', handleMultiurlOpen);
    utils.bindClick('multiurl-dedup-btn', handleMultiurlDedup);
    utils.bindClick('multiurl-copy-btn', copyAllUrls);
    utils.bindClick('multiurl-clear-btn', () => {
      utils.get('multiurl-input').value = '';
      updateMultiurlInfo(0);
    });

    utils.bindClick('tabsave-grab-btn', grabAllTabs);
    utils.bindClick('tabsave-copy-btn', copySavedTabUrls);
    utils.bindClick('tabsave-export-btn', exportSavedTabUrls);

    utils.bindClick('history-query-btn', queryHistory);

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
      const domain = extractDomain(raw);
      utils.get('history-domain').value = domain;
      const cdxUrl = buildCdxUrl(domain);
      utils.copyAndToast(cdxUrl, '查询URL已复制');
    });

    utils.bindEnterKey('history-domain', queryHistory);
    utils.on('history-domain', 'blur', function () {
      const val = this.value.trim();
      if (val) showHistoryQuickLinks(val);
    });

    utils.bindClick('history-copy-result-btn', () => {
      if (lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      const text = lastHistoryResults.map(i => i.raw || i.url).join('\n');
      utils.copyAndToast(text, '已复制 ' + lastHistoryResults.length + ' 条');
    });
    utils.bindClick('history-export-btn', historyExportData);

    utils.on('history-type-filter', 'input', function () {
      if (allHistoryResults.length === 0) return;
      const filtered = filterByType(allHistoryResults, this.value);
      renderHistoryResults(filtered, true);
      utils.get('history-status').textContent =
        '筛选: ' + filtered.length + ' / ' + allHistoryResults.length + ' 条';
    });

    utils.bindClick('history-copy-filtered-btn', () => {
      if (lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      var tfEl = utils.get('history-type-filter');
      const typeFilter = tfEl ? tfEl.value : '';
      const filtered = filterByType(lastHistoryResults, typeFilter);
      if (filtered.length === 0) {
        utils.showToast('没有匹配的结果', 'warning');
        return;
      }
      const text = filtered.map(i => i.raw || i.url).join('\n');
      utils.copyAndToast(text, '已复制 ' + filtered.length + ' 条');
    });

    utils.bindClick('history-send-links-btn', () => {
      if (lastHistoryResults.length === 0) {
        utils.showToast('没有结果', 'warning');
        return;
      }
      const urls = lastHistoryResults.map(i => i.url).filter(u => u && !u.startsWith('mailto:'));
      if (urls.length === 0) {
        utils.showToast('没有可用的URL', 'warning');
        return;
      }
      utils.get('multiurl-input').value = urls.join('\n');
      updateMultiurlInfo(urls.length);
      document
        .querySelectorAll('.tab-btn')
        .forEach(b => b.classList.toggle('active', b.dataset.panel === 'multiurl'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      var multiurlPanel = utils.get('panel-multiurl');
      if (multiurlPanel) multiurlPanel.classList.add('active');
      utils.showToast('已发送 ' + urls.length + ' 个链接', 'success');
    });
  }

  function initExifAndSpoofing() {
    initExifDragDrop();
    checkExifPending();

    utils.bindTabSwitch('exif-mode-btn', 'mode', switchExifMode);

    var exifFetchHandler = function () {
      const url = utils.get('exif-url-input').value.trim();
      url = utils.requireInput(url, '请输入图片URL');
      if (!url) return;
      fetchExifFromUrl(url);
    };
    utils.bindClick('exif-fetch-btn', exifFetchHandler);
    utils.bindEnterKey('exif-url-input', exifFetchHandler);

    utils.bindClick('exif-scan-page-btn', scanPageImages);

    utils.bindClick('exif-copy-all-btn', () => {
      lastExifData = utils.requireInput(lastExifData, '没有元数据');
      if (!lastExifData) return;
      const text = Object.entries(lastExifData)
        .map(([k, v]) => k + ': ' + v)
        .join('\n');
      utils.copyAndToast(text, '已复制全部元数据');
    });
    utils.bindClick('exif-copy-json-btn', copyExifData);
    utils.bindClick('exif-clear-btn', clearExif);

    utils.bindTabSwitch('spoof-tab', 'spoof', switchSpoofTab);

    utils.on('ua-category', 'change', function () {
      renderUaList(this.value);
    });
    utils.bindPersist('ua-category');
    renderUaList('desktop');

    utils.bindClick('spoof-ua-apply', applyUserAgent);
    utils.bindClick('spoof-ua-reset', resetUserAgent);

    utils.bindClick('cookie-refresh-btn', loadCookies);
    utils.bindClick('cookie-add-btn', showCookieAddEditor);
    utils.bindClick('cookie-import-btn', showCookieFileImportDialog);
    utils.bindClick('cookie-export-btn', exportCookies);
    utils.bindClick('cookie-clear-btn', clearAllCookies);
    utils.on('cookie-search', 'input', function () {
      filterCookies(this.value);
    });

    utils.bindClick('header-apply', applyHeaders);
    utils.bindClick('header-reset', resetHeaders);
    utils.bindClick('custom-header-add', addCustomHeaderRow);

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
        if (saved.ua) Object.assign(spoofState.ua, saved.ua);
        if (saved.headers) Object.assign(spoofState.headers, saved.headers);
        updateUaStatus();
      }
    });
  }

  function initVuePermissions() {
    utils.bindClick('vue-detect-btn', detectVue);
    utils.bindClick('vue-export-routes-btn', exportVueRoutes);
    utils.bindClick('vue-bypass-guards-btn', bypassVueGuards);
    utils.bindClick('vue-disable-auth-btn', disableRouteAuth);
    utils.bindClick('vue-copy-btn', () => {
      lastVueResult = utils.requireInput(lastVueResult, '没有可复制的内容');
      if (!lastVueResult) return;
      utils.copyAndToast(lastVueResult);
    });

    var vueResultsEl = utils.on('vue-results', 'click', function (e) {
      if (e.target.classList.contains('vue-route-open-btn')) {
        chrome.tabs.create({ url: e.target.dataset.url });
        return;
      }
      if (
        e.target.classList.contains('vue-copy-hist-btn') ||
        e.target.classList.contains('vue-copy-hash-btn')
      ) {
        lastVueResult = utils.requireInput(lastVueResult, '请先检测 Vue');
        if (!lastVueResult) return;
        try {
          var data = JSON.parse(lastVueResult);
          if (!data.routes || !data.routes.length) {
            utils.showToast('无路由数据', 'warning');
            return;
          }
          var mode = e.target.classList.contains('vue-copy-hist-btn') ? 'history' : 'hash';
          var base = (data.routerInfo && data.routerInfo.base) || '/';
          var paths = collectAllPathsFromVue(data.routes, '', base, mode);
          if (paths.length === 0) {
            utils.showToast('无静态路由路径', 'warning');
            return;
          }
          utils.copyText(paths.map(p => p.url).join('\n'));
          utils.showToast('已复制 ' + paths.length + ' 条 ' + mode + ' URL', 'success');
        } catch (err) {
          utils.showToast('复制失败', 'error');
        }
      }
    });
    utils.bindTabSwitch('vue-stab', 'vstab', switchVueSubTab);

    utils.bindClick('vue-store-read-btn', exploreVueStore);
    utils.bindClick('vue-store-copy-btn', copyFullStoreJson);
    utils.bindClick('vue-store-refresh-btn', exploreVueStore);
    initStoreExplorerEvents();

    utils.bindClick('perm-start-btn', startPermInterception);
    utils.bindClick('perm-stop-btn', stopPermInterception);
    utils.bindClick('perm-refresh-btn', refreshPermCaptured);
    utils.on('perm-filter', 'input', renderPermList);
    utils.on('perm-type-filter', 'change', renderPermList);
    utils.bindPersist('perm-type-filter');
    utils.bindClick('perm-detail-back', () => {
      permViewMode = 'list';
      const permList = utils.get('perm-captured-list');
      if (permList) permList.classList.remove('hidden');
      const filterRow = utils.get('perm-filter-row');
      if (filterRow) filterRow.classList.remove('hidden');
      const permDetail = utils.get('perm-detail');
      if (permDetail) permDetail.classList.add('hidden');
    });
    utils.bindClick('perm-open-all', permOpenAll);
    utils.bindClick('perm-change-admin', permChangeAdmin);
    utils.bindClick('perm-apply-btn', applyPermOverride);
    utils.bindClick('perm-copy-json', () => {
      let val = utils.get('perm-json-editor').value;
      val = utils.requireInput(val, '没有数据');
      if (!val) return;
      utils.copyAndToast(val);
    });

    utils.bindClick('perm-expand-ids', permExpandMenuIds);

    utils.bindClick('compare-inject-btn', () => {
      switchVueSubTab('perm');
      if (permSelectedIndex < 0 && permCapturedData.length > 0) {
        permSelectedIndex = 0;
        showPermDetail(0);
      } else if (permSelectedIndex >= 0) {
        showPermDetail(permSelectedIndex);
      }
      autoInjectHiddenRoutes();
    });
  }

  function initJsSearchAndTraverse() {
    var doJsSearch = function () {
      searchJsKeywords(utils.get('jssearch-keyword').value.trim());
    };
    utils.bindClick('jssearch-btn', doJsSearch);
    utils.bindEnterKey('jssearch-keyword', doJsSearch);
    utils.bindTabSwitch('jssearch-preset', 'kw', function (kw) {
      var input = utils.get('jssearch-keyword');
      if (input) input.value = kw;
      searchJsKeywords(kw);
    });

    utils.bindClick('compare-btn', compareRoutesAndMenu);
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
      utils.showToast('已复制 ' + hiddenPaths.length + ' 条隐藏路由', 'success');
    });

    utils.bindClick('traverse-start-btn', startTraverseRoutes);
    utils.bindClick('traverse-stop-btn', stopTraverse);

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
    utils.bindClick('ruoyi-selectall-btn', toggleSelectAll);
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
              permInterceptActive = true;
              utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', true);
              utils.setStatus('perm-status', '拦截中...');
              refreshPermCaptured();
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
        jsBlocked = true;
        updateJsToggleStatus();
      } else {
        chrome.storage.local.remove('js_blocked_tabId');
      }
    });

    chrome.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin', 'ruoyiHookTabId'], result => {
      getActiveTab().then(tab => {
        if (!tab) return;

        var tabOrigin = tab.url ? new URL(tab.url).origin : '';
        var hookEnabled = result.ruoyiHookEnabled && result.ruoyiHookOrigin;

        if (hookEnabled && tabOrigin === result.ruoyiHookOrigin) {
          ruoyiHookActive = true;
          ruoyiTabId = tab.id;
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
          allLinks = result.allLinks;
          renderLinks();
          utils.setStatus('links-count', '已恢复，共 ' + allLinks.length + ' 个链接');
        }
      });
    });
  }

  function initThemeAndPayload() {
    var themes = ['light', 'dark'];
    var savedTheme = localStorage.getItem('pentest-theme');
    if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
    utils.bindClick('settings-btn', () => {
      chrome.runtime.openOptionsPage();
    });

    utils.bindClick('theme-toggle', () => {
      var current = document.documentElement.getAttribute('data-theme') || 'light';
      var next = themes[(themes.indexOf(current) + 1) % themes.length];
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
      var output = utils.get('revshell-output');
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
        xssFilterType = btn.dataset.xfilter;
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
      var checks = document.querySelectorAll('.xssscan-point-check');
      var allChecked = Array.from(checks).every(function (cb) {
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
      var st = utils.get('xssscan-sink-status');
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
      if (sourcemapCurrentModule !== null) downloadSingleModule(sourcemapCurrentModule);
    });
    var smSearchTimer = null;
    utils.on('sourcemap-search-input', 'input', function () {
      clearTimeout(smSearchTimer);
      smSearchTimer = setTimeout(function () {
        sourcemapSearchTerm = this.value.trim().toLowerCase();
        renderSourcemapModules();
      }, 200);
    });
    utils.bindClick('sourcemap-analyze-btn', analyzeSourcemaps);
    utils.bindClick('sm-analysis-close', function () {
      var card = utils.get('sm-analysis-card');
      if (card) card.classList.add('hidden');
    });

    utils.bindClick('sourcemap-api-btn', showApiEndpoints);
    utils.bindClick('sm-api-close', function () {
      var card = utils.get('sm-api-card');
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
        statusTime.textContent =
          String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
      };
      update();
      setInterval(update, 30000);
    }

    document.addEventListener('keydown', function (e) {
      if (!e.altKey) return;
      var num = parseInt(e.key, 10);
      if (num >= 1 && num <= tabsPerPage) {
        e.preventDefault();
        var idx = currentPage * tabsPerPage + (num - 1);
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

  // ====== Init ======
  async function initApp() {
    await utils.loadSettings();
    initContextMenu();
    var savedState = await utils.restoreUIState();
    initSettings(savedState);
    initTabPagination();
    initMainTabs();
    initEncodingJwtCrypto();
    initRsaFaviconAsset();
    initGatherAndRules();
    initLinksHistoryMultiUrl();
    initExifAndSpoofing();
    initVuePermissions();
    initJsSearchAndTraverse();
    initSecurityDetectors();
    initNetworkTools();
    initStateRestoration();
    initThemeAndPayload();
    initXssAndSourcemap();
    initStatusBarAndKeyboard();
  }

  function startApp() {
    window._panelsReady.then(initApp);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startApp);
  } else {
    startApp();
  }
})();
