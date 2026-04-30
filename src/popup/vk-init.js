// VulnKit Init
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
    handleCopyXssUrls,
    initXssScanPayloadSelect,
    clearResults: xssClearResults,
    exportData: xssExportData,
    setXssSearchText,
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

  // ====== Init ======
  function initApp() {
    // Tab pagination (2 rows x 4 cols = 8 per page)
    var tabBtns = Array.from(document.querySelectorAll('.tab-btn'));
    var tabsPerPage = 8;
    var totalTabs = tabBtns.length;
    var totalPages = Math.ceil(totalTabs / tabsPerPage);
    var currentPage = 0;

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
    }

    var scrollLeftBtn = utils.bindClick('tab-scroll-left', function () {
      if (currentPage > 0) showTabPage(currentPage - 1);
    });
    var scrollRightBtn = utils.bindClick('tab-scroll-right', function () {
      if (currentPage < totalPages - 1) showTabPage(currentPage + 1);
    });
    showTabPage(0);

    // Main panel tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const panel = btn.dataset.panel;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const target = utils.get('panel-' + panel);
        if (target) target.classList.add('active');
        utils.get('status-text').textContent = btn.textContent;

        // Auto-fill history domain when switching to history panel
        if (panel === 'history') {
          var historyDomainInput = utils.get('history-domain');
          if (historyDomainInput && !historyDomainInput.value.trim()) {
            getCurrentDomain().then(d => {
              if (d && !historyDomainInput.value.trim()) historyDomainInput.value = d;
            });
          }
        }
      });
    });

    // Encoding sub-tabs
    document.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchEncodingTab(btn.dataset.type));
    });

    // Encoding buttons
    const encodingBindings = [
      { id: 'encode-btn', handler: handleEncode },
      { id: 'decode-btn', handler: handleDecode },
      { id: 'clear-encoding-btn', handler: clearEncodingFields },
      { id: 'copy-encoding-btn', handler: copyEncodingOutput },
      { id: 'encoding-swap-btn', handler: swapEncodingFields },
    ];
    encodingBindings.forEach(({ id, handler }) => utils.bindClick(id, handler));

    // JWT buttons
    var jwtDecodeBtn = utils.get('jwt-decode-btn');
    if (jwtDecodeBtn)
      jwtDecodeBtn.addEventListener('click', function () {
        var input = (utils.get('jwt-input') || {}).value;
        if (!input) {
          utils.showToast('请输入 JWT Token', 'warning');
          return;
        }
        decodeJwt(input);
      });
    var jwtClearBtn = utils.bindClick('jwt-clear-btn', clearJwt);
    var jwtCopyHeaderBtn = utils.bindClick('jwt-copy-header-btn', copyJwtHeader);
    var jwtCopyPayloadBtn = utils.bindClick('jwt-copy-payload-btn', copyJwtPayload);

    // Crypto algo tabs
    document.querySelectorAll('.crypto-algo-btn').forEach(function (btn) {
      if (btn.dataset.algo)
        btn.addEventListener('click', function () {
          switchCryptoAlgo(btn.dataset.algo);
        });
    });

    // Crypto action buttons
    var cryptoEncBtn = utils.bindClick('crypto-enc-btn', doCryptoEncrypt);
    var cryptoDecBtn = utils.bindClick('crypto-dec-btn', doCryptoDecrypt);
    var cryptoVerifyBtn = utils.bindClick('crypto-verify-btn', doCryptoVerify);
    var hashHmacCheck = utils.on('hash-hmac', 'change', toggleHashHmac);
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

    // Crypto mode/IV toggle listeners
    utils.on('aes-mode', 'change', () => toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode'));
    utils.on('des-mode', 'change', () => toggleIvVisibility('des', 'des-iv-group', 'des-mode'));
    utils.on('sm4-mode', 'change', function () {
      var ivG = utils.get('sm4-iv-group');
      if (ivG) {
        if (this.value === 'cbc') ivG.classList.remove('hidden');
        else ivG.classList.add('hidden');
      }
    });

    // SM2 generate keypair
    utils.bindClick('sm2-genkey-btn', function () {
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

    // Initial IV visibility
    toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
    toggleIvVisibility('des', 'des-iv-group', 'des-mode');
    switchCryptoAlgo('aes');

    // RSA genkey
    utils.bindClick('rsa-genkey-btn', rsaGenerateKeyPair);

    // Favicon buttons
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

    // Asset mapping
    document.querySelectorAll('.source-btn').forEach(btn => {
      btn.addEventListener('click', () => switchAssetSource(btn.dataset.source));
    });

    utils.bindClick('asset-scan-btn', handleAssetScan);
    utils.on('asset-query', 'keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAssetScan();
      }
    });
    utils.bindClick('asset-custom-toggle', function () {
      toggleCustomQueryMode(!this.classList.contains('active'));
    });
    utils.bindClick('asset-export-btn', assetExportData);

    utils.on('asset-search', 'input', function () {
      assetApplySearchFilter(this.value.trim());
    });

    utils.bindClick('shodan-host-btn', shodanHostLookup);
    utils.on('shodan-host-input', 'keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        shodanHostLookup();
      }
    });

    utils.bindClick('save-keys-btn', saveApiKeys);
    utils.bindClick('clear-keys-btn', clearApiKeys);

    loadApiKeys();

    // Info gather
    utils.bindClick('gather-btn', gatherInfo);
    utils.on('gather-search', 'input', function () {
      gather.applySearchFilter(this.value.trim());
    });
    const gatherCopyBtn = utils.bindClick('gather-copy-btn', gather.copyAllData);
    const gatherExportBtn = utils.bindClick('gather-export-btn', gather.exportAllData);

    // Rules management
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
          const scopeLabel = isPageScope(rule.scope)
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
      rulesModalClose.addEventListener('click', () => {
        rulesModal.style.display = 'none';
      });
      rulesModal.querySelector('.modal-overlay').addEventListener('click', () => {
        rulesModal.style.display = 'none';
      });
    }
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
            gather.updateRules(imported);
            renderRulesList();
            utils.showToast(
              '已导入 ' + imported.reduce((s, g) => s + (g.rules || []).length, 0) + ' 条规则',
              'success'
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
        const defaults = haeRules.getDefaultRules();
        gather.updateRules(defaults);
        renderRulesList();
        utils.showToast('已恢复默认规则', 'success');
      });
    }

    function isPageScope(scope) {
      return ['response body', 'response', 'any'].indexOf(scope) !== -1;
    }

    // Link extract
    utils.bindClick('links-extract-btn', extractLinks);
    utils.bindClick('links-copy-btn', copyFilteredUrls);
    utils.bindClick('links-export-btn', exportLinks);
    utils.bindClick('links-send-multiurl-btn', sendToMultiUrl);
    utils.on('links-filter', 'input', renderLinks);
    utils.on('links-filter-type', 'change', renderLinks);

    // URL multi-open
    utils.on('multiurl-input', 'input', () => updateMultiurlInfo(parseUrls().length));
    utils.bindClick('multiurl-open-btn', handleMultiurlOpen);
    utils.bindClick('multiurl-dedup-btn', handleMultiurlDedup);
    utils.bindClick('multiurl-copy-btn', copyAllUrls);
    utils.bindClick('multiurl-clear-btn', () => {
      utils.get('multiurl-input').value = '';
      updateMultiurlInfo(0);
    });

    // Tab save
    utils.bindClick('tabsave-grab-btn', grabAllTabs);
    utils.bindClick('tabsave-copy-btn', copySavedTabUrls);
    utils.bindClick('tabsave-export-btn', exportSavedTabUrls);

    // History
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

    utils.on('history-domain', 'keydown', function (e) {
      if (e.key === 'Enter') queryHistory();
    });
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

    // EXIF viewer
    initExifDragDrop();
    checkExifPending();

    document.querySelectorAll('.exif-mode-btn').forEach(btn => {
      btn.addEventListener('click', () => switchExifMode(btn.dataset.mode));
    });

    var exifFetchHandler = function () {
      const url = utils.get('exif-url-input').value.trim();
      if (!url) {
        utils.showToast('请输入图片URL', 'warning');
        return;
      }
      fetchExifFromUrl(url);
    };
    utils.bindClick('exif-fetch-btn', exifFetchHandler);
    utils.on('exif-url-input', 'keydown', function (e) {
      if (e.key === 'Enter') exifFetchHandler();
    });

    utils.bindClick('exif-scan-page-btn', scanPageImages);

    utils.bindClick('exif-copy-all-btn', () => {
      if (!lastExifData) {
        utils.showToast('没有元数据', 'warning');
        return;
      }
      const text = Object.entries(lastExifData)
        .map(([k, v]) => k + ': ' + v)
        .join('\n');
      utils.copyAndToast(text, '已复制全部元数据');
    });
    utils.bindClick('exif-copy-json-btn', copyExifData);
    utils.bindClick('exif-clear-btn', clearExif);

    // Request Spoofing
    document.querySelectorAll('.spoof-tab').forEach(btn => {
      btn.addEventListener('click', () => switchSpoofTab(btn.dataset.spoof));
    });

    utils.on('ua-category', 'change', function () {
      renderUaList(this.value);
    });
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

    // Vue Analysis
    utils.bindClick('vue-detect-btn', detectVue);
    utils.bindClick('vue-export-routes-btn', exportVueRoutes);
    utils.bindClick('vue-bypass-guards-btn', bypassVueGuards);
    utils.bindClick('vue-disable-auth-btn', disableRouteAuth);
    utils.bindClick('vue-copy-btn', () => {
      if (!lastVueResult) {
        utils.showToast('没有可复制的内容', 'warning');
        return;
      }
      utils.copyAndToast(lastVueResult);
    });

    // Vue results event delegation (route open + batch copy)
    var vueResultsEl = utils.on('vue-results', 'click', function (e) {
      if (e.target.classList.contains('vue-route-open-btn')) {
        chrome.tabs.create({ url: e.target.dataset.url });
        return;
      }
      if (
        e.target.classList.contains('vue-copy-hist-btn') ||
        e.target.classList.contains('vue-copy-hash-btn')
      ) {
        if (!lastVueResult) {
          utils.showToast('请先检测 Vue', 'warning');
          return;
        }
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
    document.querySelectorAll('.vue-stab').forEach(btn => {
      btn.addEventListener('click', () => switchVueSubTab(btn.dataset.vstab));
    });

    // Vue Store Explorer
    utils.bindClick('vue-store-read-btn', exploreVueStore);
    utils.bindClick('vue-store-copy-btn', copyFullStoreJson);
    utils.bindClick('vue-store-refresh-btn', exploreVueStore);
    initStoreExplorerEvents();

    // Permission menu interception
    utils.bindClick('perm-start-btn', startPermInterception);
    utils.bindClick('perm-stop-btn', stopPermInterception);
    utils.bindClick('perm-refresh-btn', refreshPermCaptured);
    utils.on('perm-filter', 'input', renderPermList);
    utils.on('perm-type-filter', 'change', renderPermList);
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
      const val = utils.get('perm-json-editor').value;
      if (!val) {
        utils.showToast('没有数据', 'warning');
        return;
      }
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

    // JS keyword search
    var doJsSearch = function () {
      searchJsKeywords(utils.get('jssearch-keyword').value.trim());
    };
    utils.bindClick('jssearch-btn', doJsSearch);
    utils.on('jssearch-keyword', 'keydown', function (e) {
      if (e.key === 'Enter') doJsSearch();
    });
    document.querySelectorAll('.jssearch-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.get('jssearch-keyword').value = btn.dataset.kw;
        searchJsKeywords(btn.dataset.kw);
      });
    });

    // Route vs menu comparison
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

    // Auto-traverse routes
    utils.bindClick('traverse-start-btn', startTraverseRoutes);
    utils.bindClick('traverse-stop-btn', stopTraverse);

    // JS Control
    document.querySelectorAll('.jsctrl-tab').forEach(btn => {
      btn.addEventListener('click', () => switchJsCtrlTab(btn.dataset.ctrl));
    });
    utils.bindClick('js-disable-btn', disableJs);
    utils.bindClick('js-enable-btn', enableJs);
    utils.bindClick('antidebug-scan-btn', scanAntiDebug);
    utils.bindClick('antidebug-bypass-btn', bypassAntiDebug);
    utils.bindClick('antidebug-clear-btn', clearScriptBlock);

    // Remove copy restrictions
    utils.bindClick('uncopy-btn', removeCopyRestrictions);

    // RuoYi sub-tabs
    document.querySelectorAll('.ruoyi-stab').forEach(btn => {
      if (btn.dataset.rstab)
        btn.addEventListener('click', () => switchRuoYiSubTab(btn.dataset.rstab));
    });

    // RuoYi detection
    utils.bindClick('ruoyi-detect-btn', detectRuoYi);

    // RuoYi route hook
    utils.bindClick('ruoyi-hook-install-btn', installRouteHook);
    utils.bindClick('ruoyi-hook-remove-btn', removeRouteHook);
    utils.bindClick('ruoyi-hook-check-btn', checkHookStatus);
    utils.on('ruoyi-augment-mode', 'change', function () {
      setAugmentMode(this.value);
    });

    // RuoYi export buttons
    utils.bindClick('ruoyi-copy-json-btn', copyRouteJson);
    utils.bindClick('ruoyi-export-curl-btn', exportCurlCommands);
    utils.bindClick('ruoyi-export-html-btn', exportHtmlReport);

    // RuoYi JS analysis
    utils.bindClick('ruoyi-analyze-btn', analyzeJsRoutes);
    utils.bindClick('ruoyi-apply-btn', applyExtraRoutes);
    utils.bindClick('ruoyi-clear-btn', clearExtraRoutes);
    utils.bindClick('ruoyi-selectall-btn', toggleSelectAll);
    utils.bindClick('ruoyi-copy-paths-btn', copyExtraPaths);

    // RuoYi batch probe
    utils.bindClick('ruoyi-probe-btn', batchProbeRoutes);
    utils.bindClick('ruoyi-probe-stop-btn', stopProbe);
    utils.bindClick('ruoyi-probe-export-btn', exportProbeResults);

    // RuoYi API traffic
    utils.bindClick('ruoyi-traffic-load-btn', loadApiTraffic);
    utils.bindClick('ruoyi-traffic-clear-btn', clearApiTraffic);
    utils.bindClick('ruoyi-traffic-export-btn', exportApiTraffic);
    utils.on('ruoyi-traffic-filter', 'input', filterApiTraffic);

    // MaR dynamic route loading
    utils.bindClick('mar-scan-btn', marScanDynamicRoutes);
    utils.bindClick('mar-inject-btn', marInjectToRouter);
    utils.bindClick('mar-selectall-btn', marToggleSelectAll);
    utils.bindClick('mar-copy-btn', marCopyHiddenPaths);

    // Restore perm intercept state
    chrome.storage.local.get(['permInterceptTabId'], result => {
      if (result.permInterceptTabId) {
        getActiveTab().then(tab => {
          if (tab && tab.id === result.permInterceptTabId) {
            permInterceptActive = true;
            const startBtn = utils.get('perm-start-btn');
            const stopBtn = utils.get('perm-stop-btn');
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;
            const statusEl = utils.get('perm-status');
            if (statusEl) statusEl.textContent = '拦截中... 页面刷新后会自动重新注入';
            // Fetch captured data and start auto-refresh
            refreshPermCaptured();
            startPermAutoRefresh();
          } else {
            chrome.storage.local.remove('permInterceptTabId');
          }
        });
      }
    });

    // Restore JS toggle state
    chrome.storage.local.get(['js_blocked_tabId'], result => {
      if (result.js_blocked_tabId) {
        getActiveTab().then(tab => {
          if (tab && tab.id === result.js_blocked_tabId) {
            jsBlocked = true;
            updateJsToggleStatus();
          } else {
            chrome.storage.local.remove('js_blocked_tabId');
          }
        });
      }
    });

    // Restore RuoYi hook state
    // The hook always passively captures /getRouters, so always check status for current tab.
    chrome.storage.local.get(['ruoyiHookTabId', 'ruoyiHookEnabled'], result => {
      getActiveTab().then(tab => {
        if (!tab) return;

        if (result.ruoyiHookTabId && result.ruoyiHookEnabled && tab.id === result.ruoyiHookTabId) {
          // Was explicitly enabled for this tab — restore full UI
          ruoyiHookActive = true;
          ruoyiTabId = result.ruoyiHookTabId;
          const installBtn = utils.get('ruoyi-hook-install-btn');
          const removeBtn = utils.get('ruoyi-hook-remove-btn');
          if (installBtn) installBtn.disabled = true;
          if (removeBtn) removeBtn.disabled = false;
          checkHookStatus();
        } else if (tab.url && /^https?:/.test(tab.url)) {
          // Always check for passively captured data on http/https pages
          checkHookStatus();
        }
      });
    });

    // Restore gather data for current tab
    getActiveTab().then(tab => {
      const currentUrl = tab?.url || '';
      gather.restoreData(currentUrl);
      chrome.storage.local.get(['allLinks', 'allLinksUrl'], result => {
        if (result.allLinks && result.allLinksUrl === currentUrl) {
          allLinks = result.allLinks;
          renderLinks();
          const statusEl = utils.get('links-count');
          if (statusEl) statusEl.textContent = '已恢复，共 ' + allLinks.length + ' 个链接';
        }
      });
    });

    // Theme toggle
    var themes = ['light', 'dark'];
    var savedTheme = localStorage.getItem('pentest-theme');
    if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
    utils.bindClick('theme-toggle', () => {
      var current = document.documentElement.getAttribute('data-theme') || 'light';
      var next = themes[(themes.indexOf(current) + 1) % themes.length];
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('pentest-theme', next);
    });

    // Payload tab switching
    document.querySelectorAll('.payload-tab').forEach(btn => {
      if (btn.dataset.ptab) btn.addEventListener('click', () => switchPayloadTab(btn.dataset.ptab));
    });

    // Payload data rendering
    renderPayloadCategories('xss-categories', XSS_DATA, false);
    renderSqliPayloads();
    renderPayloadCategories('lfi-categories', LFI_DATA, false);
    renderPayloadCategories('webshell-categories', WEBSHELL_DATA, false);
    renderPayloadCategories('cmdref-categories', CMDREF_DATA, false);
    renderAllReverseShells();

    // Payload search
    utils.on('payload-search', 'input', function () {
      payloadApplySearch(this.value.trim());
    });

    // Reverse shell
    utils.bindClick('revshell-gen-btn', generateReverseShell);
    utils.bindClick('revshell-copy-btn', () => {
      var output = utils.get('revshell-output');
      if (output && output.value) {
        utils.copyAndToast(output.value, '已复制命令', 'success', 1000);
      }
    });
    utils.on('revshell-type', 'change', generateReverseShell);
    utils.on('revshell-ip', 'input', generateReverseShell);
    utils.on('revshell-port', 'input', generateReverseShell);

    // SQL injection regenerate
    utils.bindClick('sqli-regen-btn', renderSqliPayloads);
    utils.on('sqli-columns', 'change', renderSqliPayloads);
    utils.on('sqli-table', 'input', renderSqliPayloads);

    // XSS Scan
    initXssScanPayloadSelect();
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
    utils.bindClick('xssscan-copyall-btn', handleCopyXssUrls);
    utils.bindClick('xssscan-export-btn', xssExportData);

    // Webpack Module Mapping (Source Map Scan)
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

    // Webpack API endpoint extraction
    utils.bindClick('sourcemap-api-btn', showApiEndpoints);
    utils.bindClick('sm-api-close', function () {
      var card = utils.get('sm-api-card');
      if (card) card.classList.add('hidden');
    });
    utils.bindClick('sourcemap-export-json-btn', exportModulesJSON);
    utils.bindClick('sourcemap-export-csv-btn', exportModulesCSV);

    // Status bar clock
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
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
})();
