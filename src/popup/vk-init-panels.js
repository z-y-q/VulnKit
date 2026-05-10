// vk-init-panels.js - Panel initialization functions (lazy-loaded via import())
// No static imports — each init function loads its own dependencies dynamically.
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const { getCurrentDomain, getActiveTab } = utils;

function initEncodingJwtCrypto(savedState) {
  Promise.all([import('./vk-encoding.js'), import('./vk-jwt.js'), import('./vk-crypto.js')]).then(
    function (mods) {
      var encoding = mods[0];
      var jwt = mods[1];
      var crypto = mods[2];

      utils.bindTabSwitch('sub-tab-btn', 'type', encoding.switchEncodingTab);

      var encodingBindings = [
        { id: 'encode-btn', handler: encoding.handleEncode },
        { id: 'decode-btn', handler: encoding.handleDecode },
        { id: 'clear-encoding-btn', handler: encoding.clearEncodingFields },
        { id: 'copy-encoding-btn', handler: encoding.copyOutput },
        { id: 'encoding-swap-btn', handler: encoding.swapFields },
      ];
      encodingBindings.forEach(function (b) {
        utils.bindClick(b.id, b.handler);
      });

      var jwtDecodeBtn = utils.get('jwt-decode-btn');
      if (jwtDecodeBtn)
        jwtDecodeBtn.addEventListener('click', function () {
          var input = (utils.get('jwt-input') || {}).value;
          input = utils.requireInput(input, '请输入 JWT Token');
          if (!input) return;
          jwt.decodeJwt(input);
        });
      utils.bindClick('jwt-clear-btn', jwt.clearJwt);
      utils.bindClick('jwt-copy-header-btn', jwt.copyJwtHeader);
      utils.bindClick('jwt-copy-payload-btn', jwt.copyJwtPayload);
      utils.bindClick('jwt-copy-all-btn', jwt.copyJwtAll);
      utils.bindClick('jwt-verify-btn', jwt.verifyJwtSignature);

      utils.bindTabSwitch('crypto-algo-btn', 'algo', crypto.switchCryptoAlgo);

      utils.bindClick('crypto-enc-btn', crypto.doCryptoEncrypt);
      utils.bindClick('crypto-dec-btn', crypto.doCryptoDecrypt);
      utils.bindClick('crypto-verify-btn', crypto.doCryptoVerify);
      utils.on('hash-hmac', 'change', crypto.toggleHashHmac);
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

      utils.on('aes-mode', 'change', function () {
        crypto.toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
      });
      utils.on('des-mode', 'change', function () {
        crypto.toggleIvVisibility('des', 'des-iv-group', 'des-mode');
      });
      utils.on('sm4-mode', 'change', function () {
        var ivG = utils.get('sm4-iv-group');
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
          var kp = window.sm2.generateKeyPairHex();
          var pubEl = utils.get('sm2-pubkey');
          if (pubEl) pubEl.value = kp.publicKey;
          var priEl = utils.get('sm2-prikey');
          if (priEl) priEl.value = kp.privateKey;
          utils.showToast('密钥对已生成', 'success');
        } catch (e) {
          utils.showToast('生成失败: ' + e.message, 'error');
        }
      });

      crypto.toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
      crypto.toggleIvVisibility('des', 'des-iv-group', 'des-mode');
      crypto.switchCryptoAlgo('aes');

      var defaultEncoding = utils.getSetting('defaultEncoding', 'base64');
      var hasSavedSubtab = savedState && savedState['encoding-subtab'];
      if (!hasSavedSubtab && defaultEncoding && encoding.ENCODING_NAMES[defaultEncoding]) {
        encoding.switchEncodingTab(defaultEncoding);
      }
      var defaultHash = utils.getSetting('defaultHash', 'SHA256');
      if (defaultHash) {
        var hashAlgoEl = utils.get('hash-algo');
        if (hashAlgoEl) hashAlgoEl.value = defaultHash;
      }
    }
  );
}

function initRsaFaviconAsset() {
  Promise.all([import('./vk-crypto.js'), import('./vk-favicon.js'), import('./vk-asset.js')]).then(
    function (mods) {
      var crypto = mods[0];
      var favicon = mods[1];
      var asset = mods[2];

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
  );
}

function initGatherAndRules() {
  Promise.all([
    import('./vk-gather.js'),
    import('./vk-hae-rules.js'),
    import('./vk-source-loader.js'),
  ]).then(function (mods) {
    var gather = mods[0];
    var haeRules = mods[1];
    var sourceLoader = mods[2];

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
      sourceLoader.setSourceUrls(urls);
      utils.showToast('已发送 ' + urls.length + ' 个链接到源码加载面板', 'success');
    });

    var rulesBtn = utils.get('gather-rules-btn');
    var rulesModal = utils.get('rules-modal');
    var rulesModalClose = utils.get('rules-modal-close');
    var rulesImportBtn = utils.get('rules-import-btn');
    var rulesResetBtn = utils.get('rules-reset-btn');
    var rulesFileInput = utils.get('rules-file-input');

    function renderRulesList() {
      var container = utils.get('rules-list');
      if (!container) return;
      var rules = gather.getActiveRules();
      var html = '';
      rules.forEach(function (group) {
        html += '<div class="rules-group">';
        html += '<div class="rules-group-header">' + utils.escapeHtml(group.group) + '</div>';
        (group.rules || []).forEach(function (rule) {
          var checked = rule.loaded ? ' checked' : '';
          var scopeLabel =
            ['response body', 'response', 'any'].indexOf(rule.scope) !== -1
              ? ''
              : ' <span class="rules-scope-na">[不适用]</span>';
          html +=
            '<label class="rules-item">' +
            '<input type="checkbox"' +
            checked +
            ' data-group="' +
            utils.escapeHtml(group.group) +
            '" data-rule="' +
            utils.escapeHtml(rule.name) +
            '">' +
            '<span class="rules-item-name type-' +
            (rule.color || 'gray') +
            '">' +
            utils.escapeHtml(rule.name) +
            '</span>' +
            '<span class="rules-item-scope">' +
            utils.escapeHtml(rule.scope) +
            scopeLabel +
            '</span>' +
            '</label>';
        });
        html += '</div>';
      });
      container.innerHTML = html;

      container.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
        cb.addEventListener('change', function () {
          var updated = haeRules.toggleRule(rules, cb.dataset.group, cb.dataset.rule);
          gather.updateRules(updated);
        });
      });
    }

    if (rulesBtn && rulesModal) {
      rulesBtn.addEventListener('click', function () {
        renderRulesList();
        rulesModal.style.display = 'flex';
      });
    }
    if (rulesModalClose && rulesModal) {
      var closeRulesModal = function () {
        rulesModal.style.display = 'none';
      };
      rulesModalClose.addEventListener('click', closeRulesModal);
      var overlay = rulesModal.querySelector('.modal-overlay');
      if (overlay) overlay.addEventListener('click', closeRulesModal);
    }
    var applyRules = function (rules, msg) {
      gather.updateRules(rules);
      renderRulesList();
      utils.showToast(msg, 'success');
    };
    if (rulesImportBtn && rulesFileInput) {
      rulesImportBtn.addEventListener('click', function () {
        rulesFileInput.click();
      });
      rulesFileInput.addEventListener('change', function () {
        var file = rulesFileInput.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function () {
          var imported = haeRules.importRules(reader.result);
          if (imported && imported.length > 0) {
            applyRules(
              imported,
              '已导入 ' +
                imported.reduce(function (s, g) {
                  return s + (g.rules || []).length;
                }, 0) +
                ' 条规则'
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
      rulesResetBtn.addEventListener('click', function () {
        applyRules(haeRules.getDefaultRules(), '已恢复默认规则');
      });
    }
  });
}

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

function initXssAndSourcemap() {
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
    document.querySelectorAll('.xssscan-filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        xss.setXssFilterType(btn.dataset.xfilter);
        document.querySelectorAll('.xssscan-filter-btn').forEach(function (b) {
          b.classList.remove('active');
        });
        btn.classList.add('active');
        xss.renderXssPoints();
      });
    });
    utils.on('xssscan-search', 'input', function () {
      xss.setXssSearchText(this.value);
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
    utils.bindClick('xssscan-batchopen-btn', xss.handleBatchOpenXss);
    utils.bindClick('xssscan-verify-btn', xss.handleVerifyReflection);
    utils.bindClick('xssscan-open-reflected-btn', xss.handleOpenReflected);
    utils.bindClick('xssscan-copyall-btn', xss.handleCopyXssUrls);
    utils.bindClick('xssscan-export-btn', xss.xssExportData);
    utils.bindClick('xssscan-sink-btn', xss.analyzeDomSinks);
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
  import('./vk-report.js').then(function (report) {
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
      var findings = report.getLastFindings();
      if (!findings || findings.length === 0) {
        utils.showToast('没有可导出的结果', 'warning');
        return;
      }
      report.exportHtml(findings);
    });

    utils.bindClick('report-export-md-btn', function () {
      var findings = report.getLastFindings();
      if (!findings || findings.length === 0) {
        utils.showToast('没有可导出的结果', 'warning');
        return;
      }
      report.exportMarkdown(findings);
    });
  });
}

// ====== Security Detectors 2: Headers + Redirect + Fuzz ======

function initSecurityDetectors2() {
  Promise.all([import('./vk-headers.js'), import('./vk-redirect.js'), import('./vk-fuzz.js')]).then(
    function (mods) {
      var headers = mods[0];
      var redirect = mods[1];
      var fuzz = mods[2];

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
          if (!btn) return;
          var origText = btn.textContent;
          btn.innerHTML = '<span class="spinner"></span> 扫描中...';
          btn.disabled = true;
          try {
            var result = await headers.scanSecurityHeaders(url);
            if (result) headers.renderHeadersResults(result);
          } finally {
            btn.textContent = origText;
            btn.disabled = false;
          }
        });

        utils.bindClick('headers-export-btn', function () {
          var format = (utils.get('headers-export-format') || {}).value || 'txt';
          headers.exportHeadersResults(format);
        });

        var hFilterBtns = document.querySelectorAll('#headers-filter-row .filter-btn');
        for (var hi = 0; hi < hFilterBtns.length; hi++) {
          hFilterBtns[hi].addEventListener('click', function () {
            for (var hj = 0; hj < hFilterBtns.length; hj++)
              hFilterBtns[hj].classList.remove('active');
            this.classList.add('active');
            headers.setFilter(this.getAttribute('data-filter') || 'all');
          });
        }

        var hSearch = utils.get('headers-search');
        if (hSearch) {
          hSearch.addEventListener('input', function () {
            headers.setSearch(this.value);
          });
        }
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
          if (stopBtn) {
            stopBtn.style.display = '';
            stopBtn.innerHTML = '<span class="spinner"></span> 扫描中...';
          }
          if (progressEl) progressEl.style.display = 'flex';

          try {
            var concurrency = parseInt((utils.get('redirect-concurrency') || {}).value, 10) || 5;
            var result = await redirect.scanRedirects(url, concurrency, function (p) {
              if (progressFill) progressFill.style.width = (p.completed / p.total) * 100 + '%';
              if (progressText) progressText.textContent = p.completed + '/' + p.total;
            });
            if (result) redirect.renderRedirectResults(result);
          } finally {
            if (scanBtn) scanBtn.style.display = '';
            if (stopBtn) {
              stopBtn.textContent = '停止';
              stopBtn.style.display = 'none';
            }
          }
        });

        utils.bindClick('redirect-stop-btn', function () {
          redirect.stopRedirectScan();
        });

        utils.bindClick('redirect-export-btn', function () {
          var format = (utils.get('redirect-export-format') || {}).value || 'txt';
          redirect.exportRedirectResults(format);
        });

        var filterBtns = document.querySelectorAll('#redirect-filter-row .filter-btn');
        for (var fi = 0; fi < filterBtns.length; fi++) {
          filterBtns[fi].addEventListener('click', function () {
            for (var fj = 0; fj < filterBtns.length; fj++)
              filterBtns[fj].classList.remove('active');
            this.classList.add('active');
            redirect.setFilter(this.getAttribute('data-filter') || 'all');
          });
        }

        var searchInput = utils.get('redirect-search');
        if (searchInput) {
          searchInput.addEventListener('input', function () {
            redirect.setSearch(this.value);
          });
        }
      })();

      // --- Directory Fuzzing ---
      (function () {
        var urlInput = utils.get('fuzz-url');
        if (urlInput) {
          getActiveTab().then(function (tab) {
            if (tab && tab.url) urlInput.value = tab.url.replace(/\/+$/, '');
          });
        }
        chrome.storage.local.get(['pentestSettings'], function (result) {
          var s = result.pentestSettings || {};
          var wl = utils.get('fuzz-wordlist');
          if (wl && s.fuzzDefaultWordlist) wl.value = s.fuzzDefaultWordlist;
          var cc = utils.get('fuzz-concurrency');
          if (cc && s.fuzzDefaultConcurrency) cc.value = s.fuzzDefaultConcurrency;
        });

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
          if (pauseBtn) {
            pauseBtn.style.display = '';
            pauseBtn.innerHTML = '<span class="spinner"></span> 扫描中...';
          }
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
                  progressText.textContent =
                    s.completed + '/' + s.total + ' (发现 ' + s.found + ')';
              },
              function () {
                var container = utils.get('fuzz-results');
                if (container && container.querySelector('.empty-state')) {
                  container.innerHTML = '';
                }
              }
            );
            if (result) {
              var filterRow = utils.get('fuzz-filter-row');
              if (filterRow) filterRow.style.display = 'flex';
              fuzz.renderFuzzResults(result);
            }
          } catch (e) {
            console.debug('fuzz scan error:', e);
            utils.showToast('扫描出错: ' + (e.message || e), 'error');
          } finally {
            if (startBtn) startBtn.style.display = '';
            if (pauseBtn) {
              pauseBtn.style.display = 'none';
              pauseBtn.innerHTML = '暂停';
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

        var filterBtns = document.querySelectorAll('#fuzz-filter-row .filter-btn');
        for (var fi = 0; fi < filterBtns.length; fi++) {
          filterBtns[fi].addEventListener('click', function () {
            for (var fj = 0; fj < filterBtns.length; fj++)
              filterBtns[fj].classList.remove('active');
            this.classList.add('active');
            fuzz.setFilter(this.getAttribute('data-filter'));
          });
        }

        var fuzzSearch = utils.get('fuzz-search');
        if (fuzzSearch) {
          fuzzSearch.addEventListener('input', function () {
            fuzz.setSearch(this.value);
          });
        }

        utils.bindClick('fuzz-export-btn', function () {
          var format = (utils.get('fuzz-export-format') || {}).value || 'txt';
          fuzz.exportFuzzResults(format);
        });
      })();
    }
  );
}

export {
  initEncodingJwtCrypto,
  initRsaFaviconAsset,
  initGatherAndRules,
  initLinksHistoryMultiUrl,
  initExifAndSpoofing,
  initPayload,
  initXssAndSourcemap,
  initReport,
  initSecurityDetectors2,
};
