// vk-init-panels.js - Panel initialization functions (barrel)
// No static imports — each init function loads its own dependencies dynamically.
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import {
  initLinksHistoryMultiUrl,
  initExifAndSpoofing,
  initPayload,
  initXssAndSourcemap as _initXssAndSourcemap,
  initReport,
} from './vk-init-panel-tools.js';
import {
  initSecurityDetectors2 as _initSecurityDetectors2,
} from './vk-init-panel-security.js';

function bindFilterSearch(btnSelector, searchId, mod, opts) {
  var defaultFilter = (opts && opts.defaultFilter) != null ? opts.defaultFilter : 'all';
  var attr = (opts && opts.filterAttr) || 'data-filter';
  var btns = document.querySelectorAll(btnSelector);
  for (var i = 0; i < btns.length; i++) {
    btns[i].addEventListener('click', function () {
      for (var j = 0; j < btns.length; j++) btns[j].classList.remove('active');
      this.classList.add('active');
      mod.setFilter(this.getAttribute(attr) || defaultFilter);
    });
  }
  var searchEl = utils.get(searchId);
  if (searchEl)
    searchEl.addEventListener('input', function () {
      mod.setSearch(this.value);
    });
}

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
  Promise.all([import('./vk-gather.js'), import('./vk-source-loader.js')]).then(function (mods) {
    var gather = mods[0];
    var sourceLoader = mods[1];

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
    utils.bindClick('gather-rules-btn', function () {
      chrome.runtime.openOptionsPage();
    });
  });
}

function initSecurityDetectors2() {
  return _initSecurityDetectors2(bindFilterSearch);
}

function initXssAndSourcemap() {
  return _initXssAndSourcemap(bindFilterSearch);
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
