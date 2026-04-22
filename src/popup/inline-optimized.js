// VulnKit v5.0
(function () {
  'use strict';

  let currentCryptoAlgo = 'aes';
  let currentAssetSource = 'fofa';

  const utils = {
    cache: new Map(),
    get(id) {
      if (!this.cache.has(id)) {
        this.cache.set(id, document.getElementById(id));
      }
      return this.cache.get(id);
    },
    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },
    copyText(text) {
      navigator.clipboard.writeText(text).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    },
    showToast: (() => {
      let current = null;
      const types = ['success', 'error', 'warning', 'info'];
      return function (message, type, duration) {
        if (current && current.parentNode) current.parentNode.removeChild(current);
        current = document.createElement('div');
        current.className = 'toast toast-' + (types.includes(type) ? type : 'info');
        current.textContent = message;
        document.body.appendChild(current);
        requestAnimationFrame(() => {
          if (current) current.classList.add('toast-show');
        });
        setTimeout(() => {
          if (current) {
            current.classList.remove('toast-show');
            setTimeout(() => {
              if (current && current.parentNode) {
                current.parentNode.removeChild(current);
                current = null;
              }
            }, 200);
          }
        }, duration || 2000);
      };
    })(),
  };

  // Expose utils for external modules (e.g. vk-encoding.js)
  window.VulnKitUtils = utils;

  // ====== Encoding Tools (loaded from vk-encoding.js) ======
  const encoding = window.VulnKitEncoding;
  const ENCODING_NAMES = encoding.ENCODING_NAMES;
  const handleEncode = encoding.handleEncode;
  const handleDecode = encoding.handleDecode;
  const clearEncodingFields = encoding.clearEncodingFields;
  const switchEncodingTab = encoding.switchEncodingTab;

  // ====== Crypto (AES/DES/RC4/SM2/SM4/Bcrypt) ======
  function padOrTruncate(key, len) {
    if (!key) return key;
    key = key.toString();
    if (key.length >= len) return key.substring(0, len);
    while (key.length < len) key += '\0';
    return key;
  }

  function switchCryptoAlgo(algo) {
    currentCryptoAlgo = algo;
    document.querySelectorAll('.crypto-algo-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.algo === algo);
    });
    document.querySelectorAll('.crypto-algo-panel').forEach(function (p) {
      p.classList.remove('active');
    });
    var panel = utils.get('algo-' + algo);
    if (panel) panel.classList.add('active');
    var encBtn = utils.get('crypto-enc-btn');
    var decBtn = utils.get('crypto-dec-btn');
    var verifyBtn = utils.get('crypto-verify-btn');
    if (algo === 'bcrypt') {
      if (encBtn) encBtn.textContent = '生成哈希';
      if (decBtn) decBtn.classList.add('hidden');
      if (verifyBtn) verifyBtn.classList.remove('hidden');
    } else {
      if (encBtn) encBtn.textContent = '加密';
      if (decBtn) decBtn.classList.remove('hidden');
      if (verifyBtn) verifyBtn.classList.add('hidden');
    }
  }

  function toggleIvVisibility(algoMode, ivGroupId, algoKey) {
    var ivGroup = utils.get(ivGroupId);
    if (!ivGroup) return;
    var modeEl = utils.get(algoKey);
    var mode = modeEl ? modeEl.value : '';
    if (mode === 'ECB' || mode === 'ecb') {
      ivGroup.classList.add('hidden');
    } else {
      ivGroup.classList.remove('hidden');
    }
  }

  function doCryptoEncrypt() {
    var input = (utils.get('crypto-input') || {}).value || '';
    if (!input) {
      utils.showToast('请输入内容', 'warning');
      return;
    }
    var output = utils.get('crypto-output');
    if (!output) return;
    try {
      var result;
      switch (currentCryptoAlgo) {
        case 'aes':
          result = aesEncrypt(input);
          break;
        case 'des':
          result = desEncrypt(input);
          break;
        case 'rc4':
          result = rc4Encrypt(input);
          break;
        case 'sm2':
          result = sm2Encrypt(input);
          break;
        case 'sm4':
          result = sm4Encrypt(input);
          break;
        case 'bcrypt':
          result = bcryptHash(input);
          break;
        case 'rsa':
          rsaEncrypt(input)
            .then(function (r) {
              output.value = r;
              utils.showToast('加密成功', 'success');
            })
            .catch(function (e) {
              output.value = '错误: ' + e.message;
              utils.showToast('加密失败', 'error');
            });
          return;
        default:
          return;
      }
      output.value = result;
      utils.showToast('加密成功', 'success');
    } catch (e) {
      output.value = '错误: ' + e.message;
      utils.showToast('加密失败: ' + e.message, 'error');
    }
  }

  function doCryptoDecrypt() {
    var input = (utils.get('crypto-input') || {}).value || '';
    if (!input) {
      utils.showToast('请输入密文', 'warning');
      return;
    }
    var output = utils.get('crypto-output');
    if (!output) return;
    try {
      var result;
      switch (currentCryptoAlgo) {
        case 'aes':
          result = aesDecrypt(input);
          break;
        case 'des':
          result = desDecrypt(input);
          break;
        case 'rc4':
          result = rc4Decrypt(input);
          break;
        case 'sm2':
          result = sm2Decrypt(input);
          break;
        case 'sm4':
          result = sm4Decrypt(input);
          break;
        case 'rsa':
          rsaDecrypt(input)
            .then(function (r) {
              output.value = r;
              utils.showToast('解密成功', 'success');
            })
            .catch(function (e) {
              output.value = '错误: ' + e.message;
              utils.showToast('解密失败', 'error');
            });
          return;
        default:
          output.value = '该算法不支持解密';
          return;
      }
      output.value = result;
      utils.showToast('解密成功', 'success');
    } catch (e) {
      output.value = '错误: ' + e.message;
      utils.showToast('解密失败: ' + e.message, 'error');
    }
  }

  function doCryptoVerify() {
    var input = (utils.get('crypto-input') || {}).value || '';
    var hash = (utils.get('crypto-output') || {}).value || '';
    if (!input || !hash) {
      utils.showToast('请输入密码和哈希', 'warning');
      return;
    }
    if (currentCryptoAlgo !== 'bcrypt') return;
    try {
      var match = dcodeIO.bcrypt.compareSync(input, hash);
      utils.showToast(match ? '验证通过' : '验证失败', match ? 'success' : 'error');
    } catch (e) {
      utils.showToast('验证失败: ' + e.message, 'error');
    }
  }

  function aesEncrypt(input) {
    var mode = (utils.get('aes-mode') || {}).value || 'CBC';
    var keySize = parseInt((utils.get('aes-keysize') || {}).value) || 128;
    var padding = (utils.get('aes-padding') || {}).value || 'Pkcs7';
    var key = padOrTruncate((utils.get('aes-key') || {}).value, keySize / 8);
    if (!key || key.length < 1) throw new Error('请输入密钥');
    var opts = {
      mode: CryptoJS.mode[mode],
      padding: CryptoJS.pad[padding],
    };
    if (mode !== 'ECB') {
      var iv = padOrTruncate((utils.get('aes-iv') || {}).value, 16);
      opts.iv = CryptoJS.enc.Utf8.parse(iv);
    }
    var keyWA = CryptoJS.enc.Utf8.parse(key);
    var data = CryptoJS.enc.Utf8.parse(input);
    return CryptoJS.AES.encrypt(data, keyWA, opts).toString();
  }

  function aesDecrypt(input) {
    var mode = (utils.get('aes-mode') || {}).value || 'CBC';
    var keySize = parseInt((utils.get('aes-keysize') || {}).value) || 128;
    var padding = (utils.get('aes-padding') || {}).value || 'Pkcs7';
    var key = padOrTruncate((utils.get('aes-key') || {}).value, keySize / 8);
    if (!key || key.length < 1) throw new Error('请输入密钥');
    var opts = {
      mode: CryptoJS.mode[mode],
      padding: CryptoJS.pad[padding],
    };
    if (mode !== 'ECB') {
      var iv = padOrTruncate((utils.get('aes-iv') || {}).value, 16);
      opts.iv = CryptoJS.enc.Utf8.parse(iv);
    }
    var keyWA = CryptoJS.enc.Utf8.parse(key);
    var bytes = CryptoJS.AES.decrypt(input, keyWA, opts);
    return CryptoJS.enc.Utf8.stringify(bytes);
  }

  function desEncrypt(input) {
    var mode = (utils.get('des-mode') || {}).value || 'CBC';
    var padding = (utils.get('des-padding') || {}).value || 'Pkcs7';
    var key = padOrTruncate((utils.get('des-key') || {}).value, 8);
    if (!key || key.length < 8) throw new Error('密钥需 8 字符');
    var opts = { mode: CryptoJS.mode[mode], padding: CryptoJS.pad[padding] };
    if (mode !== 'ECB') {
      var iv = padOrTruncate((utils.get('des-iv') || {}).value, 8);
      opts.iv = CryptoJS.enc.Utf8.parse(iv);
    }
    return CryptoJS.DES.encrypt(
      CryptoJS.enc.Utf8.parse(input),
      CryptoJS.enc.Utf8.parse(key),
      opts
    ).toString();
  }

  function desDecrypt(input) {
    var mode = (utils.get('des-mode') || {}).value || 'CBC';
    var padding = (utils.get('des-padding') || {}).value || 'Pkcs7';
    var key = padOrTruncate((utils.get('des-key') || {}).value, 8);
    if (!key || key.length < 8) throw new Error('密钥需 8 字符');
    var opts = { mode: CryptoJS.mode[mode], padding: CryptoJS.pad[padding] };
    if (mode !== 'ECB') {
      var iv = padOrTruncate((utils.get('des-iv') || {}).value, 8);
      opts.iv = CryptoJS.enc.Utf8.parse(iv);
    }
    var bytes = CryptoJS.DES.decrypt(input, CryptoJS.enc.Utf8.parse(key), opts);
    return CryptoJS.enc.Utf8.stringify(bytes);
  }

  function rc4Encrypt(input) {
    var key = (utils.get('rc4-key') || {}).value || '';
    if (!key) throw new Error('请输入密钥');
    return CryptoJS.RC4.encrypt(CryptoJS.enc.Utf8.parse(input), key).toString();
  }

  function rc4Decrypt(input) {
    var key = (utils.get('rc4-key') || {}).value || '';
    if (!key) throw new Error('请输入密钥');
    var bytes = CryptoJS.RC4.decrypt(input, key);
    return CryptoJS.enc.Utf8.stringify(bytes);
  }

  function sm2Encrypt(input) {
    var pubKey = (utils.get('sm2-pubkey') || {}).value || '';
    if (!pubKey) throw new Error('请输入公钥');
    if (pubKey.length === 128) pubKey = '04' + pubKey;
    if (pubKey.length !== 130 || !pubKey.startsWith('04'))
      throw new Error('公钥格式错误（需 130 位十六进制，04 开头）');
    var cipherMode = parseInt((utils.get('sm2-cipher') || {}).value) || 1;
    return sm2.doEncrypt(
      input.split('').map(function (c) {
        return c.charCodeAt(0);
      }),
      pubKey,
      cipherMode
    );
  }

  function sm2Decrypt(input) {
    var priKey = (utils.get('sm2-prikey') || {}).value || '';
    if (!priKey) throw new Error('请输入私钥');
    var cipherMode = parseInt((utils.get('sm2-cipher') || {}).value) || 1;
    var decrypted = sm2.doDecrypt(input, priKey, cipherMode, { output: 'array' });
    if (!decrypted) throw new Error('解密失败，请检查密钥和密文');
    return decrypted
      .map(function (c) {
        return String.fromCharCode(c);
      })
      .join('');
  }

  function sm4Encrypt(input) {
    var key = (utils.get('sm4-key') || {}).value || '';
    if (!key || key.length !== 16) throw new Error('密钥需 16 字符');
    var isCbc = (utils.get('sm4-mode') || {}).value === 'cbc';
    var usePadding = (utils.get('sm4-padding') || {}).checked !== false;
    var keyHex = Array.from(key)
      .map(function (c) {
        return c.charCodeAt(0).toString(16).padStart(2, '0');
      })
      .join('');
    var iv = '';
    if (isCbc) {
      var ivVal = (utils.get('sm4-iv') || {}).value || '';
      iv = Array.from(ivVal)
        .map(function (c) {
          return c.charCodeAt(0).toString(16).padStart(2, '0');
        })
        .join('');
    }
    return sm4.encrypt(input, keyHex, {
      padding: usePadding ? 'pkcs#5' : 'none',
      mode: isCbc ? 'cbc' : undefined,
      iv: isCbc ? iv : undefined,
    });
  }

  function sm4Decrypt(input) {
    var key = (utils.get('sm4-key') || {}).value || '';
    if (!key || key.length !== 16) throw new Error('密钥需 16 字符');
    var isCbc = (utils.get('sm4-mode') || {}).value === 'cbc';
    var usePadding = (utils.get('sm4-padding') || {}).checked !== false;
    var keyHex = Array.from(key)
      .map(function (c) {
        return c.charCodeAt(0).toString(16).padStart(2, '0');
      })
      .join('');
    var iv = '';
    if (isCbc) {
      var ivVal = (utils.get('sm4-iv') || {}).value || '';
      iv = Array.from(ivVal)
        .map(function (c) {
          return c.charCodeAt(0).toString(16).padStart(2, '0');
        })
        .join('');
    }
    return sm4.decrypt(input, keyHex, {
      padding: usePadding ? 'pkcs#5' : 'none',
      mode: isCbc ? 'cbc' : undefined,
      iv: isCbc ? iv : undefined,
    });
  }

  function bcryptHash(input) {
    var rounds = parseInt((utils.get('bcrypt-rounds') || {}).value) || 10;
    var salt = dcodeIO.bcrypt.genSaltSync(rounds);
    return dcodeIO.bcrypt.hashSync(input, salt);
  }

  function rsaEncrypt(input) {
    var pubKeyStr = (utils.get('rsa-pubkey') || {}).value || '';
    if (!pubKeyStr) throw new Error('请先生成密钥对');
    return window.crypto.subtle
      .importKey(
        'spki',
        pemToArrayBuffer(pubKeyStr),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      )
      .then(function (pubKey) {
        return window.crypto.subtle.encrypt(
          { name: 'RSA-OAEP' },
          pubKey,
          new TextEncoder().encode(input)
        );
      })
      .then(function (buf) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
      });
  }

  function rsaDecrypt(input) {
    var priKeyStr = (utils.get('rsa-prikey') || {}).value || '';
    if (!priKeyStr) throw new Error('请先生成密钥对');
    return window.crypto.subtle
      .importKey(
        'pkcs8',
        pemToArrayBuffer(priKeyStr),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['decrypt']
      )
      .then(function (priKey) {
        var bin = atob(input);
        var buf = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priKey, buf);
      })
      .then(function (buf) {
        return new TextDecoder().decode(buf);
      });
  }

  function rsaGenerateKeyPair() {
    var keySize = parseInt((utils.get('rsa-keysize') || {}).value) || 2048;
    var btn = utils.get('rsa-genkey-btn');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '生成中...';
    }
    window.crypto.subtle
      .generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: keySize,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      )
      .then(function (keyPair) {
        return Promise.all([
          window.crypto.subtle.exportKey('spki', keyPair.publicKey),
          window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
        ]);
      })
      .then(function (results) {
        var pubEl = utils.get('rsa-pubkey');
        var priEl = utils.get('rsa-prikey');
        if (pubEl) pubEl.value = ab2pem(results[0], 'PUBLIC KEY');
        if (priEl) priEl.value = ab2pem(results[1], 'PRIVATE KEY');
        if (btn) {
          btn.disabled = false;
          btn.textContent = '生成密钥对';
        }
        utils.showToast(keySize + ' 位密钥对已生成', 'success');
      })
      .catch(function (e) {
        if (btn) {
          btn.disabled = false;
          btn.textContent = '生成密钥对';
        }
        utils.showToast('生成失败', 'error');
      });
  }

  function ab2pem(buffer, label) {
    var b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
    var lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----';
  }

  function pemToArrayBuffer(pem) {
    var b64 = pem
      .replace(/-----BEGIN [A-Z ]+-----/, '')
      .replace(/-----END [A-Z ]+-----/, '')
      .replace(/\s/g, '');
    var bin = atob(b64);
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  // ====== Favicon (loaded from vk-favicon.js) ======
  const extractFavicon = window.VulnKitFavicon.extractFavicon;

  // ====== Asset Mapping (loaded from vk-asset.js) ======
  const {
    handleAssetScan,
    switchAssetSource,
    shodanHostLookup,
    saveApiKeys,
    loadApiKeys,
    clearApiKeys,
  } = window.VulnKitAsset;
  Object.defineProperties(window, {
    currentAssetSource: {
      get: () => window.VulnKitAsset.currentAssetSource,
      set: v => {
        window.VulnKitAsset.currentAssetSource = v;
      },
      configurable: true,
    },
  });
  async function getCurrentDomain() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    try {
      return new URL(tab.url).hostname;
    } catch {
      return null;
    }
  }

  // ====== URL Multi-Open (loaded from vk-multiurl.js) ======
  const { parseUrls, updateMultiurlInfo, handleMultiurlOpen, handleMultiurlDedup } =
    window.VulnKitMultiUrl;

  // ====== Tab Save ======
  var savedTabUrls = [];

  async function grabAllTabs() {
    var grabBtn = utils.get('tabsave-grab-btn');
    var copyBtn = utils.get('tabsave-copy-btn');
    var exportBtn = utils.get('tabsave-export-btn');
    var statusEl = utils.get('tabsave-status');
    if (grabBtn) grabBtn.disabled = true;
    if (statusEl) statusEl.textContent = '正在获取...';

    try {
      var tabs = await chrome.tabs.query({});
      savedTabUrls = tabs
        .map(function (t) {
          try {
            var u = new URL(t.url);
            if (
              u.protocol === 'chrome:' ||
              u.protocol === 'chrome-extension:' ||
              u.protocol === 'about:' ||
              u.protocol === 'edge:'
            )
              return null;
            return { url: t.url, title: t.title || '', id: t.id };
          } catch (e) {
            return null;
          }
        })
        .filter(Boolean);

      // Dedup by url
      var seen = {};
      savedTabUrls = savedTabUrls.filter(function (t) {
        if (seen[t.url]) return false;
        seen[t.url] = true;
        return true;
      });

      if (statusEl) statusEl.textContent = '已获取 ' + savedTabUrls.length + ' 个标签页（已去重）';
      if (copyBtn) copyBtn.disabled = false;
      if (exportBtn) exportBtn.disabled = false;
      utils.showToast('已获取 ' + savedTabUrls.length + ' 个标签页', 'success');
    } catch (e) {
      if (statusEl) statusEl.textContent = '获取失败';
      utils.showToast('获取失败: ' + e.message, 'error');
    }
    if (grabBtn) grabBtn.disabled = false;
  }

  function copySavedTabUrls() {
    if (savedTabUrls.length === 0) {
      utils.showToast('请先获取标签页', 'warning');
      return;
    }
    var text = savedTabUrls
      .map(function (t) {
        return t.url;
      })
      .join('\n');
    utils.copyText(text);
    utils.showToast('已复制 ' + savedTabUrls.length + ' 个 URL', 'success');
  }

  function exportSavedTabUrls() {
    if (savedTabUrls.length === 0) {
      utils.showToast('请先获取标签页', 'warning');
      return;
    }
    var lines = savedTabUrls.map(function (t) {
      return t.title + '\n' + t.url;
    });
    var text = lines.join('\n\n');
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    var now = new Date();
    var ts =
      now.getFullYear() +
      '-' +
      String(now.getMonth() + 1).padStart(2, '0') +
      '-' +
      String(now.getDate()).padStart(2, '0') +
      '_' +
      String(now.getHours()).padStart(2, '0') +
      String(now.getMinutes()).padStart(2, '0');
    a.download = 'tabs_' + ts + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    utils.showToast('已导出 tabs_' + ts + '.txt', 'success');
  }

  // ====== Info Gather (loaded from vk-gather.js) ======
  const gather = window.VulnKitGather;
  let gatherData;
  let currentGatherTab;
  Object.defineProperties(
    {},
    {
      gatherData: {
        get() {
          return gather;
        },
        set(v) {
          gatherData = v;
        },
        enumerable: true,
      },
      currentGatherTab: {
        get() {
          return currentGatherTab;
        },
        set(v) {
          currentGatherTab = v;
        },
        enumerable: true,
      },
    }
  );
  const renderGatherTab = gather.renderGatherTab.bind(gather);
  const switchGatherTab = gather.switchGatherTab.bind(gather);
  const gatherInfo = gather.gatherInfo.bind(gather);

  // ====== Link Extract (loaded from vk-links.js) ======
  const { extractLinks, getFilteredLinks, renderLinks } = window.VulnKitLinks;
  Object.defineProperties(window, {
    allLinks: {
      get: () => window.VulnKitLinks.allLinks,
      set: v => {
        window.VulnKitLinks.allLinks = v;
      },
      configurable: true,
    },
  });

  // ====== EXIF Viewer (loaded from vk-exif.js) ======
  const { initExifDragDrop, switchExifMode, fetchExifFromUrl, scanPageImages, checkExifPending } =
    window.VulnKitExif;
  Object.defineProperties(window, {
    lastExifData: {
      get: () => window.VulnKitExif.lastExifData,
      set: v => {
        window.VulnKitExif.lastExifData = v;
      },
      configurable: true,
    },
  });

  // ====== History Archive (loaded from vk-history.js) ======
  const {
    showHistoryQuickLinks,
    buildCdxUrl,
    filterByType,
    extractDomain,
    queryHistory,
    renderHistoryResults,
  } = window.VulnKitHistory;
  Object.defineProperties(window, {
    lastHistoryResults: {
      get: () => window.VulnKitHistory.lastHistoryResults,
      set: v => {
        window.VulnKitHistory.lastHistoryResults = v;
      },
      configurable: true,
    },
  });

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
    clearAllCookies,
    applyHeaders,
    addCustomHeaderRow,
    resetHeaders,
  } = window.VulnKitSpoof;
  const spoofState = window.VulnKitSpoof.spoofState;
  Object.defineProperties(window, {
    currentSpoofTab: {
      get: () => window.VulnKitSpoof.currentSpoofTab,
      set: v => {
        window.VulnKitSpoof.currentSpoofTab = v;
      },
      configurable: true,
    },
  });


  // ====== Vue Analysis (loaded from vk-vue.js) ======
  const vue = window.VulnKitVue;
  const {
    detectVue,
    exportVueRoutes,
    bypassVueGuards,
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
    extractPathsFromJsResults,
    autoFillFromJsPaths,
    extractKeywordsFromCapturedUrls,
    autoSearchForZeroOpen,
    compareRoutesAndMenu,
    startTraverseRoutes,
    stopTraverse,
    autoInjectHiddenRoutes,
    renderPermList,
    startPermAutoRefresh,
    stopPermAutoRefresh,
  } = vue;

  Object.defineProperties(window, {
    lastVueResult: {
      get() { return vue.lastVueResult; },
      set(v) { vue.lastVueResult = v; },
      configurable: true,
    },
    permInterceptActive: {
      get() { return vue.permInterceptActive; },
      set(v) { vue.permInterceptActive = v; },
      configurable: true,
    },
    permCapturedData: {
      get() { return vue.permCapturedData; },
      set(v) { vue.permCapturedData = v; },
      configurable: true,
    },
    permSelectedIndex: {
      get() { return vue.permSelectedIndex; },
      set(v) { vue.permSelectedIndex = v; },
      configurable: true,
    },
    permViewMode: {
      get() { return vue.permViewMode; },
      set(v) { vue.permViewMode = v; },
      configurable: true,
    },
  });

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

  Object.defineProperties(window, {
    jsBlocked: {
      get() { return jsCtrl.jsBlocked; },
      set(v) { jsCtrl.jsBlocked = v; },
      configurable: true,
    },
  });


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
  } = window.VulnKitXss;
  Object.defineProperties(window, {
    xssPoints: {
      get: () => window.VulnKitXss.xssPoints,
      set: v => {
        window.VulnKitXss.xssPoints = v;
      },
      configurable: true,
    },
    xssFilterType: {
      get: () => window.VulnKitXss.xssFilterType,
      set: v => {
        window.VulnKitXss.xssFilterType = v;
      },
      configurable: true,
    },
  });

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
  } = sourcemap;

  Object.defineProperties(window, {
    sourcemapSearchTerm: {
      get() { return sourcemap.sourcemapSearchTerm; },
      set(v) { sourcemap.sourcemapSearchTerm = v; },
      configurable: true,
    },
    sourcemapCurrentModule: {
      get() { return sourcemap.sourcemapCurrentModule; },
      set(v) { sourcemap.sourcemapCurrentModule = v; },
      configurable: true,
    },
  });


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

    var scrollLeftBtn = utils.get('tab-scroll-left');
    var scrollRightBtn = utils.get('tab-scroll-right');
    if (scrollLeftBtn) {
      scrollLeftBtn.addEventListener('click', function () {
        if (currentPage > 0) showTabPage(currentPage - 1);
      });
    }
    if (scrollRightBtn) {
      scrollRightBtn.addEventListener('click', function () {
        if (currentPage < totalPages - 1) showTabPage(currentPage + 1);
      });
    }
    showTabPage(0);

    // Main panel tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const panel = btn.dataset.panel;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('panel-' + panel);
        if (target) target.classList.add('active');
        utils.get('status-text').textContent = btn.textContent;
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
      {
        id: 'copy-encoding-btn',
        handler: () => {
          const v = utils.get('encoding-output').value;
          if (!v) {
            utils.showToast('没有可复制的内容', 'warning');
            return;
          }
          utils.copyText(v);
          utils.showToast('已复制', 'success');
        },
      },
    ];
    encodingBindings.forEach(({ id, handler }) => {
      const el = utils.get(id);
      if (el) el.addEventListener('click', handler);
    });

    // Crypto algo tabs
    document.querySelectorAll('.crypto-algo-btn').forEach(function (btn) {
      if (btn.dataset.algo)
        btn.addEventListener('click', function () {
          switchCryptoAlgo(btn.dataset.algo);
        });
    });

    // Crypto action buttons
    var cryptoEncBtn = utils.get('crypto-enc-btn');
    if (cryptoEncBtn) cryptoEncBtn.addEventListener('click', doCryptoEncrypt);
    var cryptoDecBtn = utils.get('crypto-dec-btn');
    if (cryptoDecBtn) cryptoDecBtn.addEventListener('click', doCryptoDecrypt);
    var cryptoVerifyBtn = utils.get('crypto-verify-btn');
    if (cryptoVerifyBtn) cryptoVerifyBtn.addEventListener('click', doCryptoVerify);
    var cryptoClearBtn = utils.get('crypto-clear-btn');
    if (cryptoClearBtn)
      cryptoClearBtn.addEventListener('click', function () {
        var ci = utils.get('crypto-input');
        if (ci) ci.value = '';
        var co = utils.get('crypto-output');
        if (co) co.value = '';
      });
    var copyCryptoBtn = utils.get('copy-crypto-btn');
    if (copyCryptoBtn)
      copyCryptoBtn.addEventListener('click', function () {
        var v = (utils.get('crypto-output') || {}).value;
        if (v) {
          utils.copyText(v);
          utils.showToast('已复制', 'success');
        }
      });

    // Crypto mode/IV toggle listeners
    var aesMode = utils.get('aes-mode');
    if (aesMode)
      aesMode.addEventListener('change', function () {
        toggleIvVisibility('aes', 'aes-iv-group', 'aes-mode');
      });
    var desMode = utils.get('des-mode');
    if (desMode)
      desMode.addEventListener('change', function () {
        toggleIvVisibility('des', 'des-iv-group', 'des-mode');
      });
    var sm4Mode = utils.get('sm4-mode');
    if (sm4Mode)
      sm4Mode.addEventListener('change', function () {
        var ivG = utils.get('sm4-iv-group');
        if (ivG) {
          if (sm4Mode.value === 'cbc') ivG.classList.remove('hidden');
          else ivG.classList.add('hidden');
        }
      });

    // SM2 generate keypair
    var sm2GenBtn = utils.get('sm2-genkey-btn');
    if (sm2GenBtn)
      sm2GenBtn.addEventListener('click', function () {
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
    var rsaGenBtn = utils.get('rsa-genkey-btn');
    if (rsaGenBtn) rsaGenBtn.addEventListener('click', rsaGenerateKeyPair);

    // Favicon buttons
    const faviconBtn = utils.get('extract-favicon-btn');
    if (faviconBtn) faviconBtn.addEventListener('click', extractFavicon);

    const copyHashBtn = utils.get('copy-favicon-hash-btn');
    if (copyHashBtn)
      copyHashBtn.addEventListener('click', () => {
        const hash = utils.get('favicon-hash').textContent;
        if (hash === '-') {
          utils.showToast('请先提取图标', 'warning');
          return;
        }
        utils.copyText(hash);
        utils.showToast('已复制 Hash', 'success');
      });

    // Asset mapping
    document.querySelectorAll('.source-btn').forEach(btn => {
      btn.addEventListener('click', () => switchAssetSource(btn.dataset.source));
    });

    const scanBtn = utils.get('asset-scan-btn');
    if (scanBtn) scanBtn.addEventListener('click', handleAssetScan);

    const shodanHostBtn = utils.get('shodan-host-btn');
    if (shodanHostBtn) shodanHostBtn.addEventListener('click', shodanHostLookup);

    const saveKeysBtn = utils.get('save-keys-btn');
    if (saveKeysBtn) saveKeysBtn.addEventListener('click', saveApiKeys);

    const clearKeysBtn = utils.get('clear-keys-btn');
    if (clearKeysBtn) clearKeysBtn.addEventListener('click', clearApiKeys);

    loadApiKeys();

    // Info gather
    document.querySelectorAll('.gather-tab').forEach(btn => {
      btn.addEventListener('click', () => switchGatherTab(btn.dataset.gather));
    });
    const gatherBtn = utils.get('gather-btn');
    if (gatherBtn) gatherBtn.addEventListener('click', gatherInfo);
    const gatherCopyBtn = utils.get('gather-copy-btn');
    if (gatherCopyBtn) {
      gatherCopyBtn.addEventListener('click', () => {
        const list = gatherData[currentGatherTab] || [];
        if (list.length === 0) {
          utils.showToast('没有可复制的内容', 'warning');
          return;
        }
        const text = list.map(i => i.value).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + list.length + ' 条', 'success');
      });
    }

    // Link extract
    const linksExtractBtn = utils.get('links-extract-btn');
    if (linksExtractBtn) linksExtractBtn.addEventListener('click', extractLinks);
    const linksCopyBtn = utils.get('links-copy-btn');
    if (linksCopyBtn) {
      linksCopyBtn.addEventListener('click', () => {
        const filtered = getFilteredLinks();
        if (filtered.length === 0) {
          utils.showToast('没有链接', 'warning');
          return;
        }
        utils.copyText(filtered.map(l => l.href).join('\n'));
        utils.showToast('已复制 ' + filtered.length + ' 个链接', 'success');
      });
    }
    const linksSendBtn = utils.get('links-send-multiurl-btn');
    if (linksSendBtn) {
      linksSendBtn.addEventListener('click', () => {
        const filtered = getFilteredLinks().filter(l => !l.isMailto && !l.isJS);
        if (filtered.length === 0) {
          utils.showToast('没有可发送的链接', 'warning');
          return;
        }
        utils.get('multiurl-input').value = filtered.map(l => l.href).join('\n');
        updateMultiurlInfo(filtered.length);
        document
          .querySelectorAll('.tab-btn')
          .forEach(b => b.classList.toggle('active', b.dataset.panel === 'multiurl'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById('panel-multiurl').classList.add('active');
        utils.showToast('已发送 ' + filtered.length + ' 个链接', 'success');
      });
    }
    const linksFilter = utils.get('links-filter');
    if (linksFilter) linksFilter.addEventListener('input', renderLinks);
    const linksFilterType = utils.get('links-filter-type');
    if (linksFilterType) linksFilterType.addEventListener('change', renderLinks);

    // URL multi-open
    const multiurlInput = utils.get('multiurl-input');
    if (multiurlInput) {
      multiurlInput.addEventListener('input', () => updateMultiurlInfo(parseUrls().length));
    }
    const multiurlOpenBtn = utils.get('multiurl-open-btn');
    if (multiurlOpenBtn) multiurlOpenBtn.addEventListener('click', handleMultiurlOpen);
    const multiurlDedupBtn = utils.get('multiurl-dedup-btn');
    if (multiurlDedupBtn) multiurlDedupBtn.addEventListener('click', handleMultiurlDedup);
    const multiurlClearBtn = utils.get('multiurl-clear-btn');
    if (multiurlClearBtn)
      multiurlClearBtn.addEventListener('click', () => {
        utils.get('multiurl-input').value = '';
        updateMultiurlInfo(0);
      });

    // Tab save
    const tabsaveGrabBtn = utils.get('tabsave-grab-btn');
    if (tabsaveGrabBtn) tabsaveGrabBtn.addEventListener('click', grabAllTabs);
    const tabsaveCopyBtn = utils.get('tabsave-copy-btn');
    if (tabsaveCopyBtn) tabsaveCopyBtn.addEventListener('click', copySavedTabUrls);
    const tabsaveExportBtn = utils.get('tabsave-export-btn');
    if (tabsaveExportBtn) tabsaveExportBtn.addEventListener('click', exportSavedTabUrls);

    // History
    const historyBtn = utils.get('history-query-btn');
    if (historyBtn) historyBtn.addEventListener('click', queryHistory);

    const historyCopyUrlBtn = utils.get('history-copy-url-btn');
    if (historyCopyUrlBtn) {
      historyCopyUrlBtn.addEventListener('click', async () => {
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
        utils.copyText(cdxUrl);
        utils.showToast('查询URL已复制', 'success');
      });
    }

    const historyDomainInput = utils.get('history-domain');
    if (historyDomainInput) {
      historyDomainInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') queryHistory();
      });
      historyDomainInput.addEventListener('blur', () => {
        const val = historyDomainInput.value.trim();
        if (val) showHistoryQuickLinks(val);
      });

      // Auto-fill domain when switching to history panel
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          if (btn.dataset.panel === 'history') {
            if (!historyDomainInput.value.trim()) {
              getCurrentDomain().then(d => {
                if (d) historyDomainInput.value = d;
              });
            }
          }
        });
      });
    }

    const historyCopyResultBtn = utils.get('history-copy-result-btn');
    if (historyCopyResultBtn) {
      historyCopyResultBtn.addEventListener('click', () => {
        if (lastHistoryResults.length === 0) {
          utils.showToast('没有结果', 'warning');
          return;
        }
        const text = lastHistoryResults.map(i => i.raw || i.url).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + lastHistoryResults.length + ' 条', 'success');
      });
    }

    const historyTypeFilter = utils.get('history-type-filter');
    if (historyTypeFilter) {
      historyTypeFilter.addEventListener('input', () => {
        if (lastHistoryResults.length === 0) return;
        const filtered = filterByType(lastHistoryResults, historyTypeFilter.value);
        renderHistoryResults(filtered);
        utils.get('history-status').textContent =
          '筛选: ' + filtered.length + ' / ' + lastHistoryResults.length + ' 条';
      });
    }

    const historyCopyFilteredBtn = utils.get('history-copy-filtered-btn');
    if (historyCopyFilteredBtn) {
      historyCopyFilteredBtn.addEventListener('click', () => {
        if (lastHistoryResults.length === 0) {
          utils.showToast('没有结果', 'warning');
          return;
        }
        const typeFilter = historyTypeFilter ? historyTypeFilter.value : '';
        const filtered = filterByType(lastHistoryResults, typeFilter);
        if (filtered.length === 0) {
          utils.showToast('没有匹配的结果', 'warning');
          return;
        }
        const text = filtered.map(i => i.raw || i.url).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + filtered.length + ' 条', 'success');
      });
    }

    const historySendLinksBtn = utils.get('history-send-links-btn');
    if (historySendLinksBtn) {
      historySendLinksBtn.addEventListener('click', () => {
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
        document.getElementById('panel-multiurl').classList.add('active');
        utils.showToast('已发送 ' + urls.length + ' 个链接', 'success');
      });
    }

    // EXIF viewer
    initExifDragDrop();
    checkExifPending();

    document.querySelectorAll('.exif-mode-btn').forEach(btn => {
      btn.addEventListener('click', () => switchExifMode(btn.dataset.mode));
    });

    const exifFetchBtn = utils.get('exif-fetch-btn');
    if (exifFetchBtn) {
      const handler = () => {
        const url = utils.get('exif-url-input').value.trim();
        if (!url) {
          utils.showToast('请输入图片URL', 'warning');
          return;
        }
        fetchExifFromUrl(url);
      };
      exifFetchBtn.addEventListener('click', handler);
      utils.get('exif-url-input')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') handler();
      });
    }

    const exifScanBtn = utils.get('exif-scan-page-btn');
    if (exifScanBtn) exifScanBtn.addEventListener('click', scanPageImages);

    const exifCopyAllBtn = utils.get('exif-copy-all-btn');
    if (exifCopyAllBtn) {
      exifCopyAllBtn.addEventListener('click', () => {
        if (!lastExifData) {
          utils.showToast('没有元数据', 'warning');
          return;
        }
        const text = Object.entries(lastExifData)
          .map(([k, v]) => k + ': ' + v)
          .join('\n');
        utils.copyText(text);
        utils.showToast('已复制全部元数据', 'success');
      });
    }

    // Request Spoofing
    document.querySelectorAll('.spoof-tab').forEach(btn => {
      btn.addEventListener('click', () => switchSpoofTab(btn.dataset.spoof));
    });

    const uaCategoryEl = utils.get('ua-category');
    if (uaCategoryEl) {
      uaCategoryEl.addEventListener('change', () => renderUaList(uaCategoryEl.value));
      renderUaList('desktop');
    }

    const uaApplyBtn = utils.get('spoof-ua-apply');
    if (uaApplyBtn) uaApplyBtn.addEventListener('click', applyUserAgent);
    const uaResetBtn = utils.get('spoof-ua-reset');
    if (uaResetBtn) uaResetBtn.addEventListener('click', resetUserAgent);

    const cookieRefreshBtn = utils.get('cookie-refresh-btn');
    if (cookieRefreshBtn) cookieRefreshBtn.addEventListener('click', loadCookies);
    const cookieAddBtn = utils.get('cookie-add-btn');
    if (cookieAddBtn) cookieAddBtn.addEventListener('click', showCookieAddEditor);
    const cookieImportBtn = utils.get('cookie-import-btn');
    if (cookieImportBtn) cookieImportBtn.addEventListener('click', showCookieImportDialog);
    const cookieClearBtn = utils.get('cookie-clear-btn');
    if (cookieClearBtn) cookieClearBtn.addEventListener('click', clearAllCookies);

    const headerApplyBtn = utils.get('header-apply');
    if (headerApplyBtn) headerApplyBtn.addEventListener('click', applyHeaders);
    const headerResetBtn = utils.get('header-reset');
    if (headerResetBtn) headerResetBtn.addEventListener('click', resetHeaders);
    const customHeaderAddBtn = utils.get('custom-header-add');
    if (customHeaderAddBtn) customHeaderAddBtn.addEventListener('click', addCustomHeaderRow);

    const initialRemoveBtn = document.querySelector('.custom-header-remove');
    if (initialRemoveBtn)
      initialRemoveBtn.addEventListener('click', function () {
        this.closest('.custom-header-row').remove();
      });

    const refererPresetEl = utils.get('referer-preset');
    if (refererPresetEl) {
      refererPresetEl.addEventListener('change', () => {
        const v = refererPresetEl.value;
        const refererInput = utils.get('header-referer');
        if (!refererInput) return;
        if (v === 'none') refererInput.value = '';
        else if (v === 'google') refererInput.value = 'https://www.google.com/';
        else if (v === 'baidu') refererInput.value = 'https://www.baidu.com/';
        else if (v === 'same') refererInput.value = '';
      });
    }

    chrome.storage.local.get(['pentest_spoof'], result => {
      const saved = result.pentest_spoof;
      if (saved) {
        if (saved.ua) Object.assign(spoofState.ua, saved.ua);
        if (saved.headers) Object.assign(spoofState.headers, saved.headers);
        updateUaStatus();
      }
    });

    // Vue Analysis
    const vueDetectBtn = utils.get('vue-detect-btn');
    if (vueDetectBtn) vueDetectBtn.addEventListener('click', detectVue);
    const vueExportBtn = utils.get('vue-export-routes-btn');
    if (vueExportBtn) vueExportBtn.addEventListener('click', exportVueRoutes);
    const vueBypassBtn = utils.get('vue-bypass-guards-btn');
    if (vueBypassBtn) vueBypassBtn.addEventListener('click', bypassVueGuards);
    const vueCopyBtn = utils.get('vue-copy-btn');
    if (vueCopyBtn) {
      vueCopyBtn.addEventListener('click', () => {
        if (!lastVueResult) {
          utils.showToast('没有可复制的内容', 'warning');
          return;
        }
        utils.copyText(lastVueResult);
        utils.showToast('已复制', 'success');
      });
    }

    // Vue sub-tabs
    document.querySelectorAll('.vue-stab').forEach(btn => {
      btn.addEventListener('click', () => switchVueSubTab(btn.dataset.vstab));
    });

    // Permission menu interception
    const permStartBtn = utils.get('perm-start-btn');
    if (permStartBtn) permStartBtn.addEventListener('click', startPermInterception);
    const permStopBtn = utils.get('perm-stop-btn');
    if (permStopBtn) permStopBtn.addEventListener('click', stopPermInterception);
    const permRefreshBtn = utils.get('perm-refresh-btn');
    if (permRefreshBtn) permRefreshBtn.addEventListener('click', refreshPermCaptured);
    const permFilter = utils.get('perm-filter');
    if (permFilter) permFilter.addEventListener('input', renderPermList);
    const permTypeFilter = utils.get('perm-type-filter');
    if (permTypeFilter) permTypeFilter.addEventListener('change', renderPermList);
    const permDetailBack = utils.get('perm-detail-back');
    if (permDetailBack)
      permDetailBack.addEventListener('click', () => {
        permViewMode = 'list';
        utils.get('perm-captured-list').classList.remove('hidden');
        const filterRow = utils.get('perm-filter-row');
        if (filterRow) filterRow.classList.remove('hidden');
        utils.get('perm-detail').classList.add('hidden');
      });
    const permOpenAllBtn = utils.get('perm-open-all');
    if (permOpenAllBtn) permOpenAllBtn.addEventListener('click', permOpenAll);
    const permChangeAdminBtn = utils.get('perm-change-admin');
    if (permChangeAdminBtn) permChangeAdminBtn.addEventListener('click', permChangeAdmin);
    const permApplyBtn = utils.get('perm-apply-btn');
    if (permApplyBtn) permApplyBtn.addEventListener('click', applyPermOverride);
    const permCopyJsonBtn = utils.get('perm-copy-json');
    if (permCopyJsonBtn)
      permCopyJsonBtn.addEventListener('click', () => {
        const val = utils.get('perm-json-editor').value;
        if (!val) {
          utils.showToast('没有数据', 'warning');
          return;
        }
        utils.copyText(val);
        utils.showToast('已复制', 'success');
      });

    const permExpandIdsBtn = utils.get('perm-expand-ids');
    if (permExpandIdsBtn) permExpandIdsBtn.addEventListener('click', permExpandMenuIds);

    const compareInjectBtn = utils.get('compare-inject-btn');
    if (compareInjectBtn)
      compareInjectBtn.addEventListener('click', () => {
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
    const jssearchBtn = utils.get('jssearch-btn');
    if (jssearchBtn)
      jssearchBtn.addEventListener('click', () => {
        searchJsKeywords(utils.get('jssearch-keyword').value.trim());
      });
    const jssearchInput = utils.get('jssearch-keyword');
    if (jssearchInput)
      jssearchInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') searchJsKeywords(jssearchInput.value.trim());
      });
    document.querySelectorAll('.jssearch-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.get('jssearch-keyword').value = btn.dataset.kw;
        searchJsKeywords(btn.dataset.kw);
      });
    });

    // Route vs menu comparison
    const compareBtn = utils.get('compare-btn');
    if (compareBtn) compareBtn.addEventListener('click', compareRoutesAndMenu);
    const compareCopyHidden = utils.get('compare-copy-hidden');
    if (compareCopyHidden)
      compareCopyHidden.addEventListener('click', () => {
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
    const traverseStartBtn = utils.get('traverse-start-btn');
    if (traverseStartBtn) traverseStartBtn.addEventListener('click', startTraverseRoutes);
    const traverseStopBtn = utils.get('traverse-stop-btn');
    if (traverseStopBtn) traverseStopBtn.addEventListener('click', stopTraverse);

    // JS Control
    document.querySelectorAll('.jsctrl-tab').forEach(btn => {
      btn.addEventListener('click', () => switchJsCtrlTab(btn.dataset.ctrl));
    });
    const jsDisableBtn = utils.get('js-disable-btn');
    if (jsDisableBtn) jsDisableBtn.addEventListener('click', disableJs);
    const jsEnableBtn = utils.get('js-enable-btn');
    if (jsEnableBtn) jsEnableBtn.addEventListener('click', enableJs);
    const antidebugScanBtn = utils.get('antidebug-scan-btn');
    if (antidebugScanBtn) antidebugScanBtn.addEventListener('click', scanAntiDebug);
    const antidebugBypassBtn = utils.get('antidebug-bypass-btn');
    if (antidebugBypassBtn) antidebugBypassBtn.addEventListener('click', bypassAntiDebug);
    const antidebugClearBtn = utils.get('antidebug-clear-btn');
    if (antidebugClearBtn) antidebugClearBtn.addEventListener('click', clearScriptBlock);

    // Remove copy restrictions
    const uncopyBtn = utils.get('uncopy-btn');
    if (uncopyBtn) uncopyBtn.addEventListener('click', removeCopyRestrictions);

    // Restore perm intercept state
    chrome.storage.local.get(['permInterceptTabId'], result => {
      if (result.permInterceptTabId) {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          if (tabs[0] && tabs[0].id === result.permInterceptTabId) {
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
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          if (tabs[0] && tabs[0].id === result.js_blocked_tabId) {
            jsBlocked = true;
            updateJsToggleStatus();
          } else {
            chrome.storage.local.remove('js_blocked_tabId');
          }
        });
      }
    });

    // Restore gather data for current tab
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const currentUrl = tabs[0]?.url || '';
      chrome.storage.local.get(['gatherData', 'gatherDataUrl'], result => {
        if (result.gatherData && result.gatherDataUrl === currentUrl) {
          gatherData = result.gatherData;
          renderGatherTab();
          const total = Object.values(gatherData).reduce((s, a) => s + a.length, 0);
          const statusEl = utils.get('gather-status');
          if (statusEl) statusEl.textContent = '已恢复，共 ' + total + ' 条';
        }
      });
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
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
      const themes = ['light', 'dark'];
      const saved = localStorage.getItem('pentest-theme');
      if (saved) document.documentElement.setAttribute('data-theme', saved);
      themeBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        const next = themes[(themes.indexOf(current) + 1) % themes.length];
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('pentest-theme', next);
      });
    }

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

    // Reverse shell
    const revshellGen = utils.get('revshell-gen-btn');
    if (revshellGen) revshellGen.addEventListener('click', generateReverseShell);
    const revshellCopy = utils.get('revshell-copy-btn');
    if (revshellCopy)
      revshellCopy.addEventListener('click', () => {
        const output = utils.get('revshell-output');
        if (output && output.value) {
          utils.copyText(output.value);
          utils.showToast('已复制命令', 'success', 1000);
        }
      });
    const revshellType = utils.get('revshell-type');
    if (revshellType) revshellType.addEventListener('change', generateReverseShell);
    const revshellIp = utils.get('revshell-ip');
    if (revshellIp) revshellIp.addEventListener('input', generateReverseShell);
    const revshellPort = utils.get('revshell-port');
    if (revshellPort) revshellPort.addEventListener('input', generateReverseShell);

    // SQL injection regenerate
    const sqliRegen = utils.get('sqli-regen-btn');
    if (sqliRegen) sqliRegen.addEventListener('click', renderSqliPayloads);
    const sqliColumns = utils.get('sqli-columns');
    if (sqliColumns) sqliColumns.addEventListener('change', renderSqliPayloads);
    const sqliTable = utils.get('sqli-table');
    if (sqliTable) sqliTable.addEventListener('input', renderSqliPayloads);

    // XSS Scan
    initXssScanPayloadSelect();
    var xssHarvestBtn = utils.get('xssscan-harvest-btn');
    if (xssHarvestBtn) xssHarvestBtn.addEventListener('click', handleXssHarvest);
    var xssStartBtn = utils.get('xssscan-start-intercept-btn');
    if (xssStartBtn) xssStartBtn.addEventListener('click', startXssIntercept);
    var xssStopBtn = utils.get('xssscan-stop-intercept-btn');
    if (xssStopBtn) xssStopBtn.addEventListener('click', stopXssIntercept);
    var xssClearBtn = utils.get('xssscan-clear-btn');
    if (xssClearBtn) {
      xssClearBtn.addEventListener('click', function () {
        xssPoints = [];
        renderXssPoints();
        updateXssInterceptStatus();
        utils.showToast('已清空', 'info');
      });
    }
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
    var xssSelectAllBtn = utils.get('xssscan-selectall-btn');
    if (xssSelectAllBtn) {
      xssSelectAllBtn.addEventListener('click', function () {
        var checks = document.querySelectorAll('.xssscan-point-check');
        var allChecked = Array.from(checks).every(function (cb) {
          return cb.checked;
        });
        checks.forEach(function (cb) {
          cb.checked = !allChecked;
        });
      });
    }
    var xssBatchOpenBtn = utils.get('xssscan-batchopen-btn');
    if (xssBatchOpenBtn) xssBatchOpenBtn.addEventListener('click', handleBatchOpenXss);
    var xssCopyAllBtn = utils.get('xssscan-copyall-btn');
    if (xssCopyAllBtn) xssCopyAllBtn.addEventListener('click', handleCopyXssUrls);

    // Webpack Module Mapping (Source Map Scan)
    var smScanBtn = utils.get('sourcemap-scan-btn');
    if (smScanBtn) smScanBtn.addEventListener('click', scanWebpackModules);
    var smCopyAllBtn = utils.get('sourcemap-copy-all-btn');
    if (smCopyAllBtn) smCopyAllBtn.addEventListener('click', copyAllSourcemapPaths);
    var smCopyTreeBtn = utils.get('sourcemap-copy-tree-btn');
    if (smCopyTreeBtn) smCopyTreeBtn.addEventListener('click', generateSourcemapTree);
    var smLoadBtn = utils.get('sourcemap-load-sources-btn');
    if (smLoadBtn) smLoadBtn.addEventListener('click', loadSourcesToDevTools);
    var smDlAllBtn = utils.get('sourcemap-download-all-btn');
    if (smDlAllBtn) smDlAllBtn.addEventListener('click', downloadAllSourcemapSources);
    var smBackBtn = utils.get('sourcemap-detail-back');
    if (smBackBtn) smBackBtn.addEventListener('click', backToSourcemapList);
    var smCopySrcBtn = utils.get('sourcemap-copy-src-btn');
    if (smCopySrcBtn) smCopySrcBtn.addEventListener('click', copyModuleSource);
    var smDlBtn = utils.get('sourcemap-download-btn');
    if (smDlBtn)
      smDlBtn.addEventListener('click', function () {
        if (sourcemapCurrentModule !== null) downloadSingleModule(sourcemapCurrentModule);
      });
    var smSearch = utils.get('sourcemap-search-input');
    if (smSearch) {
      var smSearchTimer = null;
      smSearch.addEventListener('input', function () {
        clearTimeout(smSearchTimer);
        smSearchTimer = setTimeout(function () {
          sourcemapSearchTerm = smSearch.value.trim().toLowerCase();
          renderSourcemapModules();
        }, 200);
      });
    }
    var smAnalyzeBtn = utils.get('sourcemap-analyze-btn');
    if (smAnalyzeBtn) smAnalyzeBtn.addEventListener('click', analyzeSourcemaps);
    var smAnalysisClose = utils.get('sm-analysis-close');
    if (smAnalysisClose)
      smAnalysisClose.addEventListener('click', function () {
        var card = utils.get('sm-analysis-card');
        if (card) card.classList.add('hidden');
      });

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
