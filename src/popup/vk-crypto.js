window.VulnKitCrypto = (function () {
  'use strict';

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
      return u[method].apply(u, arguments);
    };
  });

  // ====== Crypto (AES/DES/RC4/SM2/SM4/Bcrypt) ======
  var currentCryptoAlgo = 'aes';

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

  return {
    switchCryptoAlgo,
    toggleIvVisibility,
    doCryptoEncrypt,
    doCryptoDecrypt,
    doCryptoVerify,
    rsaGenerateKeyPair,
    get currentCryptoAlgo() { return currentCryptoAlgo; },
    set currentCryptoAlgo(v) { currentCryptoAlgo = v; },
  };
})();
