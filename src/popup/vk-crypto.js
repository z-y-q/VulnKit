// 灵眸 - Crypto (AES/DES/RC4/SM2/SM4/Bcrypt)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

function ensureCryptoLibs() {
  if (typeof window.CryptoJS !== 'undefined') return true;
  utils.showToast('加密库加载中，请稍候...', 'info');
  return false;
}

function ensureLib(name, loaded) {
  if (loaded) return true;
  utils.showToast(`${name} 库加载中，请稍候...`, 'info');
  return false;
}

// ====== Crypto (AES/DES/RC4/SM2/SM4/Bcrypt) ======
let currentCryptoAlgo = 'aes';
function padOrTruncate(key, len) {
  if (!key) return key;
  key = key.toString();
  if (key.length >= len) return key.substring(0, len);
  while (key.length < len) key += '\0';
  return key;
}

let WEAK_ALGO_WARNINGS = {
  des: 'DES 密钥仅 56 位，已被认为不安全，建议使用 AES 或 SM4',
  rc4: 'RC4 存在多个已知漏洞，已被认为不安全，建议使用 AES 或 SM4',
};

function switchCryptoAlgo(algo) {
  currentCryptoAlgo = algo;
  if (WEAK_ALGO_WARNINGS[algo]) {
    utils.showToast(WEAK_ALGO_WARNINGS[algo], 'warning');
  }
  document.querySelectorAll('.crypto-algo-btn').forEach(function (b) {
    b.classList.toggle('active', b.dataset.algo === algo);
  });
  document.querySelectorAll('.crypto-algo-panel').forEach(function (p) {
    p.classList.remove('active');
  });
  let panel = utils.get(`algo-${algo}`);
  if (panel) panel.classList.add('active');
  let encBtn = utils.get('crypto-enc-btn');
  let decBtn = utils.get('crypto-dec-btn');
  let verifyBtn = utils.get('crypto-verify-btn');
  if (algo === 'bcrypt') {
    if (encBtn) encBtn.textContent = '生成哈希';
    if (decBtn) decBtn.classList.add('hidden');
    if (verifyBtn) verifyBtn.classList.remove('hidden');
  } else if (algo === 'hash') {
    if (encBtn) encBtn.textContent = '计算哈希';
    if (decBtn) decBtn.classList.add('hidden');
    if (verifyBtn) verifyBtn.classList.add('hidden');
  } else {
    if (encBtn) encBtn.textContent = '加密';
    if (decBtn) decBtn.classList.remove('hidden');
    if (verifyBtn) verifyBtn.classList.add('hidden');
  }
}

function toggleIvVisibility(algoMode, ivGroupId, algoKey) {
  let ivGroup = utils.get(ivGroupId);
  if (!ivGroup) return;
  let modeEl = utils.get(algoKey);
  let mode = modeEl ? modeEl.value : '';
  if (mode === 'ECB' || mode === 'ecb') {
    ivGroup.classList.add('hidden');
  } else {
    ivGroup.classList.remove('hidden');
  }
}

function doCryptoEncrypt() {
  if (!ensureCryptoLibs()) return;
  let input = (utils.get('crypto-input') || {}).value || '';
  input = utils.requireInput(input, '请输入内容');
  if (!input) return;
  let output = utils.get('crypto-output');
  if (!output) return;
  try {
    let result;
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
      case 'hash':
        result = computeHash(input);
        break;
      case 'rsa':
        rsaEncrypt(input)
          .then(function (r) {
            output.value = r;
            utils.showToast('加密成功', 'success');
          })
          .catch(function (e) {
            output.value = `错误: ${e.message}`;
            utils.showToast('加密失败', 'error');
          });
        return;
      default:
        return;
    }
    output.value = result;
    utils.showToast('加密成功', 'success');
  } catch (e) {
    output.value = `错误: ${e.message}`;
    utils.showToast(`加密失败: ${e.message}`, 'error');
  }
}

function doCryptoDecrypt() {
  if (!ensureCryptoLibs()) return;
  let input = (utils.get('crypto-input') || {}).value || '';
  input = utils.requireInput(input, '请输入密文');
  if (!input) return;
  let output = utils.get('crypto-output');
  if (!output) return;
  try {
    let result;
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
            output.value = `错误: ${e.message}`;
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
    output.value = `错误: ${e.message}`;
    utils.showToast(`解密失败: ${e.message}`, 'error');
  }
}

function doCryptoVerify() {
  if (!ensureLib('Bcrypt', typeof window.dcodeIO !== 'undefined')) return;
  let input = (utils.get('crypto-input') || {}).value || '';
  let hash = (utils.get('crypto-output') || {}).value || '';
  if (!input || !hash) {
    utils.showToast('请输入密码和哈希', 'warning');
    return;
  }
  if (currentCryptoAlgo !== 'bcrypt') return;
  try {
    let match = window.dcodeIO.bcrypt.compareSync(input, hash);
    utils.showToast(match ? '验证通过' : '验证失败', match ? 'success' : 'error');
  } catch (e) {
    utils.showToast(`验证失败: ${e.message}`, 'error');
  }
}

function readCryptoSelect(id) {
  return (utils.get(id) || {}).value || '';
}
function readCryptoCheck(id) {
  return (utils.get(id) || {}).checked;
}

function aesParams() {
  let mode = readCryptoSelect('aes-mode') || 'CBC';
  let keySize = parseInt(readCryptoSelect('aes-keysize')) || 128;
  let padding = readCryptoSelect('aes-padding') || 'Pkcs7';
  let key = padOrTruncate(readCryptoSelect('aes-key'), keySize / 8);
  if (!key || key.length < 1) throw new Error('请输入密钥');
  let opts = { mode: window.CryptoJS.mode[mode], padding: window.CryptoJS.pad[padding] };
  if (mode !== 'ECB') {
    opts.iv = window.CryptoJS.enc.Utf8.parse(padOrTruncate(readCryptoSelect('aes-iv'), 16));
  }
  return { keyWA: window.CryptoJS.enc.Utf8.parse(key), opts: opts };
}

function aesEncrypt(input) {
  let p = aesParams();
  return window.CryptoJS.AES.encrypt(
    window.CryptoJS.enc.Utf8.parse(input),
    p.keyWA,
    p.opts
  ).toString();
}

function aesDecrypt(input) {
  let p = aesParams();
  return window.CryptoJS.enc.Utf8.stringify(window.CryptoJS.AES.decrypt(input, p.keyWA, p.opts));
}

function desParams() {
  let mode = readCryptoSelect('des-mode') || 'CBC';
  let padding = readCryptoSelect('des-padding') || 'Pkcs7';
  let key = padOrTruncate(readCryptoSelect('des-key'), 8);
  if (!key || key.length < 8) throw new Error('密钥需 8 字符');
  let opts = { mode: window.CryptoJS.mode[mode], padding: window.CryptoJS.pad[padding] };
  if (mode !== 'ECB') {
    opts.iv = window.CryptoJS.enc.Utf8.parse(padOrTruncate(readCryptoSelect('des-iv'), 8));
  }
  return { keyWA: window.CryptoJS.enc.Utf8.parse(key), opts: opts };
}

function desEncrypt(input) {
  let p = desParams();
  return window.CryptoJS.DES.encrypt(
    window.CryptoJS.enc.Utf8.parse(input),
    p.keyWA,
    p.opts
  ).toString();
}

function desDecrypt(input) {
  let p = desParams();
  return window.CryptoJS.enc.Utf8.stringify(window.CryptoJS.DES.decrypt(input, p.keyWA, p.opts));
}

function rc4Encrypt(input) {
  let key = readCryptoSelect('rc4-key');
  if (!key) throw new Error('请输入密钥');
  return window.CryptoJS.RC4.encrypt(window.CryptoJS.enc.Utf8.parse(input), key).toString();
}

function rc4Decrypt(input) {
  let key = readCryptoSelect('rc4-key');
  if (!key) throw new Error('请输入密钥');
  let bytes = window.CryptoJS.RC4.decrypt(input, key);
  return window.CryptoJS.enc.Utf8.stringify(bytes);
}

function sm2Encrypt(input) {
  let pubKey = readCryptoSelect('sm2-pubkey');
  if (!pubKey) throw new Error('请输入公钥');
  if (pubKey.length === 128) pubKey = `04${pubKey}`;
  if (pubKey.length !== 130 || !pubKey.startsWith('04'))
    throw new Error('公钥格式错误（需 130 位十六进制，04 开头）');
  const bytes = new TextEncoder().encode(input);
  return window.sm2.doEncrypt(
    Array.from(bytes),
    pubKey,
    parseInt(readCryptoSelect('sm2-cipher')) || 1
  );
}

function sm2Decrypt(input) {
  let priKey = readCryptoSelect('sm2-prikey');
  if (!priKey) throw new Error('请输入私钥');
  let cipherMode = parseInt(readCryptoSelect('sm2-cipher')) || 1;
  let decrypted = window.sm2.doDecrypt(input, priKey, cipherMode, { output: 'array' });
  if (!decrypted) throw new Error('解密失败，请检查密钥和密文');
  return new TextDecoder().decode(new Uint8Array(decrypted));
}

function toHex(str) {
  return Array.from(str)
    .map(function (c) {
      return c.charCodeAt(0).toString(16).padStart(2, '0');
    })
    .join('');
}

function sm4Params() {
  let key = readCryptoSelect('sm4-key');
  if (!key || key.length !== 16) throw new Error('密钥需 16 字符');
  let isCbc = readCryptoSelect('sm4-mode') === 'cbc';
  let usePadding = readCryptoCheck('sm4-padding') !== false;
  return {
    keyHex: toHex(key),
    opts: {
      padding: usePadding ? 'pkcs#5' : 'none',
      mode: isCbc ? 'cbc' : undefined,
      iv: isCbc ? toHex(readCryptoSelect('sm4-iv') || '') : undefined,
    },
  };
}

function sm4Encrypt(input) {
  let p = sm4Params();
  return window.sm4.encrypt(input, p.keyHex, p.opts);
}

function sm4Decrypt(input) {
  let p = sm4Params();
  return window.sm4.decrypt(input, p.keyHex, p.opts);
}

function computeHash(input) {
  let algo = readCryptoSelect('hash-algo') || 'sha256';
  let useHex = readCryptoCheck('hash-hex') !== false;
  let useHmac = readCryptoCheck('hash-hmac');
  let hmacKey = readCryptoSelect('hash-hmac-key');
  if (useHmac && !hmacKey) throw new Error('请输入 HMAC 密钥');
  let algoName = algo.toUpperCase().replace('-', '');
  if (useHmac) {
    let keyWA = window.CryptoJS.enc.Utf8.parse(hmacKey);
    let fn = window.CryptoJS[`Hmac${algoName.charAt(0).toUpperCase()}${algoName.slice(1)}`];
    let hash = fn ? fn(input, keyWA) : window.CryptoJS.HmacSHA256(input, keyWA);
    return useHex
      ? hash.toString(window.CryptoJS.enc.Hex)
      : window.CryptoJS.enc.Base64.stringify(hash);
  }
  let result = window.CryptoJS[algoName](input);
  return useHex
    ? result.toString(window.CryptoJS.enc.Hex)
    : window.CryptoJS.enc.Base64.stringify(result);
}

function toggleHashHmac() {
  let row = utils.get('hash-hmac-key-row');
  if (row) row.classList.toggle('hidden', !readCryptoCheck('hash-hmac'));
}

function bcryptHash(input) {
  let rounds = parseInt(readCryptoSelect('bcrypt-rounds')) || 10;
  let salt = window.dcodeIO.bcrypt.genSaltSync(rounds);
  return window.dcodeIO.bcrypt.hashSync(input, salt);
}

function rsaEncrypt(input) {
  let pubKeyStr = (utils.get('rsa-pubkey') || {}).value || '';
  if (!pubKeyStr) throw new Error('请先生成密钥对');
  return window.crypto.subtle
    .importKey('spki', pemToArrayBuffer(pubKeyStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
      'encrypt',
    ])
    .then(function (pubKey) {
      return window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pubKey,
        new TextEncoder().encode(input)
      );
    })
    .then(function (buf) {
      let bytes = new Uint8Array(buf);
      let chunks = [];
      for (let i = 0; i < bytes.length; i += 8192) {
        chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)));
      }
      return btoa(chunks.join(''));
    });
}

function rsaDecrypt(input) {
  let priKeyStr = (utils.get('rsa-prikey') || {}).value || '';
  if (!priKeyStr) throw new Error('请先生成密钥对');
  return window.crypto.subtle
    .importKey('pkcs8', pemToArrayBuffer(priKeyStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
      'decrypt',
    ])
    .then(function (priKey) {
      let bin = atob(input);
      let buf = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
      return window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priKey, buf);
    })
    .then(function (buf) {
      return new TextDecoder().decode(buf);
    });
}

function rsaGenerateKeyPair() {
  let keySize = parseInt((utils.get('rsa-keysize') || {}).value) || 2048;
  if (keySize < 2048) {
    utils.showToast(`RSA ${keySize} 位密钥太短，建议至少 2048 位`, 'warning');
  }
  let btn = utils.get('rsa-genkey-btn');
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
      let pubEl = utils.get('rsa-pubkey');
      let priEl = utils.get('rsa-prikey');
      if (pubEl) pubEl.value = ab2pem(results[0], 'PUBLIC KEY');
      if (priEl) priEl.value = ab2pem(results[1], 'PRIVATE KEY');
      if (btn) {
        btn.disabled = false;
        btn.textContent = '生成密钥对';
      }
      utils.showToast(`${keySize} 位密钥对已生成`, 'success');
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
  let bytes = new Uint8Array(buffer);
  let binary = '';
  let chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    let chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  let b64 = btoa(binary);
  let lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem) {
  let b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s/g, '');
  let bin = atob(b64);
  let buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export {
  padOrTruncate,
  toHex,
  pemToArrayBuffer,
  ab2pem,
  switchCryptoAlgo,
  toggleIvVisibility,
  doCryptoEncrypt,
  doCryptoDecrypt,
  doCryptoVerify,
  computeHash,
  toggleHashHmac,
  rsaGenerateKeyPair,
  currentCryptoAlgo,
};

// Getter/setter for currentCryptoAlgo are handled via the exported variable reference
// Module consumers can use the exported functions to interact with the algo state
