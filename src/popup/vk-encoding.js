// 灵眸 - Encoding Tools
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const ENCODING_NAMES = { base64: 'Base64', url: 'URL', html: 'HTML', hex: 'Hex' };
let currentEncodingType = 'base64';

const encodingTools = {
  base64: {
    encode(t) {
      try {
        return btoa(unescape(encodeURIComponent(t)));
      } catch (e) {
        return `Error: ${e.message}`;
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
  let inputEl = utils.get('encoding-input');
  if (!inputEl) return;
  let input = inputEl.value;
  input = utils.requireInput(input, '请输入文本');
  if (!input) return;
  let result =
    encodingTools[currentEncodingType] && encodingTools[currentEncodingType].encode(input);
  if (result === undefined) {
    utils.showToast('未知编码类型', 'error');
    return;
  }
  let outputEl = utils.get('encoding-output');
  if (outputEl) outputEl.value = result;
  utils.showToast('编码成功', 'success');
}

function handleDecode() {
  let inputEl = utils.get('encoding-input');
  if (!inputEl) return;
  let input = inputEl.value;
  input = utils.requireInput(input, '请输入文本');
  if (!input) return;
  let result =
    encodingTools[currentEncodingType] && encodingTools[currentEncodingType].decode(input);
  if (result === undefined) {
    utils.showToast('未知编码类型', 'error');
    return;
  }
  let outputEl = utils.get('encoding-output');
  if (outputEl) outputEl.value = result;
  utils.showToast('解码成功', 'success');
}

function clearEncodingFields() {
  let inputEl = utils.get('encoding-input');
  let outputEl = utils.get('encoding-output');
  if (inputEl) inputEl.value = '';
  if (outputEl) outputEl.value = '';
}

function copyOutput() {
  let outputEl = utils.get('encoding-output');
  if (!outputEl || !outputEl.value) {
    utils.showToast('没有可复制的内容', 'warning');
    return;
  }
  utils.copyAndToast(outputEl.value, '已复制到剪贴板');
}

function swapFields() {
  const inputEl = utils.get('encoding-input');
  const outputEl = utils.get('encoding-output');
  if (!inputEl || !outputEl) return;
  const tmp = inputEl.value;
  inputEl.value = outputEl.value;
  outputEl.value = tmp;
}

function switchEncodingTab(type) {
  currentEncodingType = type;
  utils.saveUIState('encoding-subtab', type);
  document.querySelectorAll('.sub-tab-btn').forEach(function (b) {
    b.classList.toggle('active', b.dataset.type === type);
  });
  const encSection = utils.get('enc-classic-section');
  const cryptoSection = utils.get('crypto-section');
  const jwtSection = utils.get('jwt-section');
  const cardTitle = utils.get('card-title');
  if (type === 'crypto') {
    if (encSection) encSection.classList.add('hidden');
    if (jwtSection) jwtSection.classList.add('hidden');
    if (cryptoSection) cryptoSection.classList.remove('hidden');
    if (cardTitle) cardTitle.textContent = '加密解密';
    if (!switchEncodingTab._cryptoLoaded) {
      switchEncodingTab._cryptoLoaded = true;
      utils
        .loadLibs(['lib/crypto-js.min.js', 'lib/sm2.js', 'lib/sm4.js', 'lib/bcrypt.min.js'])
        .catch(function (e) {
          console.debug('crypto libs load failed', e);
        });
    }
  } else if (type === 'jwt') {
    if (encSection) encSection.classList.add('hidden');
    if (cryptoSection) cryptoSection.classList.add('hidden');
    if (jwtSection) jwtSection.classList.remove('hidden');
    if (cardTitle) cardTitle.textContent = 'JWT 解码';
  } else {
    if (encSection) encSection.classList.remove('hidden');
    if (cryptoSection) cryptoSection.classList.add('hidden');
    if (jwtSection) jwtSection.classList.add('hidden');
    if (cardTitle) cardTitle.textContent = `${ENCODING_NAMES[type]} 编码/解码`;
  }
}

export {
  ENCODING_NAMES,
  encodingTools,
  handleEncode,
  handleDecode,
  clearEncodingFields,
  copyOutput,
  swapFields,
  switchEncodingTab,
};
