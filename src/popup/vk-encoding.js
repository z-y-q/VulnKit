// VulnKit - Encoding Tools
window.VulnKitEncoding = (function () {
  'use strict';

  const ENCODING_NAMES = { base64: 'Base64', url: 'URL', html: 'HTML', hex: 'Hex' };
  let currentEncodingType = 'base64';
  var utils = window.VulnKitUtils.utilsProxy;

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
        const d = document.createElement('textarea');
        d.innerHTML = t;
        return d.value || '';
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
    var inputEl = utils.get('encoding-input');
    if (!inputEl) return;
    var input = inputEl.value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    var result =
      encodingTools[currentEncodingType] && encodingTools[currentEncodingType].encode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    var outputEl = utils.get('encoding-output');
    if (outputEl) outputEl.value = result;
    utils.showToast('编码成功', 'success');
  }

  function handleDecode() {
    var inputEl = utils.get('encoding-input');
    if (!inputEl) return;
    var input = inputEl.value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    var result =
      encodingTools[currentEncodingType] && encodingTools[currentEncodingType].decode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    var outputEl = utils.get('encoding-output');
    if (outputEl) outputEl.value = result;
    utils.showToast('解码成功', 'success');
  }

  function clearEncodingFields() {
    var inputEl = utils.get('encoding-input');
    var outputEl = utils.get('encoding-output');
    if (inputEl) inputEl.value = '';
    if (outputEl) outputEl.value = '';
  }

  function copyOutput() {
    var outputEl = utils.get('encoding-output');
    if (!outputEl || !outputEl.value) {
      utils.showToast('没有可复制的内容', 'warning');
      return;
    }
    utils.copyText(outputEl.value);
    utils.showToast('已复制到剪贴板', 'success');
  }

  function swapFields() {
    var inputEl = utils.get('encoding-input');
    var outputEl = utils.get('encoding-output');
    if (!inputEl || !outputEl) return;
    var tmp = inputEl.value;
    inputEl.value = outputEl.value;
    outputEl.value = tmp;
  }

  function switchEncodingTab(type) {
    currentEncodingType = type;
    document.querySelectorAll('.sub-tab-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.type === type);
    });
    var encSection = utils.get('enc-classic-section');
    var cryptoSection = utils.get('crypto-section');
    var jwtSection = utils.get('jwt-section');
    var cardTitle = utils.get('card-title');
    if (type === 'crypto') {
      if (encSection) encSection.classList.add('hidden');
      if (jwtSection) jwtSection.classList.add('hidden');
      if (cryptoSection) cryptoSection.classList.remove('hidden');
      if (cardTitle) cardTitle.textContent = '加密解密';
    } else if (type === 'jwt') {
      if (encSection) encSection.classList.add('hidden');
      if (cryptoSection) cryptoSection.classList.add('hidden');
      if (jwtSection) jwtSection.classList.remove('hidden');
      if (cardTitle) cardTitle.textContent = 'JWT 解码';
    } else {
      if (encSection) encSection.classList.remove('hidden');
      if (cryptoSection) cryptoSection.classList.add('hidden');
      if (jwtSection) jwtSection.classList.add('hidden');
      if (cardTitle) cardTitle.textContent = ENCODING_NAMES[type] + ' 编码/解码';
    }
  }

  return {
    ENCODING_NAMES: ENCODING_NAMES,
    handleEncode: handleEncode,
    handleDecode: handleDecode,
    clearEncodingFields: clearEncodingFields,
    copyOutput: copyOutput,
    swapFields: swapFields,
    switchEncodingTab: switchEncodingTab,
  };
})();
