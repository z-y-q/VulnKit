// VulnKit - Encoding Tools
window.VulnKitEncoding = (function () {
  'use strict';

  const ENCODING_NAMES = { base64: 'Base64', url: 'URL', html: 'HTML', hex: 'Hex' };
  let currentEncodingType = 'base64';

  // Forward reference to utils (populated by inline-optimized.js after this loads)
  function getUtils() {
    return window.VulnKitUtils || null;
  }

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
    const utils = getUtils();
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
    const utils = getUtils();
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
    const utils = getUtils();
    utils.get('encoding-input').value = '';
    utils.get('encoding-output').value = '';
  }

  function switchEncodingTab(type) {
    currentEncodingType = type;
    const utils = getUtils();
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

  return {
    ENCODING_NAMES: ENCODING_NAMES,
    handleEncode: handleEncode,
    handleDecode: handleDecode,
    clearEncodingFields: clearEncodingFields,
    switchEncodingTab: switchEncodingTab,
  };
})();
