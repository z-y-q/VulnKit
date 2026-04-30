// VulnKit - JWT Decoder
window.VulnKitJwt = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  function base64UrlDecode(str) {
    var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    var raw = atob(base64);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function decodeJwt(token) {
    var resultEl = utils.get('jwt-result');
    var errorEl = utils.get('jwt-error');
    var headerEl = utils.get('jwt-header');
    var payloadEl = utils.get('jwt-payload');
    var sigEl = utils.get('jwt-signature');
    var claimsEl = utils.get('jwt-claims');

    if (!resultEl || !errorEl || !headerEl || !payloadEl || !claimsEl) return;
    resultEl.classList.add('hidden');
    errorEl.classList.add('hidden');

    var trimmed = token.trim();
    var parts = trimmed.split('.');
    if (parts.length !== 3) {
      errorEl.textContent = '无效的 JWT 格式（需 3 段，用 . 分隔）';
      errorEl.classList.remove('hidden');
      return;
    }

    try {
      var header = JSON.parse(base64UrlDecode(parts[0]));
      headerEl.textContent = JSON.stringify(header, null, 2);
    } catch (e) {
      errorEl.textContent = 'Header 解析失败: ' + e.message;
      errorEl.classList.remove('hidden');
      return;
    }

    try {
      var payload = JSON.parse(base64UrlDecode(parts[1]));
      payloadEl.textContent = JSON.stringify(payload, null, 2);
    } catch (e) {
      errorEl.textContent = 'Payload 解析失败: ' + e.message;
      errorEl.classList.remove('hidden');
      return;
    }

    sigEl.textContent = parts[2];

    var now = Math.floor(Date.now() / 1000);
    var claimsHtml = '';

    if (payload.exp) {
      var expDate = new Date(payload.exp * 1000);
      var isExpired = payload.exp < now;
      claimsHtml +=
        '<div class="jwt-claim ' +
        (isExpired ? 'jwt-claim-expired' : 'jwt-claim-valid') +
        '">' +
        '<span>过期时间 (exp)</span><span>' +
        expDate.toLocaleString('zh-CN') +
        (isExpired ? ' — 已过期' : ' — 有效') +
        '</span></div>';
    }
    if (payload.iat) {
      claimsHtml +=
        '<div class="jwt-claim"><span>签发时间 (iat)</span><span>' +
        new Date(payload.iat * 1000).toLocaleString('zh-CN') +
        '</span></div>';
    }
    if (payload.nbf) {
      var isNbfValid = payload.nbf <= now;
      claimsHtml +=
        '<div class="jwt-claim ' +
        (isNbfValid ? 'jwt-claim-valid' : 'jwt-claim-expired') +
        '">' +
        '<span>生效时间 (nbf)</span><span>' +
        new Date(payload.nbf * 1000).toLocaleString('zh-CN') +
        (isNbfValid ? ' — 已生效' : ' — 尚未生效') +
        '</span></div>';
    }

    claimsEl.innerHTML = claimsHtml;
    resultEl.classList.remove('hidden');
    utils.showToast('JWT 解码成功', 'success');
  }

  function clearJwt() {
    var inputEl = utils.get('jwt-input');
    var resultEl = utils.get('jwt-result');
    var errorEl = utils.get('jwt-error');
    if (inputEl) inputEl.value = '';
    if (resultEl) resultEl.classList.add('hidden');
    if (errorEl) errorEl.classList.add('hidden');
  }

  function copyJwtHeader() {
    var el = utils.get('jwt-header');
    if (!el || !el.textContent) {
      utils.showToast('请先解码 JWT', 'warning');
      return;
    }
    utils.copyAndToast(el.textContent, '已复制 Header');
  }

  function copyJwtPayload() {
    var el = utils.get('jwt-payload');
    if (!el || !el.textContent) {
      utils.showToast('请先解码 JWT', 'warning');
      return;
    }
    utils.copyAndToast(el.textContent, '已复制 Payload');
  }

  return {
    decodeJwt: decodeJwt,
    clearJwt: clearJwt,
    copyJwtHeader: copyJwtHeader,
    copyJwtPayload: copyJwtPayload,
  };
})();
