// VulnKit - Request Spoofing (UA, Cookie, Headers)
window.VulnKitSpoof = (function () {
  'use strict';

  let currentSpoofTab = 'ua';
  let spoofState = {
    ua: { enabled: false, current: '', original: '' },
    headers: { xff: '', referer: '', clientIp: '', custom: [] },
  };

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  function confirmAction(message, onConfirm) {
    var utils = getUtils();
    var safeMsg =
      utils && utils.escapeHtml
        ? utils.escapeHtml(message)
        : message.replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
          });
    var overlay = document.createElement('div');
    overlay.className = 'confirm-overlay';
    overlay.innerHTML =
      '<div class="confirm-dialog">' +
      '<div class="confirm-msg">' +
      safeMsg +
      '</div>' +
      '<div class="confirm-actions">' +
      '<button class="btn btn-sm btn-primary confirm-yes">确定</button>' +
      '<button class="btn btn-sm btn-outline confirm-no">取消</button>' +
      '</div></div>';
    document.body.appendChild(overlay);

    overlay.querySelector('.confirm-yes').addEventListener('click', function () {
      overlay.remove();
      onConfirm();
    });
    overlay.querySelector('.confirm-no').addEventListener('click', function () {
      overlay.remove();
    });
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) overlay.remove();
    });
  }

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
    const utils = getUtils();
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
      html +=
        '<span class="ua-item-value" title="' +
        preset.value
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;') +
        '">';
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
    const utils = getUtils();
    const el = utils.get('spoof-ua-status');
    if (!el) return;
    el.innerHTML = spoofState.ua.enabled
      ? '<span class="spoof-status-active">UA 伪造已启用</span>'
      : '';
  }

  async function applyUserAgent() {
    const utils = getUtils();
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
    const utils = getUtils();
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
    const utils = getUtils();
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
    const utils = getUtils();
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
    const utils = getUtils();
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

  function deleteCookie(cookieName) {
    var utils = getUtils();
    confirmAction('确定删除 Cookie「' + cookieName + '」？', function () {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (!tabs[0]?.url) return;
        var url = new URL(tabs[0].url);
        chrome.cookies.remove({ url: url.origin, name: cookieName }, function () {
          if (chrome.runtime.lastError) {
            utils.showToast('删除失败: ' + chrome.runtime.lastError.message, 'error');
            return;
          }
          utils.showToast('Cookie 已删除', 'success');
          loadCookies();
        });
      });
    });
  }

  function showCookieImportDialog() {
    const utils = getUtils();
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
    const utils = getUtils();
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

  function clearAllCookies() {
    var utils = getUtils();
    confirmAction('确定清除当前域名所有 Cookie？此操作不可撤销。', function () {
      chrome.tabs.query({ active: true, currentWindow: true }, async function (tabs) {
        if (!tabs[0]?.url) return;
        var url = new URL(tabs[0].url);
        var domain = url.hostname;
        var cookies = await chrome.cookies.getAll({ domain: domain });
        var count = 0;
        for (var i = 0; i < cookies.length; i++) {
          await chrome.cookies.remove({ url: url.origin, name: cookies[i].name });
          count++;
        }
        utils.showToast('已清除 ' + count + ' 个 Cookie', 'success');
        loadCookies();
      });
    });
  }

  async function applyHeaders() {
    const utils = getUtils();
    const xffEl = utils.get('header-xff');
    const refererPresetEl = utils.get('referer-preset');
    const refererEl = utils.get('header-referer');
    const clientIpEl = utils.get('header-client-ip');
    if (!xffEl || !refererPresetEl || !refererEl || !clientIpEl) return;

    const xff = xffEl.value.trim();
    const refererPreset = refererPresetEl.value;
    let referer = refererEl.value.trim();

    if (refererPreset === 'none') referer = '';
    else if (refererPreset === 'same') {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        referer = tab && tab.url ? new URL(tab.url).origin + new URL(tab.url).pathname : '';
      } catch {
        referer = '';
      }
    }
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
    const utils = getUtils();
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
    const utils = getUtils();
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

  async function exportCookies() {
    const utils = getUtils();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) {
      utils.showToast('无法获取当前页面', 'error');
      return;
    }
    const url = new URL(tab.url);
    const domain = url.hostname;
    const cookies = await chrome.cookies.getAll({ domain: domain });

    if (cookies.length === 0) {
      utils.showToast('当前域名无 Cookie', 'warning');
      return;
    }

    var exportData = cookies.map(function (c) {
      return {
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        httpOnly: c.httpOnly || false,
        secure: c.secure || false,
        sameSite: c.sameSite || 'unspecified',
        expirationDate: c.expirationDate || null,
      };
    });

    var json = JSON.stringify(exportData, null, 2);
    var blob = new Blob([json], { type: 'application/json' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = domain.replace(/\./g, '_') + '_cookies.json';
    link.click();
    URL.revokeObjectURL(link.href);
    utils.showToast('已导出 ' + exportData.length + ' 个 Cookie', 'success');
  }

  function showCookieFileImportDialog() {
    const utils = getUtils();
    const listEl = utils.get('cookie-list');
    if (!listEl) return;

    let html = '<div class="cookie-editor">';
    html += '<div class="card-title">从文件导入 Cookie</div>';
    html += '<div class="form-group">';
    html += '<label>选择 JSON 文件（由导出功能生成）</label>';
    html += '<input type="file" id="cookie-file-input" accept=".json" style="margin:4px 0">';
    html += '</div>';
    html += '<div class="form-group">';
    html += '<label>或粘贴 JSON 数组</label>';
    html +=
      '<textarea class="textarea cookie-json-import-textarea" rows="4" placeholder=\'[{"name":"token","value":"xxx","domain":".example.com",...}\'></textarea>';
    html += '</div>';
    html += '<div class="form-actions">';
    html += '<button class="btn btn-primary" id="cookie-file-import-do">导入</button>';
    html += '<button class="btn btn-outline cookie-cancel-btn">取消</button>';
    html += '</div></div>';
    listEl.innerHTML = html;

    listEl.querySelector('.cookie-cancel-btn').addEventListener('click', () => loadCookies());
    listEl.querySelector('#cookie-file-import-do').addEventListener('click', () => {
      var fileInput = document.getElementById('cookie-file-input');
      var textarea = document.querySelector('.cookie-json-import-textarea');
      if (fileInput && fileInput.files && fileInput.files.length > 0) {
        var reader = new FileReader();
        reader.onload = function (e) {
          importCookieJson(e.target.result);
        };
        reader.readAsText(fileInput.files[0]);
      } else if (textarea && textarea.value.trim()) {
        importCookieJson(textarea.value.trim());
      } else {
        utils.showToast('请选择文件或粘贴 JSON', 'warning');
      }
    });
  }

  async function importCookieJson(jsonStr) {
    const utils = getUtils();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);

    var cookies;
    try {
      cookies = JSON.parse(jsonStr);
      if (!Array.isArray(cookies)) {
        utils.showToast('JSON 格式错误：需要数组', 'error');
        return;
      }
    } catch (e) {
      utils.showToast('JSON 解析失败: ' + e.message, 'error');
      return;
    }

    var count = 0;
    for (var i = 0; i < cookies.length; i++) {
      var c = cookies[i];
      if (!c.name) continue;
      try {
        await chrome.cookies.set({
          url: url.origin + (c.path || '/'),
          name: c.name,
          value: c.value || '',
          domain: c.domain || url.hostname,
          path: c.path || '/',
          secure: c.secure !== false,
          httpOnly: !!c.httpOnly,
          sameSite: c.sameSite || 'unspecified',
          expirationDate: c.expirationDate && c.expirationDate > 0 ? c.expirationDate : undefined,
        });
        count++;
      } catch (e) {
        /* skip invalid */
      }
    }
    utils.showToast('已导入 ' + count + '/' + cookies.length + ' 个 Cookie', 'success');
    loadCookies();
  }

  return {
    UA_PRESETS,
    spoofState,
    switchSpoofTab,
    renderUaList,
    updateUaStatus,
    applyUserAgent,
    resetUserAgent,
    loadCookies,
    showCookieAddEditor,
    showCookieImportDialog,
    showCookieFileImportDialog,
    exportCookies,
    clearAllCookies,
    applyHeaders,
    addCustomHeaderRow,
    resetHeaders,
    get currentSpoofTab() {
      return currentSpoofTab;
    },
    set currentSpoofTab(v) {
      currentSpoofTab = v;
    },
  };
})();
