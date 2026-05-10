function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ====== Toolbar Configuration ======

const DEFAULT_TABS = [
  { id: 'encoding', label: '编码工具' },
  { id: 'favicon', label: '图标识别' },
  { id: 'gather', label: '信息收集' },
  { id: 'asset', label: '资产测绘' },
  { id: 'links', label: '链接提取' },
  { id: 'multiurl', label: 'URL多开' },
  { id: 'history', label: '历史档案' },
  { id: 'exif', label: 'EXIF查看' },
  { id: 'spoof', label: '请求伪造' },
  { id: 'vue', label: 'Vue分析' },
  { id: 'ruoyi', label: 'RuoYi路由' },
  { id: 'jsctrl', label: 'JS控制' },
  { id: 'payload', label: 'Payload' },
  { id: 'xssscan', label: 'XSS扫描' },
  { id: 'sourcemap', label: 'Source Map' },
  { id: 'waf', label: 'WAF指纹' },
  { id: 'cookie-audit', label: 'Cookie审计' },
  { id: 'react', label: 'React分析' },
  { id: 'angular', label: 'Angular分析' },
  { id: 'cors', label: 'CORS检测' },
  { id: 'subdomain', label: '子域名' },
  { id: 'source-loader', label: '源码加载' },
  { id: 'sniff', label: '网站嗅探' },
  { id: 'report', label: '统一报告' },
  { id: 'headers', label: '安全头' },
  { id: 'redirect', label: '重定向' },
  { id: 'fuzz', label: '目录扫描' },
];

const TAB_CATEGORIES_OPT = [
  {
    id: 'recon',
    label: '侦察',
    color: '#4A90E2',
    tabs: ['favicon', 'gather', 'subdomain', 'sniff'],
  },
  {
    id: 'scan',
    label: '扫描',
    color: '#e74c3c',
    tabs: ['xssscan', 'cors', 'waf', 'cookie-audit', 'headers', 'redirect', 'fuzz'],
  },
  {
    id: 'exploit',
    label: '利用',
    color: '#e67e22',
    tabs: ['jsctrl', 'payload', 'encoding', 'spoof'],
  },
  {
    id: 'framework',
    label: '框架分析',
    color: '#27ae60',
    tabs: ['vue', 'ruoyi', 'react', 'angular', 'sourcemap'],
  },
  {
    id: 'tools',
    label: '工具',
    color: '#9b59b6',
    tabs: ['asset', 'links', 'multiurl', 'history', 'exif', 'source-loader'],
  },
  { id: 'report', label: '统一报告', color: '#999', tabs: ['report'] },
];

var TAB_TO_CATEGORY_OPT = {};
TAB_CATEGORIES_OPT.forEach(function (cat) {
  cat.tabs.forEach(function (tabId) {
    TAB_TO_CATEGORY_OPT[tabId] = cat;
  });
});

function getToolbarConfig(settings) {
  const saved = settings.toolbarConfig;
  if (!saved || !Array.isArray(saved)) {
    return DEFAULT_TABS.map(function (t) {
      return { id: t.id, label: t.label, visible: true };
    });
  }
  const seenIds = {};
  let result = [];
  saved.forEach(function (t) {
    const def = DEFAULT_TABS.find(function (d) {
      return d.id === t.id;
    });
    if (def) {
      result.push({ id: t.id, label: def.label, visible: t.visible !== false });
      seenIds[t.id] = true;
    }
  });
  DEFAULT_TABS.forEach(function (t) {
    if (!seenIds[t.id]) {
      result.push({ id: t.id, label: t.label, visible: true });
    }
  });
  return result;
}

function saveToolbarConfigFromDOM() {
  let container = $('toolbar-config-list');
  if (!container) return;
  const items = container.querySelectorAll('.toolbar-config-item');
  let config = [];
  items.forEach(function (item) {
    const cb = item.querySelector('input[type="checkbox"]');
    config.push({
      id: item.dataset.id,
      label: item.querySelector('label').textContent.trim(),
      visible: cb ? cb.checked : true,
    });
  });
  chrome.storage.local.get(['pentestSettings'], function (result) {
    let settings = result.pentestSettings || {};
    settings.toolbarConfig = config;
    chrome.storage.local.set({ pentestSettings: settings }, function () {
      showStatus('工具栏配置已保存', 'success');
    });
  });
}

function initToolbarDragDrop(container) {
  let dragSrc = null;
  container.addEventListener('dragstart', function (e) {
    let item = e.target.closest('.toolbar-config-item');
    if (!item) return;
    dragSrc = item;
    item.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', '');
  });
  container.addEventListener('dragover', function (e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    let item = e.target.closest('.toolbar-config-item');
    if (!item || item === dragSrc) return;
    const rect = item.getBoundingClientRect();
    const midY = rect.top + rect.height / 2;
    if (e.clientY < midY) {
      container.insertBefore(dragSrc, item);
    } else {
      container.insertBefore(dragSrc, item.nextSibling);
    }
  });
  container.addEventListener('dragend', function () {
    if (dragSrc) dragSrc.classList.remove('dragging');
    dragSrc = null;
    saveToolbarConfigFromDOM();
  });
  container.addEventListener('drop', function (e) {
    e.preventDefault();
  });
}

function renderToolbarConfig() {
  chrome.storage.local.get(['pentestSettings'], function (result) {
    let settings = result.pentestSettings || {};
    const config = getToolbarConfig(settings);
    const container = $('toolbar-config-list');
    if (!container) return;
    container.innerHTML = '';

    var lastCatId = null;
    config.forEach(function (tab) {
      var cat = TAB_TO_CATEGORY_OPT[tab.id];
      if (cat && cat.id !== lastCatId) {
        lastCatId = cat.id;
        var header = document.createElement('div');
        header.className = 'toolbar-config-category';
        header.innerHTML =
          '<span class="toolbar-cat-dot" style="background:' +
          cat.color +
          '"></span>' +
          escapeHtml(cat.label);
        container.appendChild(header);
      }
      if (!cat && lastCatId !== '_uncategorized') {
        lastCatId = '_uncategorized';
        var miscHeader = document.createElement('div');
        miscHeader.className = 'toolbar-config-category';
        miscHeader.textContent = '其他';
        container.appendChild(miscHeader);
      }
      var item = document.createElement('div');
      item.className = 'toolbar-config-item';
      item.draggable = true;
      item.dataset.id = tab.id;
      item.innerHTML =
        '<span class="toolbar-drag-handle" title="拖拽排序">&#9776;</span>' +
        '<label><input type="checkbox"' +
        (tab.visible ? ' checked' : '') +
        '> ' +
        escapeHtml(tab.label) +
        '</label>';
      container.appendChild(item);
    });

    initToolbarDragDrop(container);
    container.addEventListener('change', function (e) {
      if (e.target.type !== 'checkbox') return;
      var checkedCount = container.querySelectorAll('input[type="checkbox"]:checked').length;
      if (checkedCount === 0) {
        e.target.checked = true;
        showStatus('至少保留一个可见工具', 'error');
        return;
      }
      saveToolbarConfigFromDOM();
    });
  });
}

// ====== End Toolbar Configuration ======

// HaE rules management loaded from hae-rules.js

function saveSettings() {
  let el;
  const settings = {
    enableNotifications: (el = $('enableNotifications')) ? el.checked : true,
    enableContextMenu: (el = $('enableContextMenu')) ? el.checked : true,
    theme: (el = $('theme')) ? el.value : 'auto',
    storeHistory: (el = $('storeHistory')) ? el.checked : true,
    defaultEncoding: (el = $('defaultEncoding')) ? el.value : 'base64',
    defaultHash: (el = $('defaultHash')) ? el.value : 'SHA256',
    domainExcludeList: (el = $('domain-exclude-list')) ? el.value : '',
    fuzzDefaultWordlist: (el = $('fuzz-default-wordlist')) ? el.value : 'common',
    fuzzDefaultConcurrency: (el = $('fuzz-default-concurrency')) ? parseInt(el.value, 10) || 5 : 5,
    xssDefaultTimeout: (el = $('xss-default-timeout')) ? parseInt(el.value, 10) || 10000 : 10000,
  };

  chrome.storage.local.set({ pentestSettings: settings }, () => {
    if (chrome.runtime.lastError) {
      showStatus('保存失败: ' + chrome.runtime.lastError.message, 'error');
      return;
    }
    showStatus('设置已保存', 'success');
  });
}

function loadSettings() {
  chrome.storage.local.get(['pentestSettings'], result => {
    const settings = result.pentestSettings || {};
    let el;
    if ((el = $('enableNotifications'))) el.checked = settings.enableNotifications !== false;
    if ((el = $('enableContextMenu'))) el.checked = settings.enableContextMenu !== false;
    if ((el = $('theme'))) el.value = settings.theme || 'auto';
    if ((el = $('storeHistory'))) el.checked = settings.storeHistory !== false;
    if ((el = $('defaultEncoding'))) el.value = settings.defaultEncoding || 'base64';
    if ((el = $('defaultHash'))) el.value = settings.defaultHash || 'SHA256';
    if ((el = $('domain-exclude-list'))) el.value = settings.domainExcludeList || '';
    if ((el = $('fuzz-default-wordlist'))) el.value = settings.fuzzDefaultWordlist || 'common';
    if ((el = $('fuzz-default-concurrency'))) el.value = settings.fuzzDefaultConcurrency || 5;
    if ((el = $('xss-default-timeout'))) el.value = settings.xssDefaultTimeout || 10000;
  });
}

var _toastEl = null;
var _toastTimer = null;

function showStatus(message, type) {
  type = type || 'info';
  if (!_toastEl) {
    _toastEl = document.createElement('div');
    _toastEl.className = 'options-toast';
    document.body.appendChild(_toastEl);
  }
  clearTimeout(_toastTimer);
  _toastEl.textContent = message;
  _toastEl.className = 'options-toast ' + type;
  requestAnimationFrame(function () {
    _toastEl.classList.add('show');
  });
  _toastTimer = setTimeout(function () {
    _toastEl.classList.remove('show');
  }, 3000);
}

function exportSettings() {
  chrome.storage.local.get(['pentestSettings'], result => {
    const dataStr = JSON.stringify(result.pentestSettings || {}, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'lingmou-settings.json';
    a.click();

    URL.revokeObjectURL(url);
    showStatus('设置已导出', 'success');
  });
}

function importSettings() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = function (e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (evt) {
      try {
        const data = JSON.parse(evt.target.result);
        if (typeof data !== 'object' || data === null || Array.isArray(data)) {
          showStatus('设置格式错误：需要 JSON 对象', 'error');
          return;
        }
        const knownKeys = {
          enableNotifications: 'boolean',
          enableContextMenu: 'boolean',
          theme: 'string',
          storeHistory: 'boolean',
          defaultEncoding: 'string',
          defaultHash: 'string',
          toolbarConfig: 'object',
          domainExcludeList: 'string',
          fuzzDefaultWordlist: 'string',
          fuzzDefaultConcurrency: 'number',
          xssDefaultTimeout: 'number',
        };
        const cleaned = {};
        let skipped = 0;
        for (let key in data) {
          if (!data.hasOwnProperty(key)) continue;
          if (!knownKeys[key]) {
            skipped++;
            continue;
          }
          if (typeof data[key] !== knownKeys[key]) {
            skipped++;
            continue;
          }
          if (key === 'toolbarConfig' && !Array.isArray(data[key])) {
            skipped++;
            continue;
          }
          cleaned[key] = data[key];
        }
        chrome.storage.local.set({ pentestSettings: cleaned }, () => {
          if (chrome.runtime.lastError) {
            showStatus('导入失败: ' + chrome.runtime.lastError.message, 'error');
            return;
          }
          loadSettings();
          let msg = '设置已导入';
          if (skipped > 0) msg += '（跳过 ' + skipped + ' 个无效字段）';
          showStatus(msg, 'success');
        });
      } catch {
        showStatus('文件格式错误：无法解析 JSON', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function clearData() {
  if (confirm('确定要清除所有数据吗？此操作不可恢复。')) {
    chrome.storage.local.get(null, function (allData) {
      var keysToRemove = Object.keys(allData).filter(function (key) {
        return !key.startsWith('context') && key !== '__vk_ruoyi_event';
      });
      var known = [
        'pentestSettings',
        'pentest_keys',
        'haeRules',
        'gatherData',
        'gatherDataUrl',
        'gatherDataTabs',
        'gatherDataTime',
        'allLinks',
        'allLinksUrl',
        'pentest_spoof',
        'pentest_ui_state',
        'remotePayloads',
        'payloadRemoteUrl',
        'payloadVersion',
        'ruoyiHookTabId',
        'ruoyiHookEnabled',
        'ruoyiHookOrigin',
        'js_blocked_tabId',
        'permInterceptTabId',
      ];
      known.forEach(function (k) {
        if (keysToRemove.indexOf(k) === -1) keysToRemove.push(k);
      });
      chrome.storage.local.remove(keysToRemove, function () {
        if (chrome.runtime.lastError) {
          showStatus('清除失败: ' + chrome.runtime.lastError.message, 'error');
          return;
        }
        loadSettings();
        loadApiKeys();
        renderStorageOverview();
        renderToolbarConfig();
        showStatus('所有数据已清除', 'success');
      });
    });
  }
}

function resetSettings() {
  if (confirm('确定要重置为默认设置吗？')) {
    chrome.storage.local.remove(['pentestSettings'], () => {
      if (chrome.runtime.lastError) {
        showStatus('重置失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      loadSettings();
      showStatus('设置已重置', 'success');
    });
  }
}

function initScrollSpy() {
  var sections = document.querySelectorAll('.options-section[id]');
  var navItems = document.querySelectorAll('.sidebar-nav-item');
  if (!sections.length || !navItems.length) return;

  var observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var id = entry.target.id;
          navItems.forEach(function (item) {
            item.classList.toggle('active', item.getAttribute('href') === '#' + id);
          });
        }
      });
    },
    { rootMargin: '-20% 0px -70% 0px' }
  );

  sections.forEach(function (s) {
    observer.observe(s);
  });

  navItems.forEach(function (item) {
    item.addEventListener('click', function (e) {
      e.preventDefault();
      var target = document.querySelector(item.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

// ====== Storage Management ======

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function renderStorageOverview() {
  var knownKeys = [
    { key: 'pentestSettings', label: '通用设置' },
    { key: 'pentest_keys', label: 'API 密钥' },
    { key: 'haeRules', label: 'HaE 规则' },
    { key: 'gatherData', label: '采集数据' },
    { key: 'gatherDataUrl', label: '采集来源' },
    { key: 'gatherDataTabs', label: '采集标签' },
    { key: 'gatherDataTime', label: '采集时间' },
    { key: 'allLinks', label: '链接数据' },
    { key: 'allLinksUrl', label: '链接来源' },
    { key: 'pentest_spoof', label: '伪装状态' },
    { key: 'remotePayloads', label: '远程载荷' },
    { key: 'payloadRemoteUrl', label: '载荷 URL' },
    { key: 'payloadVersion', label: '载荷版本' },
    { key: 'pentest_ui_state', label: 'UI 状态' },
  ];

  chrome.storage.local.get(
    knownKeys.map(function (k) {
      return k.key;
    }),
    function (result) {
      var container = $('storage-overview');
      if (!container) return;
      container.innerHTML = '';

      var totalBytes = 0;
      knownKeys.forEach(function (item) {
        var val = result[item.key];
        if (val === undefined) return;
        var json = JSON.stringify(val);
        var bytes = new Blob([json]).size;
        totalBytes += bytes;

        var row = document.createElement('div');
        row.className = 'storage-item';
        row.innerHTML =
          '<span class="storage-label">' +
          escapeHtml(item.label) +
          '</span>' +
          '<span class="storage-size">' +
          formatBytes(bytes) +
          '</span>';
        container.appendChild(row);
      });

      var totalEl = $('storage-total');
      if (totalEl) totalEl.textContent = '总计: ' + formatBytes(totalBytes);
    }
  );
}

function clearStorageCategory(keys, label) {
  if (!confirm('确定要清除 ' + label + ' 吗？')) return;
  chrome.storage.local.remove(keys, function () {
    if (chrome.runtime.lastError) {
      showStatus('清除失败: ' + chrome.runtime.lastError.message, 'error');
      return;
    }
    showStatus(label + ' 已清除', 'success');
    renderStorageOverview();
  });
}

// ====== API Key Management ======

var _cryptoCache = null;

async function _getCryptoKey() {
  if (_cryptoCache) return _cryptoCache;
  var extId = chrome.runtime.id;
  var enc = new TextEncoder();
  var keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode('vulnkit-key-v1:' + extId),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  _cryptoCache = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('vulnkit-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return _cryptoCache;
}

async function _decryptValue(encrypted) {
  if (!encrypted || !encrypted.startsWith('enc:aes256:gcm:')) return encrypted;
  var raw = atob(encrypted.slice(14));
  var iv = new Uint8Array(
    raw.length > 12
      ? raw
          .slice(0, 12)
          .split('')
          .map(function (c) {
            return c.charCodeAt(0);
          })
      : []
  );
  var data = new Uint8Array(
    raw.length > 12
      ? raw
          .slice(12)
          .split('')
          .map(function (c) {
            return c.charCodeAt(0);
          })
      : []
  );
  var key = await _getCryptoKey();
  var decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
  return new TextDecoder().decode(decrypted);
}

async function _encryptValue(plain) {
  if (!plain) return '';
  var enc = new TextEncoder();
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var key = await _getCryptoKey();
  var encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(plain));
  var combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return 'enc:aes256:gcm:' + btoa(String.fromCharCode.apply(null, combined));
}

var API_KEY_FIELDS = [
  { id: 'opt-key-fofa-email', storageKey: 'fofa_email' },
  { id: 'opt-key-fofa-key', storageKey: 'fofa_key' },
  { id: 'opt-key-zoomeye', storageKey: 'zoomeye' },
  { id: 'opt-key-shodan', storageKey: 'shodan' },
];

function loadApiKeys() {
  chrome.storage.local.get(['pentest_keys'], async function (result) {
    var keys = result.pentest_keys || {};
    for (var i = 0; i < API_KEY_FIELDS.length; i++) {
      var f = API_KEY_FIELDS[i];
      var el = $(f.id);
      if (el && keys[f.storageKey]) {
        try {
          el.value = await _decryptValue(keys[f.storageKey]);
        } catch (e) {
          el.value = '';
        }
      }
    }
  });
}

async function saveApiKeys() {
  var keys = {};
  for (var i = 0; i < API_KEY_FIELDS.length; i++) {
    var f = API_KEY_FIELDS[i];
    var el = $(f.id);
    if (el && el.value.trim()) {
      keys[f.storageKey] = await _encryptValue(el.value.trim());
    }
  }
  chrome.storage.local.get(['pentest_keys'], function (result) {
    var existing = result.pentest_keys || {};
    var updated = Object.assign({}, existing, keys);
    API_KEY_FIELDS.forEach(function (f) {
      var el = $(f.id);
      if (!el || !el.value.trim()) delete updated[f.storageKey];
    });
    chrome.storage.local.set({ pentest_keys: updated }, function () {
      if (chrome.runtime.lastError) {
        showStatus('保存失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      showStatus('API 密钥已保存', 'success');
    });
  });
}

// ====== Full Backup ======

function exportFullData() {
  chrome.storage.local.get(null, function (allData) {
    var transientKeys = [
      'contextExtractedLinks',
      'contextExtractedUrl',
      'contextSelection',
      'contextAction',
      'contextExtractUrl',
      'exif_pending_url',
      'ruoyiHookTabId',
      'ruoyiHookEnabled',
      'ruoyiHookOrigin',
      'js_blocked_tabId',
      'permInterceptTabId',
      '__vk_ruoyi_event',
    ];
    var exportData = {};
    for (var key in allData) {
      if (!allData.hasOwnProperty(key)) continue;
      if (transientKeys.indexOf(key) === -1) {
        exportData[key] = allData[key];
      }
    }
    var dataStr = JSON.stringify(exportData, null, 2);
    var blob = new Blob([dataStr], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'lingmou-full-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
    showStatus('完整数据已导出', 'success');
  });
}

function importFullData() {
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = function (e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (evt) {
      try {
        var data = JSON.parse(evt.target.result);
        if (typeof data !== 'object' || data === null || Array.isArray(data)) {
          showStatus('文件格式错误：需要 JSON 对象', 'error');
          return;
        }
        var validKeys = [
          'pentestSettings',
          'pentest_keys',
          'haeRules',
          'gatherData',
          'gatherDataUrl',
          'gatherDataTabs',
          'gatherDataTime',
          'allLinks',
          'allLinksUrl',
          'pentest_spoof',
          'pentest_ui_state',
          'remotePayloads',
          'payloadRemoteUrl',
          'payloadVersion',
        ];
        var cleaned = {};
        var imported = 0;
        for (var key in data) {
          if (!data.hasOwnProperty(key)) continue;
          if (validKeys.indexOf(key) !== -1) {
            cleaned[key] = data[key];
            imported++;
          }
        }
        if (imported === 0) {
          showStatus('文件中没有找到有效的数据', 'error');
          return;
        }
        chrome.storage.local.set(cleaned, function () {
          if (chrome.runtime.lastError) {
            showStatus('导入失败: ' + chrome.runtime.lastError.message, 'error');
            return;
          }
          loadSettings();
          renderStorageOverview();
          loadApiKeys();
          showStatus('已导入 ' + imported + ' 项数据', 'success');
        });
      } catch (err) {
        showStatus('文件格式错误：无法解析 JSON', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

// ====== End Storage Management ======

document.addEventListener('DOMContentLoaded', () => {
  // Sync theme from popup's localStorage preference
  const savedTheme = localStorage.getItem('pentest-theme');
  if (savedTheme && savedTheme !== 'light') {
    document.documentElement.setAttribute('data-theme', savedTheme);
  }
  // Listen for theme changes from popup (same origin localStorage)
  window.addEventListener('storage', function (e) {
    if (e.key === 'pentest-theme') {
      let theme = e.newValue || 'light';
      document.documentElement.setAttribute('data-theme', theme);
    }
  });

  const version = chrome.runtime.getManifest().version;
  const versionEl = $('version');
  if (versionEl) versionEl.textContent = version;

  loadSettings();
  renderToolbarConfig();
  renderHaeRules();

  let btn;
  if ((btn = $('toolbar-reset-order')))
    btn.addEventListener('click', function () {
      const defaultConfig = DEFAULT_TABS.map(function (t) {
        return { id: t.id, label: t.label, visible: true };
      });
      chrome.storage.local.get(['pentestSettings'], function (result) {
        const settings = result.pentestSettings || {};
        settings.toolbarConfig = defaultConfig;
        chrome.storage.local.set({ pentestSettings: settings }, function () {
          renderToolbarConfig();
          showStatus('工具栏已恢复默认顺序', 'success');
        });
      });
    });
  if ((btn = $('export-btn'))) btn.addEventListener('click', exportSettings);
  if ((btn = $('import-btn'))) btn.addEventListener('click', importSettings);
  if ((btn = $('clear-btn'))) btn.addEventListener('click', clearData);
  if ((btn = $('reset-btn'))) btn.addEventListener('click', resetSettings);
  if ((btn = $('hae-export-yaml'))) btn.addEventListener('click', exportHaeYaml);
  if ((btn = $('hae-import-yaml'))) btn.addEventListener('click', importHaeYaml);
  if ((btn = $('hae-reset-rules'))) btn.addEventListener('click', resetHaeRules);

  // Storage management
  renderStorageOverview();
  loadApiKeys();

  if ((btn = $('save-api-keys'))) btn.addEventListener('click', saveApiKeys);
  if ((btn = $('clear-api-keys')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['pentest_keys'], 'API 密钥');
    });
  if ((btn = $('clear-api-keys-alt')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['pentest_keys'], 'API 密钥');
    });
  if ((btn = $('clear-gather')))
    btn.addEventListener('click', function () {
      clearStorageCategory(
        ['gatherData', 'gatherDataUrl', 'gatherDataTabs', 'gatherDataTime'],
        '采集数据'
      );
    });
  if ((btn = $('clear-links')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['allLinks', 'allLinksUrl'], '链接数据');
    });
  if ((btn = $('clear-spoof')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['pentest_spoof'], '伪装状态');
    });
  if ((btn = $('clear-payload')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['remotePayloads', 'payloadRemoteUrl', 'payloadVersion'], '远程载荷');
    });
  if ((btn = $('clear-ui-state')))
    btn.addEventListener('click', function () {
      clearStorageCategory(['pentest_ui_state'], 'UI 状态');
    });
  if ((btn = $('clear-temp-state')))
    btn.addEventListener('click', function () {
      clearStorageCategory(
        [
          'ruoyiHookTabId',
          'ruoyiHookEnabled',
          'ruoyiHookOrigin',
          'js_blocked_tabId',
          'permInterceptTabId',
        ],
        '临时状态'
      );
    });
  if ((btn = $('export-full-btn'))) btn.addEventListener('click', exportFullData);
  if ((btn = $('import-full-btn'))) btn.addEventListener('click', importFullData);

  document.querySelectorAll('input, select').forEach(input => {
    input.addEventListener('change', saveSettings);
  });

  var domainListEl = $('domain-exclude-list');
  if (domainListEl) {
    var _domainSaveTimer = null;
    domainListEl.addEventListener('input', function () {
      clearTimeout(_domainSaveTimer);
      _domainSaveTimer = setTimeout(saveSettings, 500);
    });
  }

  // Theme select also syncs to localStorage so popup picks it up
  const themeSelect = $('theme');
  if (themeSelect) {
    themeSelect.addEventListener('change', function () {
      const theme =
        this.value === 'auto'
          ? window.matchMedia('(prefers-color-scheme: dark)').matches
            ? 'dark'
            : 'light'
          : this.value;
      localStorage.setItem('pentest-theme', theme);
      document.documentElement.setAttribute('data-theme', theme);
    });
  }

  initScrollSpy();
});
