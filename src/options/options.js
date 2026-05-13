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

let TAB_TO_CATEGORY_OPT = {};
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
  const container = $('toolbar-config-list');
  if (!container) return;
  const items = container.querySelectorAll('.toolbar-config-item');
  const config = [];
  items.forEach(function (item) {
    const cb = item.querySelector('input[type="checkbox"]');
    config.push({
      id: item.dataset.id,
      label: item.querySelector('label').textContent.trim(),
      visible: cb ? cb.checked : true,
    });
  });
  chrome.storage.local.get(['pentestSettings'], function (result) {
    const settings = result.pentestSettings || {};
    settings.toolbarConfig = config;
    chrome.storage.local.set({ pentestSettings: settings }, function () {
      showStatus('工具栏配置已保存', 'success');
    });
  });
}

function initToolbarDragDrop(container) {
  let dragSrc = null;
  container.addEventListener('dragstart', function (e) {
    const item = e.target.closest('.toolbar-config-item');
    if (!item) return;
    dragSrc = item;
    item.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', '');
  });
  container.addEventListener('dragover', function (e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const item = e.target.closest('.toolbar-config-item');
    if (!item || item === dragSrc) return;
    const rect = item.getBoundingClientRect();
    if (e.clientY < rect.top + rect.height / 2) {
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
    const settings = result.pentestSettings || {};
    const config = getToolbarConfig(settings);
    const container = $('toolbar-config-list');
    if (!container) return;
    container.innerHTML = '';

    let lastCatId = null;
    config.forEach(function (tab) {
      const cat = TAB_TO_CATEGORY_OPT[tab.id];
      if (cat && cat.id !== lastCatId) {
        lastCatId = cat.id;
        const header = document.createElement('div');
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
        const miscHeader = document.createElement('div');
        miscHeader.className = 'toolbar-config-category';
        miscHeader.textContent = '其他';
        container.appendChild(miscHeader);
      }
      const item = document.createElement('div');
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
      const checkedCount = container.querySelectorAll('input[type="checkbox"]:checked').length;
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

let _toastEl = null;
let _toastTimer = null;

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
        for (const key in data) {
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
      const keysToRemove = Object.keys(allData).filter(function (key) {
        return !key.startsWith('context');
      });
      const known = [
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
  const sections = document.querySelectorAll('.options-section[id]');
  const navItems = document.querySelectorAll('.sidebar-nav-item');
  if (!sections.length || !navItems.length) return;

  const observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          const id = entry.target.id;
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
      const target = document.querySelector(item.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  // Sync theme from popup's localStorage preference
  const savedTheme = localStorage.getItem('pentest-theme');
  if (savedTheme && savedTheme !== 'light') {
    document.documentElement.setAttribute('data-theme', savedTheme);
  }
  window.addEventListener('storage', function (e) {
    if (e.key === 'pentest-theme') {
      const theme = e.newValue || 'light';
      document.documentElement.setAttribute('data-theme', theme);
    }
  });

  const isExtension = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;

  if (isExtension) {
    try {
      const version = chrome.runtime.getManifest().version;
      const versionEl = $('version');
      if (versionEl) versionEl.textContent = version;
    } catch (_) {
      console.debug('options init:', _.message);
    }

    loadSettings();
    renderToolbarConfig();
    renderHaeRules();
    renderStorageOverview();
    loadApiKeys();
  }

  initAllRuleSections();

  let btn;

  // Toolbar
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

  // HaE rules
  if ((btn = $('hae-add-rule'))) btn.addEventListener('click', addHaeRule);
  if ((btn = $('hae-add-group'))) btn.addEventListener('click', addHaeGroup);
  if ((btn = $('hae-validate-all'))) btn.addEventListener('click', validateAllHaeRules);
  if ((btn = $('hae-export-yaml'))) btn.addEventListener('click', exportHaeYaml);
  if ((btn = $('hae-import-yaml'))) btn.addEventListener('click', importHaeYaml);
  if ((btn = $('hae-reset-rules'))) btn.addEventListener('click', resetHaeRules);

  // Settings import/export/clear/reset
  if ((btn = $('export-btn'))) btn.addEventListener('click', exportSettings);
  if ((btn = $('import-btn'))) btn.addEventListener('click', importSettings);
  if ((btn = $('clear-btn'))) btn.addEventListener('click', clearData);
  if ((btn = $('reset-btn'))) btn.addEventListener('click', resetSettings);

  // Storage management — API keys
  if ((btn = $('save-api-keys'))) btn.addEventListener('click', saveApiKeys);
  const clearApiKeysHandler = function () {
    clearStorageCategory(['pentest_keys'], 'API 密钥');
  };
  if ((btn = $('clear-api-keys'))) btn.addEventListener('click', clearApiKeysHandler);
  if ((btn = $('clear-api-keys-alt'))) btn.addEventListener('click', clearApiKeysHandler);

  // Storage management — category clear
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

  // Full backup
  if ((btn = $('export-full-btn'))) btn.addEventListener('click', exportFullData);
  if ((btn = $('import-full-btn'))) btn.addEventListener('click', importFullData);

  // Auto-save on change
  document.querySelectorAll('input, select').forEach(input => {
    input.addEventListener('change', saveSettings);
  });

  const domainListEl = $('domain-exclude-list');
  if (domainListEl) {
    let _domainSaveTimer = null;
    domainListEl.addEventListener('input', function () {
      clearTimeout(_domainSaveTimer);
      _domainSaveTimer = setTimeout(saveSettings, 500);
    });
  }

  // Theme select syncs to localStorage so popup picks it up
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
