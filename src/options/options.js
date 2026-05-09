function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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
];

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
    config.forEach(function (tab) {
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
      let checkedCount = container.querySelectorAll('input[type="checkbox"]:checked').length;
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

function saveSettings() {
  let el;
  const settings = {
    enableNotifications: (el = $('enableNotifications')) ? el.checked : true,
    enableContextMenu: (el = $('enableContextMenu')) ? el.checked : true,
    theme: (el = $('theme')) ? el.value : 'auto',
    storeHistory: (el = $('storeHistory')) ? el.checked : true,
    analytics: (el = $('analytics')) ? el.checked : false,
    defaultEncoding: (el = $('defaultEncoding')) ? el.value : 'base64',
    defaultHash: (el = $('defaultHash')) ? el.value : 'SHA256',
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
    if ((el = $('analytics'))) el.checked = settings.analytics || false;
    if ((el = $('defaultEncoding'))) el.value = settings.defaultEncoding || 'base64';
    if ((el = $('defaultHash'))) el.value = settings.defaultHash || 'SHA256';
  });
}

function showStatus(message, type) {
  type = type || 'info';
  const status = $('status');
  if (!status) return;
  status.textContent = message;
  status.className = 'status ' + type;

  setTimeout(() => {
    status.className = 'status status-hidden';
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
          analytics: 'boolean',
          defaultEncoding: 'string',
          defaultHash: 'string',
          toolbarConfig: 'object',
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
    chrome.storage.local.remove(
      ['pentestSettings', 'pentest_history', 'pentest_spoof', 'pentest_keys'],
      () => {
        if (chrome.runtime.lastError) {
          showStatus('清除失败: ' + chrome.runtime.lastError.message, 'error');
          return;
        }
        showStatus('所有数据已清除', 'success');
      }
    );
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

  document.querySelectorAll('input, select').forEach(input => {
    input.addEventListener('change', saveSettings);
  });

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
});
