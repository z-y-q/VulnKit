function $(id) {
  return document.getElementById(id);
}

function saveSettings() {
  var el;
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
    var el;
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
        var knownKeys = {
          enableNotifications: 'boolean',
          enableContextMenu: 'boolean',
          theme: 'string',
          storeHistory: 'boolean',
          analytics: 'boolean',
          defaultEncoding: 'string',
          defaultHash: 'string',
        };
        var cleaned = {};
        var skipped = 0;
        for (var key in data) {
          if (!data.hasOwnProperty(key)) continue;
          if (!knownKeys[key]) {
            skipped++;
            continue;
          }
          if (typeof data[key] !== knownKeys[key]) {
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
          var msg = '设置已导入';
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
  var savedTheme = localStorage.getItem('pentest-theme');
  if (savedTheme && savedTheme !== 'light') {
    document.documentElement.setAttribute('data-theme', savedTheme);
  }
  // Listen for theme changes from popup (same origin localStorage)
  window.addEventListener('storage', function (e) {
    if (e.key === 'pentest-theme') {
      var theme = e.newValue || 'light';
      document.documentElement.setAttribute('data-theme', theme);
    }
  });

  const version = chrome.runtime.getManifest().version;
  const versionEl = $('version');
  if (versionEl) versionEl.textContent = version;

  loadSettings();

  var btn;
  if ((btn = $('export-btn'))) btn.addEventListener('click', exportSettings);
  if ((btn = $('import-btn'))) btn.addEventListener('click', importSettings);
  if ((btn = $('clear-btn'))) btn.addEventListener('click', clearData);
  if ((btn = $('reset-btn'))) btn.addEventListener('click', resetSettings);

  document.querySelectorAll('input, select').forEach(input => {
    input.addEventListener('change', saveSettings);
  });

  // Theme select also syncs to localStorage so popup picks it up
  var themeSelect = $('theme');
  if (themeSelect) {
    themeSelect.addEventListener('change', function () {
      var theme =
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
