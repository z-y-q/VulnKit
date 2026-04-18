function saveSettings() {
  const settings = {
    enableNotifications: document.getElementById('enableNotifications').checked,
    enableContextMenu: document.getElementById('enableContextMenu').checked,
    theme: document.getElementById('theme').value,
    storeHistory: document.getElementById('storeHistory').checked,
    analytics: document.getElementById('analytics').checked,
    defaultEncoding: document.getElementById('defaultEncoding').value,
    defaultHash: document.getElementById('defaultHash').value,
  };

  chrome.storage.local.set({ pentestSettings: settings }, () => {
    showStatus('设置已保存', 'success');
  });
}

function loadSettings() {
  chrome.storage.local.get(['pentestSettings'], result => {
    const settings = result.pentestSettings || {};

    document.getElementById('enableNotifications').checked = settings.enableNotifications !== false;
    document.getElementById('enableContextMenu').checked = settings.enableContextMenu !== false;
    document.getElementById('theme').value = settings.theme || 'auto';
    document.getElementById('storeHistory').checked = settings.storeHistory !== false;
    document.getElementById('analytics').checked = settings.analytics || false;
    document.getElementById('defaultEncoding').value = settings.defaultEncoding || 'base64';
    document.getElementById('defaultHash').value = settings.defaultHash || 'SHA256';
  });
}

function showStatus(message, type) {
  type = type || 'info';
  const status = document.getElementById('status');
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
    a.download = 'pentest-tools-settings.json';
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
        const settings = JSON.parse(evt.target.result);
        chrome.storage.local.set({ pentestSettings: settings }, () => {
          loadSettings();
          showStatus('设置已导入', 'success');
        });
      } catch {
        showStatus('文件格式错误', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function clearData() {
  if (confirm('确定要清除所有数据吗？此操作不可恢复。')) {
    chrome.storage.local.clear(() => {
      showStatus('所有数据已清除', 'success');
    });
  }
}

function resetSettings() {
  if (confirm('确定要重置为默认设置吗？')) {
    chrome.storage.local.remove(['pentestSettings'], () => {
      loadSettings();
      showStatus('设置已重置', 'success');
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const version = chrome.runtime.getManifest().version;
  const versionEl = document.getElementById('version');
  if (versionEl) versionEl.textContent = version;

  loadSettings();

  document.getElementById('export-btn').addEventListener('click', exportSettings);
  document.getElementById('import-btn').addEventListener('click', importSettings);
  document.getElementById('clear-btn').addEventListener('click', clearData);
  document.getElementById('reset-btn').addEventListener('click', resetSettings);

  document.querySelectorAll('input, select').forEach(input => {
    input.addEventListener('change', saveSettings);
  });
});
