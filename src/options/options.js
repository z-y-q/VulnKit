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
    chrome.storage.local.remove(
      ['pentestSettings', 'pentest_history', 'pentest_spoof', 'pentest_keys'],
      () => {
        showStatus('所有数据已清除', 'success');
      }
    );
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
});
