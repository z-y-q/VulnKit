// ====== Storage Management ======

const KB = 1024;
const MB = KB * KB;

function formatBytes(bytes) {
  if (bytes < KB) return bytes + ' B';
  if (bytes < MB) return (bytes / KB).toFixed(1) + ' KB';
  return (bytes / MB).toFixed(2) + ' MB';
}

function renderStorageOverview() {
  const knownKeys = [
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
      const container = document.getElementById('storage-overview');
      if (!container) return;
      container.innerHTML = '';

      let totalBytes = 0;
      knownKeys.forEach(function (item) {
        const val = result[item.key];
        if (val === undefined) return;
        const json = JSON.stringify(val);
        const bytes = new Blob([json]).size;
        totalBytes += bytes;

        const row = document.createElement('div');
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

      const totalEl = document.getElementById('storage-total');
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

let _cryptoCache = null;

async function _getCryptoKey() {
  if (_cryptoCache) return _cryptoCache;
  const extId = chrome.runtime.id;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
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
  const raw = atob(encrypted.slice(14));
  const combined = Uint8Array.from(raw, function (c) {
    return c.charCodeAt(0);
  });
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const key = await _getCryptoKey();
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
  return new TextDecoder().decode(decrypted);
}

async function _encryptValue(plain) {
  if (!plain) return '';
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await _getCryptoKey();
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(plain));
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return 'enc:aes256:gcm:' + btoa(String.fromCharCode.apply(null, combined));
}

const API_KEY_FIELDS = [
  { id: 'opt-key-fofa-email', storageKey: 'fofa_email' },
  { id: 'opt-key-fofa-key', storageKey: 'fofa_key' },
  { id: 'opt-key-zoomeye', storageKey: 'zoomeye' },
  { id: 'opt-key-shodan', storageKey: 'shodan' },
];

function loadApiKeys() {
  chrome.storage.local.get(['pentest_keys'], async function (result) {
    const keys = result.pentest_keys || {};
    for (let i = 0; i < API_KEY_FIELDS.length; i++) {
      const f = API_KEY_FIELDS[i];
      const el = document.getElementById(f.id);
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
  const keys = {};
  for (let i = 0; i < API_KEY_FIELDS.length; i++) {
    const f = API_KEY_FIELDS[i];
    const el = document.getElementById(f.id);
    if (el && el.value.trim()) {
      keys[f.storageKey] = await _encryptValue(el.value.trim());
    }
  }
  chrome.storage.local.get(['pentest_keys'], function (result) {
    const existing = result.pentest_keys || {};
    const fieldsToKeep = Object.keys(existing).filter(function (k) {
      const field = API_KEY_FIELDS.find(function (f) {
        return f.storageKey === k;
      });
      if (!field) return true;
      const el = document.getElementById(field.id);
      return el && el.value.trim();
    });
    const updated = {};
    fieldsToKeep.forEach(function (k) {
      updated[k] = existing[k];
    });
    Object.keys(keys).forEach(function (k) {
      updated[k] = keys[k];
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

const FULL_BACKUP_SCHEMA = {
  pentestSettings: 'object',
  pentest_keys: 'object',
  haeRules: 'object',
  gatherData: 'object',
  gatherDataUrl: 'string',
  gatherDataTabs: 'string',
  gatherDataTime: 'string',
  allLinks: 'object',
  allLinksUrl: 'string',
  pentest_spoof: 'object',
  pentest_ui_state: 'object',
  remotePayloads: 'object',
  payloadRemoteUrl: 'string',
  payloadVersion: 'string',
};

const TRANSIENT_KEYS = [
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
];

function exportFullData() {
  chrome.storage.local.get(null, function (allData) {
    const exportData = {};
    for (const key in allData) {
      if (!allData.hasOwnProperty(key)) continue;
      if (TRANSIENT_KEYS.indexOf(key) !== -1) continue;
      exportData[key] = allData[key];
    }
    const dataStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'lingmou-full-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
    showStatus('完整数据已导出（含 API 密钥和采集数据，请妥善保管）', 'success');
  });
}

function importFullData() {
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
          showStatus('文件格式错误：需要 JSON 对象', 'error');
          return;
        }
        const cleaned = {};
        let imported = 0;
        let skipped = 0;
        for (const key in data) {
          if (!data.hasOwnProperty(key)) continue;
          if (!FULL_BACKUP_SCHEMA[key]) {
            skipped++;
            continue;
          }
          if (data[key] === null || typeof data[key] !== FULL_BACKUP_SCHEMA[key]) {
            skipped++;
            continue;
          }
          cleaned[key] = data[key];
          imported++;
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
          renderToolbarConfig();
          let msg = '已导入 ' + imported + ' 项数据';
          if (skipped > 0) msg += '（跳过 ' + skipped + ' 个无效字段）';
          showStatus(msg, 'success');
        });
      } catch (err) {
        showStatus('文件格式错误：无法解析 JSON', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}
