// vk-storage-check.js -- 灵眸 Chrome Extension
// Browser storage inspector: localStorage, sessionStorage, IndexedDB

import { utilsProxy as utils } from './vk-namespace.js';
import { saveScanResult } from './vk-scan-history.js';

// ====== Sensitive patterns ======

var KEY_PATTERNS = [
  'token',
  'auth',
  'session',
  'password',
  'passwd',
  'secret',
  'api_key',
  'apikey',
  'bearer',
  'access_token',
  'refresh_token',
  'private_key',
  'credential',
  'jwt',
  'id_token',
  'stripe',
  'twilio',
  'sendgrid',
  'mailgun',
  'nexmo',
  'api_secret',
  'apisecret',
  'secret_key',
  'secretkey',
  'privatekey',
  'auth_token',
  'db_password',
  'db_host',
  'db_port',
  'connection_string',
  'conn_str',
  'firebase',
  'supabase',
];

var VALUE_PATTERNS = [
  { regex: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, label: 'JWT Token' },
  { regex: /^Bearer\s+/i, label: 'Bearer Token' },
  { regex: /^sk-[A-Za-z0-9]{20,}$/, label: 'OpenAI API Key' },
  { regex: /^AKIA[A-Z0-9]{16}$/, label: 'AWS Access Key' },
  { regex: /-----BEGIN.*PRIVATE KEY-----/, label: 'PEM Private Key' },
  { regex: /^[a-f0-9]{32,}$/, label: 'Hex Hash/Key' },
  { regex: /^(pk|sk|rk)_live_[A-Za-z0-9]{24,}$/, label: 'Stripe API Key' },
  { regex: /^(pk|sk|rk)_test_[A-Za-z0-9]{24,}$/, label: 'Stripe Test Key' },
  { regex: /^ghp_[A-Za-z0-9]{36,}$/, label: 'GitHub PAT' },
  { regex: /^gho_[A-Za-z0-9]{36,}$/, label: 'GitHub OAuth Token' },
  { regex: /^ghs_[A-Za-z0-9]{36,}$/, label: 'GitHub App Token' },
  { regex: /^ghu_[A-Za-z0-9]{36,}$/, label: 'GitHub User Token' },
  { regex: /^xox[bpas]-[A-Za-z0-9-]{10,}$/, label: 'Slack Token' },
  {
    regex: /^hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    label: 'Slack Webhook',
  },
  { regex: /^wif-[a-f0-9-]{36,}$/, label: 'GCP Service Account Key' },
  { regex: /^AIza[A-Za-z0-9_-]{35}$/, label: 'Google API Key' },
  { regex: /^[a-f0-9]{64}$/, label: 'SHA-256 Hash' },
  { regex: /^[A-Za-z0-9+/]{40,}={0,2}$/, label: 'Base64 Encoded Data' },
  { regex: /^mysql:\/\/[^\s]+/, label: 'MySQL Connection String' },
  { regex: /^postgres(?:ql)?:\/\/[^\s]+/, label: 'PostgreSQL Connection String' },
  { regex: /^mongodb(?:\+srv)?:\/\/[^\s]+/, label: 'MongoDB Connection String' },
  { regex: /^redis:\/\/[^\s]+/, label: 'Redis Connection String' },
  { regex: /^amqp(?:s)?:\/\/[^\s]+/, label: 'RabbitMQ Connection String' },
  {
    regex: /^[A-F0-9]{8}-[A-F0-9]{4}-4[A-F0-9]{3}-[89AB][A-F0-9]{3}-[A-F0-9]{12}$/i,
    label: 'UUID Token',
  },
  { regex: /^AC[a-f0-9]{32}$/, label: 'Twilio Account SID' },
  { regex: /^SK[a-f0-9]{32}$/, label: 'Twilio Auth Token' },
  { regex: /^NDA[0-9A-Z]{24,}$/, label: 'Nexmo API Key' },
  { regex: /^(?:MII[A-Za-z0-9+/]{4,})/, label: 'X.509 Certificate' },
  { regex: /^-----BEGIN CERTIFICATE-----/, label: 'PEM Certificate' },
  { regex: /^-----BEGIN RSA PRIVATE KEY-----/, label: 'RSA Private Key' },
  { regex: /^-----BEGIN EC PRIVATE KEY-----/, label: 'EC Private Key' },
  { regex: /^-----BEGIN OPENSSH PRIVATE KEY-----/, label: 'OpenSSH Private Key' },
  { regex: /^[a-zA-Z0-9+/]{200,}={0,2}$/, label: 'Long Base64 (Possible Secret)' },
];

// ====== State ======

var SC_SORT_FNS = {
  sensitivity: function (a, b) {
    return (b.isSensitive ? 1 : 0) - (a.isSensitive ? 1 : 0);
  },
  key: function (a, b) {
    return (a.key || '').localeCompare(b.key || '');
  },
};

var state = {
  localItems: [],
  sessionItems: [],
  idbInfo: null,
  lastScanUrl: '',
};

// ====== Sensitivity check ======

function checkSensitivity(key, value) {
  var keyLower = (key || '').toLowerCase();
  var patterns = [];
  var valStr = typeof value === 'string' ? value : String(value || '');

  for (var i = 0; i < KEY_PATTERNS.length; i++) {
    if (keyLower.indexOf(KEY_PATTERNS[i]) !== -1) {
      patterns.push(KEY_PATTERNS[i]);
    }
  }

  for (var j = 0; j < VALUE_PATTERNS.length; j++) {
    if (VALUE_PATTERNS[j].regex.test(valStr)) {
      patterns.push(VALUE_PATTERNS[j].label);
    }
  }

  var unique = [];
  var seen = {};
  for (var k = 0; k < patterns.length; k++) {
    if (!seen[patterns[k]]) {
      seen[patterns[k]] = true;
      unique.push(patterns[k]);
    }
  }

  return {
    isSensitive: unique.length > 0,
    patterns: unique,
  };
}

// ====== Read functions ======

function readWebStorage(type) {
  var storageType = type; // 'local' or 'session'
  return utils.withTab(async function (tab) {
    var items = await utils.execInTabData(
      tab.id,
      function (stype) {
        var storage = stype === 'local' ? localStorage : sessionStorage;
        var result = [];
        var len = Math.min(storage.length, 500);
        for (var i = 0; i < len; i++) {
          var key = storage.key(i);
          if (key === null) continue;
          result.push({ key: key, value: storage.getItem(key) });
        }
        return result;
      },
      { world: 'MAIN', args: [storageType] },
      []
    );

    var enriched = [];
    for (var i = 0; i < items.length; i++) {
      var sens = checkSensitivity(items[i].key, items[i].value);
      enriched.push({
        key: items[i].key,
        value: items[i].value,
        isSensitive: sens.isSensitive,
        matchedPatterns: sens.patterns,
        storageType: type,
      });
    }

    if (type === 'local') state.localItems = enriched;
    else state.sessionItems = enriched;

    return enriched;
  });
}

function readIndexedDB() {
  return utils.withTab(async function (tab) {
    var info = await utils.execInTabData(
      tab.id,
      async function () {
        try {
          var dbs = await indexedDB.databases();
          if (!dbs || dbs.length === 0) return { databases: [] };

          var result = [];
          for (var i = 0; i < dbs.length; i++) {
            var dbInfo = dbs[i];
            try {
              var db = await new Promise(function (resolve, reject) {
                var req = indexedDB.open(dbInfo.name, dbInfo.version);
                req.onsuccess = function () {
                  resolve(req.result);
                };
                req.onerror = function () {
                  reject(req.error);
                };
              });
              var stores = [];
              for (var s = 0; s < db.objectStoreNames.length; s++) {
                var storeName = db.objectStoreNames[s];
                try {
                  var tx = db.transaction(storeName, 'readonly');
                  var store = tx.objectStore(storeName);
                  var count = await new Promise(function (res, rej) {
                    var r = store.count();
                    r.onsuccess = function () {
                      res(r.result);
                    };
                    r.onerror = function () {
                      rej(r.error);
                    };
                  });
                  var records = [];
                  if (count > 0 && count <= 100) {
                    records = await new Promise(function (res, rej) {
                      var r = store.getAll();
                      r.onsuccess = function () {
                        res(r.result);
                      };
                      r.onerror = function () {
                        rej(r.error);
                      };
                    });
                    for (var ri = 0; ri < records.length; ri++) {
                      records[ri] = JSON.stringify(records[ri]);
                      if (records[ri].length > 500) {
                        records[ri] = records[ri].substring(0, 500) + '...';
                      }
                    }
                  }
                  stores.push({ name: storeName, count: count, records: records });
                } catch (e) {
                  stores.push({ name: storeName, count: -1, records: [] });
                }
              }
              db.close();
              result.push({ name: dbInfo.name, version: dbInfo.version, stores: stores });
            } catch (e) {
              result.push({ name: dbInfo.name, version: dbInfo.version || 0, stores: [] });
            }
          }
          return { databases: result };
        } catch (e) {
          return { databases: [], error: e.message };
        }
      },
      { world: 'MAIN' },
      { databases: [] }
    );

    state.idbInfo = info;
    return info;
  });
}

// ====== Render functions ======

function truncate(val, max) {
  var s = typeof val === 'string' ? val : String(val || '');
  return s.length > max ? s.substring(0, max) + '...' : s;
}

function escapeAttr(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderStats(type, items) {
  var el = utils.get('sc-' + type + '-stats');
  if (!el) return;
  var total = items.length;
  var sensCount = 0;
  for (var i = 0; i < items.length; i++) {
    if (items[i].isSensitive) sensCount++;
  }
  el.innerHTML =
    '<span class="stat-badge stat-found">总数 ' +
    total +
    '</span>' +
    (sensCount > 0 ? ' <span class="stat-badge stat-vuln">敏感 ' + sensCount + '</span>' : '');
  el.style.display = '';
}

function renderStorageResults(type) {
  var items = type === 'local' ? state.localItems : state.sessionItems;
  var container = utils.get('sc-' + type + '-results');
  if (!container) return;

  var filterEl = utils.get('sc-' + type + '-filter');
  var searchInput = utils.get('sc-' + type + '-search');
  var filter = 'all';
  var search = searchInput ? (searchInput.value || '').toLowerCase() : '';

  if (filterEl) {
    var activeBtn = filterEl.querySelector('.sc-filter-chip.active');
    if (activeBtn) filter = activeBtn.getAttribute('data-scfilter') || 'all';
  }

  var filtered = items.filter(function (item) {
    if (filter === 'sensitive' && !item.isSensitive) return false;
    if (search) {
      var text = (item.key + ' ' + item.value).toLowerCase();
      if (text.indexOf(search) === -1) return false;
    }
    return true;
  });

  var sortEl = utils.get('sc-' + type + '-sort');
  var sortKey = sortEl ? sortEl.value : '';
  var sorted = utils.applySort(filtered, sortKey, SC_SORT_FNS);

  if (sorted.length === 0) {
    container.innerHTML =
      '<div class="empty-state">' + (items.length === 0 ? '存储为空' : '无匹配结果') + '</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < sorted.length; i++) {
    var item = sorted[i];
    var cls = item.isSensitive ? 'sc-item sc-item-sensitive' : 'sc-item';
    html += '<div class="' + cls + '">';
    html += '<div class="sc-item-header">';
    html +=
      '<span class="sc-item-key" title="' +
      escapeAttr(item.key) +
      '">' +
      utils.escapeHtml(item.key) +
      '</span>';
    html += '<div class="sc-item-actions">';
    if (item.isSensitive) {
      for (var p = 0; p < item.matchedPatterns.length; p++) {
        html +=
          '<span class="sc-sens-badge">' + utils.escapeHtml(item.matchedPatterns[p]) + '</span>';
      }
    }
    html +=
      '<button class="sc-action-btn" data-action="copy" data-type="' +
      type +
      '" data-key="' +
      escapeAttr(item.key) +
      '" title="复制值">&#128203;</button>';
    html +=
      '<button class="sc-action-btn sc-action-delete" data-action="delete" data-type="' +
      type +
      '" data-key="' +
      escapeAttr(item.key) +
      '" title="删除">&#128465;</button>';
    html += '</div></div>';
    html +=
      '<div class="sc-item-value" data-trunc="' +
      escapeAttr(truncate(item.value, 120)) +
      '" data-full="' +
      escapeAttr(item.value) +
      '">' +
      utils.escapeHtml(truncate(item.value, 120)) +
      '</div>';
    html += '</div>';
  }

  container.innerHTML = html;
}

function renderIDBResults() {
  var container = utils.get('sc-idb-results');
  if (!container || !state.idbInfo) return;

  var dbs = state.idbInfo.databases;
  if (!dbs || dbs.length === 0) {
    container.innerHTML = '<div class="empty-state">未发现 IndexedDB 数据库</div>';
    return;
  }

  var html = '';
  for (var d = 0; d < dbs.length; d++) {
    var db = dbs[d];
    html += '<div class="sc-idb-db">';
    html +=
      '<div class="sc-idb-db-name">' +
      utils.escapeHtml(db.name) +
      ' <span class="sc-idb-meta">v' +
      db.version +
      '</span></div>';
    if (db.stores) {
      for (var s = 0; s < db.stores.length; s++) {
        var store = db.stores[s];
        html += '<div class="sc-idb-store">';
        html +=
          '<div class="sc-idb-store-name">' +
          utils.escapeHtml(store.name) +
          ' <span class="sc-idb-meta">' +
          store.count +
          ' 条</span></div>';
        if (store.records && store.records.length > 0) {
          html += '<div class="sc-idb-records">';
          for (var r = 0; r < store.records.length; r++) {
            html +=
              '<div class="sc-idb-record"><code>' +
              utils.escapeHtml(truncate(store.records[r], 200)) +
              '</code></div>';
          }
          html += '</div>';
        }
        html += '</div>';
      }
    }
    html += '</div>';
  }

  container.innerHTML = html;
}

// ====== Action functions ======

function deleteStorageItem(type, key) {
  utils.withTab(async function (tab) {
    await utils.execInTab(
      tab.id,
      function (params) {
        var storage = params.type === 'local' ? localStorage : sessionStorage;
        storage.removeItem(params.key);
      },
      { world: 'MAIN', args: [{ type: type, key: key }] }
    );
    var items = type === 'local' ? state.localItems : state.sessionItems;
    var updated = items.filter(function (item) {
      return item.key !== key;
    });
    if (type === 'local') state.localItems = updated;
    else state.sessionItems = updated;
    renderStorageResults(type);
    renderStats(type, updated);
  });
}

function clearStorage(type) {
  utils
    .confirmDanger(
      '确定清空当前页面的 ' +
        (type === 'local' ? 'localStorage' : 'sessionStorage') +
        '？此操作不可撤销。'
    )
    .then(function (confirmed) {
      if (!confirmed) return;
      utils.withTab(async function (tab) {
        await utils.execInTab(
          tab.id,
          function (stype) {
            var storage = stype === 'local' ? localStorage : sessionStorage;
            storage.clear();
          },
          { world: 'MAIN', args: [type] }
        );
        if (type === 'local') state.localItems = [];
        else state.sessionItems = [];
        renderStorageResults(type);
        renderStats(type, []);
        utils.setStatus('sc-' + type + '-status', '已清空');
      });
    });
}

function copyAllData(type) {
  var items = type === 'local' ? state.localItems : state.sessionItems;
  if (items.length === 0) return;
  var obj = {};
  for (var i = 0; i < items.length; i++) {
    obj[items[i].key] = items[i].value;
  }
  utils.copyAndToast(JSON.stringify(obj, null, 2));
}

function copyIDBData() {
  if (!state.idbInfo || !state.idbInfo.databases || state.idbInfo.databases.length === 0) return;
  utils.copyAndToast(JSON.stringify(state.idbInfo, null, 2));
}

// ====== Filter/Search ======

function bindFilterSearch(type) {
  var filterBar = utils.get('sc-' + type + '-filter');
  if (!filterBar) return;

  filterBar.addEventListener('click', function (e) {
    var btn = e.target.closest('.sc-filter-chip');
    if (!btn) return;
    var chips = filterBar.querySelectorAll('.sc-filter-chip');
    for (var i = 0; i < chips.length; i++) chips[i].classList.remove('active');
    btn.classList.add('active');
    renderStorageResults(type);
  });

  var searchInput = utils.get('sc-' + type + '-search');
  if (searchInput) {
    var timer = null;
    searchInput.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        renderStorageResults(type);
      }, 200);
    });
  }
}

// ====== Event delegation for value expand / actions ======

function bindEventDelegation(type) {
  var container = utils.get('sc-' + type + '-results');
  if (!container) return;

  container.addEventListener('click', function (e) {
    var actionBtn = e.target.closest('.sc-action-btn');
    if (actionBtn) {
      var action = actionBtn.getAttribute('data-action');
      var key = actionBtn.getAttribute('data-key');
      var aType = actionBtn.getAttribute('data-type');
      if (action === 'copy' && key) {
        var items = aType === 'local' ? state.localItems : state.sessionItems;
        for (var i = 0; i < items.length; i++) {
          if (items[i].key === key) {
            utils.copyAndToast(items[i].value);
            return;
          }
        }
      }
      if (action === 'delete' && key) {
        deleteStorageItem(aType, key);
      }
      return;
    }

    var valueEl = e.target.closest('.sc-item-value');
    if (valueEl) {
      valueEl.classList.toggle('expanded');
      if (valueEl.classList.contains('expanded')) {
        valueEl.textContent = valueEl.getAttribute('data-full') || '';
      } else {
        valueEl.textContent = valueEl.getAttribute('data-trunc') || '';
      }
    }
  });
}

// ====== Report integration ======

function getFindings() {
  var findings = [];
  var sources = [
    { items: state.localItems, label: 'localStorage' },
    { items: state.sessionItems, label: 'sessionStorage' },
  ];
  for (var s = 0; s < sources.length; s++) {
    var src = sources[s];
    for (var i = 0; i < src.items.length; i++) {
      var item = src.items[i];
      if (!item.isSensitive) continue;
      findings.push({
        severity: 'medium',
        title: '敏感存储项: ' + item.key,
        detail: src.label + ' — 匹配模式: ' + item.matchedPatterns.join(', '),
        module: 'storage-check',
        url: state.lastScanUrl || '',
      });
    }
  }

  if (state.idbInfo && state.idbInfo.databases) {
    for (var d = 0; d < state.idbInfo.databases.length; d++) {
      var db = state.idbInfo.databases[d];
      for (var st = 0; st < db.stores.length; st++) {
        var store = db.stores[st];
        if (store.count > 0) {
          findings.push({
            severity: 'low',
            title: 'IndexedDB 数据: ' + db.name + '/' + store.name,
            detail: '包含 ' + store.count + ' 条记录',
            module: 'storage-check',
            url: state.lastScanUrl || '',
          });
        }
      }
    }
  }

  utils.getCurrentDomain().then(function (d) {
    if (d) saveScanResult('storage-check', d, findings);
  });

  return findings;
}

function sortResults(type, key) {
  var el = utils.get('sc-' + type + '-sort');
  if (el) {
    el.value = key;
    renderStorageResults(type);
  }
}

export {
  readWebStorage,
  readIndexedDB,
  renderStorageResults,
  renderIDBResults,
  renderStats,
  clearStorage,
  copyAllData,
  copyIDBData,
  bindFilterSearch,
  bindEventDelegation,
  getFindings,
  state,
  sortResults,
};
