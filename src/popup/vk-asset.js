// 灵眸 - Asset Mapping
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let currentAssetSource = 'fofa';
let lastAssetResults = [];
let customQueryMode = false;

async function getApiKey(source) {
  const result = await chrome.storage.local.get(['pentest_keys']);
  const keys = result.pentest_keys || {};
  if (source === 'fofa') {
    return {
      email: await decryptValue(keys.fofa_email),
      key: await decryptValue(keys.fofa_key),
    };
  }
  if (source === 'zoomeye') return await decryptValue(keys.zoomeye);
  if (source === 'shodan') return await decryptValue(keys.shodan);
  return null;
}

async function getCurrentUrl() {
  const tab = await utils.getActiveTab();
  return tab?.url || null;
}

function setAssetStatus(text) {
  const el = utils.get('asset-status');
  if (el) el.textContent = text;
}

function getAssetSize() {
  const el = utils.get('asset-size');
  return el ? parseInt(el.value, 10) || 10 : 10;
}

let currentSearchFilter = '';

async function fetchScanResults(engineName, url, fetchOpts) {
  setAssetStatus(`正在查询 ${engineName}...`);
  const result = await utils.fetchUrlJson(fetchOpts || { url: url });
  if (!result || !result.success) {
    setAssetStatus(`查询失败: ${result ? result.error : '超时'}`);
    return null;
  }
  const json = result.data;
  if (json.error) {
    setAssetStatus(`API 错误: ${json.message || json.error}`);
    return null;
  }
  return json;
}

const ASSET_FILTER_FIELDS = ['host', 'port', 'protocol', 'title'];

function renderAssetResults(data) {
  let filtered = data || lastAssetResults || [];
  if (currentSearchFilter && filtered.length > 0) {
    filtered = utils.filterByQuery(filtered, currentSearchFilter, ASSET_FILTER_FIELDS);
  }

  const container = utils.get('asset-results');
  if (!container) return;
  const actionsRow = utils.get('asset-actions-row');
  if (data) lastAssetResults = data;
  const hasResults = lastAssetResults.length > 0;
  if (actionsRow) actionsRow.style.display = hasResults ? 'flex' : 'none';
  const searchInput = utils.get('asset-search');
  if (searchInput) searchInput.style.display = hasResults ? '' : 'none';
  if (filtered.length === 0 && !hasResults) {
    utils.setEmpty('asset-results', '未找到结果');
    return;
  }
  if (filtered.length === 0) {
    utils.setEmpty('asset-results', '无匹配结果');
    return;
  }
  const countLabel = currentSearchFilter
    ? `匹配 ${filtered.length} / ${lastAssetResults.length} 条结果`
    : `共 ${filtered.length} 条结果`;
  let html = `<div class="asset-count">${countLabel}</div>`;
  html +=
    '<table class="asset-table"><thead><tr><th>IP/域名</th><th>端口</th><th>协议</th><th>标题</th></tr></thead><tbody>';
  filtered.forEach(function (item) {
    html += `<tr>
      <td title="${utils.escapeHtml(item.host || '')}">${utils.escapeHtml(item.host || '-')}</td>
      <td>${utils.escapeHtml(String(item.port || '-'))}</td>
      <td>${utils.escapeHtml(item.protocol || '-')}</td>
      <td title="${utils.escapeHtml(item.title || '')}">${utils.escapeHtml(item.title || '-')}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  container.innerHTML = html;
}

function applySearchFilter(text) {
  currentSearchFilter = text || '';
  renderAssetResults();
}

function exportData() {
  if (!lastAssetResults || lastAssetResults.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  let data = lastAssetResults;
  if (currentSearchFilter) {
    data = utils.filterByQuery(data, currentSearchFilter, ASSET_FILTER_FIELDS);
  }
  const rows = data.map(function (item) {
    return [item.host, String(item.port || ''), item.protocol, item.title];
  });
  utils.buildCsv(
    ['IP/域名', '端口', '协议', '标题'],
    rows,
    `lingmou-asset-${currentAssetSource}-${Date.now()}.csv`
  );
}

async function scanFofa(query, opts) {
  const keys = await getApiKey('fofa');
  if (!keys?.email || !keys?.key) {
    utils.showToast('请先配置 FOFA API Key', 'warning');
    return [];
  }
  const fofaQuery = customQueryMode ? query : `domain="${query}"`;
  const qbase64 = btoa(unescape(encodeURIComponent(fofaQuery)));
  const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(keys.email)}&key=${encodeURIComponent(keys.key)}&qbase64=${qbase64}&fields=host,port,protocol,title&size=${getAssetSize()}`;

  const json = await fetchScanResults('FOFA', url);
  if (!json) return [];
  const results = (json.results || []).map(function (r) {
    return { host: r[0], port: r[1], protocol: r[2], title: r[3] };
  });
  setAssetStatus(`FOFA: 查询完成 (共 ${json.size || results.length} 条)`);
  if (!opts?.skipRender) renderAssetResults(results);
  return results;
}

async function scanZoomEye(query, opts) {
  let key = await getApiKey('zoomeye');
  key = utils.requireInput(key, '请先配置 ZoomEye API Key');
  if (!key) return [];
  const zoomQuery = customQueryMode ? query : `hostname:${query.replace(/^www\./, '')}`;
  const url = `https://api.zoomeye.org/host/search?query=${encodeURIComponent(zoomQuery)}&page=1&size=${getAssetSize()}`;

  const json = await fetchScanResults('ZoomEye', url, {
    type: 'FETCH_URL_AUTH',
    url: url,
    key: key,
    provider: 'zoomeye',
  });
  if (!json) return [];
  const list = json.matches || json.data || [];
  let total = json.total || list.length;
  if (list.length === 0) {
    setAssetStatus('ZoomEye: 未找到资产 (total=0)');
    if (!opts?.skipRender) renderAssetResults([]);
    return [];
  }
  const results = list.map(function (r) {
    return {
      host: r.ip || '-',
      port: r.portinfo && r.portinfo.port ? r.portinfo.port : '-',
      protocol: (r.portinfo && (r.portinfo.service || r.portinfo.type)) || '-',
      title: (r.webinfo && r.webinfo.title) || (r.portinfo && r.portinfo.product) || '-',
    };
  });
  setAssetStatus(`ZoomEye: 查询完成 (共 ${total} 条)`);
  if (!opts?.skipRender) renderAssetResults(results);
  return results;
}

async function scanShodan(query, opts) {
  let key = await getApiKey('shodan');
  key = utils.requireInput(key, '请先配置 Shodan API Key');
  if (!key) return [];
  const searchQuery = customQueryMode
    ? query
    : /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)
      ? query
      : `hostname:"${query}"`;
  const url = `https://api.shodan.io/shodan/search?key=${encodeURIComponent(key)}&query=${encodeURIComponent(searchQuery)}`;

  const json = await fetchScanResults('Shodan', url);
  if (!json) return [];
  const results = (json.matches || []).slice(0, getAssetSize()).map(function (m) {
    return {
      host: m.ip_str || '-',
      port: m.port || '-',
      protocol: (m._shodan && m._shodan.module) || '-',
      title: (m.http && m.http.title) || '-',
    };
  });
  setAssetStatus(`Shodan: 查询完成 (共 ${json.total || results.length} 条)`);
  if (!opts?.skipRender) renderAssetResults(results);
  return results;
}

function shodanHostLookup() {
  const inputEl = utils.get('shodan-host-input');
  const input = inputEl ? inputEl.value.trim() : '';
  const container = utils.get('shodan-host-info');
  if (!container) return;

  if (!input) {
    utils.getCurrentDomain().then(function (domain) {
      if (!domain) {
        utils.showToast('请输入 IP 或域名', 'warning');
        return;
      }
      if (inputEl) inputEl.value = domain;
      doShodanLookup(domain, container);
    });
    return;
  }
  doShodanLookup(input, container);
}

async function doShodanLookup(input, container) {
  container.innerHTML =
    '<div style="text-align:center;padding:8px;color:#66B2FF;">正在查询...</div>';
  let resolvedIp = null;
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(input);

  // Step 1: resolve domain to IP
  if (!isIp) {
    const dnsResult = await utils.fetchUrlJson({
      url: `https://geonet.shodan.io/api/dns/${encodeURIComponent(input)}`,
    });
    if (dnsResult && dnsResult.success && dnsResult.data) {
      const dnsJson = dnsResult.data;
      if (dnsJson && dnsJson.answers && dnsJson.answers.length > 0) {
        resolvedIp = dnsJson.answers[0].value;
      }
    }
  } else {
    resolvedIp = input;
  }

  // Step 2: query InternetDB
  const targetIp = resolvedIp;
  if (!targetIp || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(targetIp)) {
    container.innerHTML = `<div style="color:#ff6b6b;padding:8px;">无法解析域名 ${utils.escapeHtml(input)} 为 IP 地址，请直接输入 IP</div>`;
    return;
  }
  const idbResult = await utils.fetchUrlJson({
    url: `https://internetdb.shodan.io/${encodeURIComponent(targetIp)}`,
  });
  if (!idbResult || !idbResult.success) {
    container.innerHTML = '<div style="color:#ff6b6b;padding:8px;">未找到该主机的信息</div>';
    return;
  }
  const idbData = idbResult.data;
  if (idbData && idbData.error) {
    container.innerHTML = '<div style="color:#ff6b6b;padding:8px;">未找到该主机的信息</div>';
    return;
  }

  // Step 3: query Shodan API for extra detail
  const shodanKey = await getApiKey('shodan');
  let shodanData = null;
  if (shodanKey && resolvedIp) {
    const hostResult = await utils.fetchUrlJson({
      url: `https://api.shodan.io/shodan/host/${encodeURIComponent(resolvedIp)}?key=${encodeURIComponent(shodanKey)}`,
    });
    if (hostResult && hostResult.success) {
      shodanData = hostResult.data;
    }
  }
  renderShodanHostInfo(container, idbData, shodanData, input, targetIp);
}

function renderShodanHostInfo(container, idbData, shodanData, queryInput, resolvedIp) {
  const esc =
    utils && utils.escapeHtml
      ? function (s) {
          return utils.escapeHtml(String(s == null ? '' : s));
        }
      : function (s) {
          return String(s == null ? '' : s);
        };
  const ip =
    (idbData && idbData.ip) || (shodanData && shodanData.ip_str) || resolvedIp || queryInput;
  const hostnames = (idbData && idbData.hostnames) || (shodanData && shodanData.hostnames) || [];
  const location = idbData && idbData.location ? idbData.location : null;
  const country = location
    ? location.country_name || location.country || '-'
    : (shodanData && shodanData.country_name) || '-';
  const city = location ? location.city || '-' : (shodanData && shodanData.city) || '-';
  const lat = location ? location.latitude : shodanData && shodanData.latitude;
  const lon = location ? location.longitude : shodanData && shodanData.longitude;
  const ports = (idbData && idbData.ports) || (shodanData && shodanData.ports) || [];
  const vulns = idbData ? idbData.vulns || {} : (shodanData && shodanData.vulns) || {};
  const cpes = (idbData && idbData.cpes) || [];
  const tags = (idbData && idbData.tags) || [];
  const lastUpdate =
    idbData && idbData.last_report_at
      ? idbData.last_report_at.replace('T', ' ').substring(0, 19)
      : (shodanData && shodanData.last_update) || '-';
  const isp = shodanData && shodanData.isp ? shodanData.isp : null;
  const org = shodanData && shodanData.org ? shodanData.org : null;
  const os = shodanData && shodanData.os ? shodanData.os : null;
  const serviceData = shodanData && shodanData.data ? shodanData.data : [];

  let h = '';
  const otherHostnames = hostnames.filter(function (hn) {
    return hn !== queryInput && hn !== resolvedIp;
  });
  h += `<div class="shodan-host-header">
    <div class="shodan-host-title">${esc(queryInput)}</div>
    <div class="shodan-host-ip">${esc(ip)}</div>`;
  if (otherHostnames.length > 0) {
    h +=
      '<div style="margin-top:4px;font-size:11px;color:#888;">同 IP 域名: ' +
      otherHostnames.map(hn => esc(hn)).join(', ') +
      '</div>';
  }
  if (tags.length > 0) {
    h += '<div style="margin-top:4px;">';
    tags.forEach(function (tag) {
      h += `<span style="display:inline-block;font-size:10px;background:#E8F4FD;color:#1976D2;padding:1px 6px;border-radius:3px;margin-right:4px;">${esc(tag)}</span>`;
    });
    h += '</div>';
  }
  h += '</div>';

  h += '<div class="shodan-info-grid">';
  const infoItems = [];
  if (isp) infoItems.push({ label: 'ISP', value: isp });
  if (org) infoItems.push({ label: '组织', value: org });
  infoItems.push({ label: '国家/地区', value: country });
  infoItems.push({ label: '城市', value: city });
  if (lat != null && lon != null) infoItems.push({ label: '经纬度', value: `${lat}, ${lon}` });
  if (os) infoItems.push({ label: '操作系统', value: os });
  infoItems.push({ label: '最后更新', value: lastUpdate });
  infoItems.forEach(function (item) {
    h += `<div class="shodan-info-item"><span class="shodan-info-label">${item.label}</span><span class="shodan-info-value">${esc(item.value)}</span></div>`;
  });
  h += '</div>';

  if (ports.length > 0) {
    h += `<div class="shodan-section-title">开放端口 (${ports.length})</div>`;
    h += '<div class="shodan-ports">';
    ports.forEach(function (port) {
      const portInfo = serviceData.find(function (d) {
        return d.port === port;
      });
      const product = portInfo
        ? portInfo.product || (portInfo._shodan && portInfo._shodan.module) || ''
        : '';
      const version = portInfo && portInfo.version ? ` ${portInfo.version}` : '';
      const portLabel = product ? product + version : '';
      h += `<div class="shodan-port-item"><span class="shodan-port-num">${esc(port)}</span><span class="shodan-port-service">${esc(portLabel)}</span></div>`;
    });
    h += '</div>';
  }

  if (cpes.length > 0) {
    h += `<div class="shodan-section-title">CPE 识别 (${cpes.length})</div>`;
    h += '<div class="shodan-ports">';
    cpes.slice(0, 15).forEach(function (cpe) {
      const short = cpe.replace('cpe:2.3:a:', '').replace(/:/g, ' ');
      h += `<div class="shodan-port-item"><span class="shodan-port-service" style="font-family:monospace;font-size:11px;">${esc(short)}</span></div>`;
    });
    if (cpes.length > 15)
      h += `<div style="color:#888;font-size:11px;padding:4px 0;">...还有 ${cpes.length - 15} 个</div>`;
    h += '</div>';
  }

  const vulnKeys = Object.keys(vulns);
  if (vulnKeys.length > 0) {
    h += `<div class="shodan-section-title">已知漏洞 (${vulnKeys.length})</div>`;
    h += '<div class="shodan-vulns">';
    vulnKeys.slice(0, 30).forEach(function (cve) {
      let v = vulns[cve];
      let severity;
      if (v && typeof v === 'object' && v.cvss) {
        severity = v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low';
      } else {
        severity = 'info';
      }
      const cvssStr =
        v && typeof v === 'object' && v.cvss
          ? `<span class="shodan-vuln-cvss">CVSS: ${esc(v.cvss)}</span>`
          : '';
      h += `<div class="shodan-vuln-item shodan-vuln-${severity}">
        <span class="shodan-vuln-cve">${esc(cve)}</span>
        ${cvssStr}
      </div>`;
    });
    if (vulnKeys.length > 30)
      h += `<div style="color:#888;font-size:11px;padding:4px 0;">...还有 ${vulnKeys.length - 30} 个</div>`;
    h += '</div>';
  }

  if (ports.length === 0 && vulnKeys.length === 0) {
    h += '<div style="color:#888;padding:8px;">该 IP 暂无开放端口或漏洞信息</div>';
  }

  h += `<div style="text-align:center;padding:6px;font-size:10px;color:#aaa;">数据来源: Shodan InternetDB${shodanData ? ' + Shodan API' : '（配置 Shodan API Key 可获取地理位置、ISP、服务等详情）'}</div>`;

  container.innerHTML = h;
}

async function handleAssetScan() {
  const queryEl = utils.get('asset-query');
  let query = queryEl ? queryEl.value.trim() : '';
  if (!query) {
    query = await getCurrentUrl().then(url => {
      if (!url) return null;
      try {
        return new URL(url).hostname;
      } catch {
        return null;
      }
    });
    if (!query) {
      utils.showToast('请输入目标或打开一个网页', 'warning');
      return;
    }
    if (queryEl) queryEl.value = query;
  }

  const scanners = { fofa: scanFofa, zoomeye: scanZoomEye, shodan: scanShodan };
  const scanner = scanners[currentAssetSource];
  if (scanner) scanner(query);
}

async function scanAllEngines() {
  const queryEl = utils.get('asset-query');
  let query = queryEl ? queryEl.value.trim() : '';
  if (!query) {
    query = await getCurrentUrl().then(function (url) {
      if (!url) return null;
      try {
        return new URL(url).hostname;
      } catch (e) {
        return null;
      }
    });
    if (!query) {
      utils.showToast('请输入目标或打开一个网页', 'warning');
      return;
    }
    if (queryEl) queryEl.value = query;
  }

  setAssetStatus('正在并发查询全部引擎...');
  const scanBtn = utils.get('asset-scan-all-btn');
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.textContent = '查询中...';
  }

  const engineNames = ['FOFA', 'ZoomEye', 'Shodan'];
  const scanFns = [scanFofa, scanZoomEye, scanShodan];

  try {
    const results = await Promise.allSettled(
      scanFns.map(function (fn) {
        return fn(query, { skipRender: true });
      })
    );

    const allResults = results.reduce(function (merged, r) {
      if (r.status === 'fulfilled' && Array.isArray(r.value)) {
        return merged.concat(r.value);
      }
      return merged;
    }, []);

    const successCount = results.filter(function (r) {
      return r.status === 'fulfilled' && Array.isArray(r.value);
    }).length;
    renderAssetResults(allResults);
    setAssetStatus(
      `全部引擎查询完成 (${successCount}/${engineNames.length} 成功，共 ${allResults.length} 条)`
    );
  } catch (e) {
    setAssetStatus(`查询出错: ${e.message}`);
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.textContent = '全部搜索';
    }
  }
}

function switchAssetSource(source) {
  currentAssetSource = source;
  utils.saveUIState('asset-source', source);

  document
    .querySelectorAll('.source-btn')
    .forEach(b => b.classList.toggle('active', b.dataset.source === source));
  const results = utils.get('asset-results');
  if (results) results.innerHTML = '';
  setAssetStatus('');
}

function toggleCustomQueryMode(enabled) {
  customQueryMode = enabled;

  const queryInput = utils.get('asset-query');
  const hint = utils.get('asset-query-hint');
  if (queryInput) {
    queryInput.placeholder = enabled
      ? '输入自定义查询语法，如 domain="x.com" && title="login"'
      : '留空使用当前页面域名';
  }
  if (hint) hint.textContent = enabled ? '自定义模式：直接输入引擎查询语法' : '';
  const toggle = utils.get('asset-custom-toggle');
  if (toggle) toggle.classList.toggle('active', enabled);
}

const API_KEY_FIELDS = [
  { id: 'key-fofa-email', storageKey: 'fofa_email' },
  { id: 'key-fofa-key', storageKey: 'fofa_key' },
  { id: 'key-zoomeye', storageKey: 'zoomeye' },
  { id: 'key-shodan', storageKey: 'shodan' },
];

const ENCRYPTED_KEY_PREFIX = 'enc:aes256:gcm:';
let _cryptoKey = null;

async function getCryptoKey() {
  if (_cryptoKey) return _cryptoKey;
  const extId = chrome.runtime.id;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(`vulnkit-key-v1:${extId}`),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  _cryptoKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('vulnkit-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return _cryptoKey;
}

async function encryptValue(plaintext) {
  if (!plaintext) return '';
  let key = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(plaintext)
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return `${ENCRYPTED_KEY_PREFIX}${btoa(String.fromCharCode.apply(null, combined))}`;
}

async function decryptValue(stored) {
  if (!stored || !stored.startsWith(ENCRYPTED_KEY_PREFIX)) return stored || '';
  const b64 = stored.slice(ENCRYPTED_KEY_PREFIX.length);
  const combined = Uint8Array.from(atob(b64), function (c) {
    return c.charCodeAt(0);
  });
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  let key = await getCryptoKey();
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

function readKeyField(field) {
  let v = (utils.get(field.id) || {}).value;
  return v ? v.trim() : '';
}

async function saveApiKeys() {
  const keys = {};
  for (let i = 0; i < API_KEY_FIELDS.length; i++) {
    const f = API_KEY_FIELDS[i];
    keys[f.storageKey] = await encryptValue(readKeyField(f));
  }
  chrome.storage.local.set({ pentest_keys: keys }, function () {
    utils.showToast('配置已加密保存', 'success');
  });
}

async function loadApiKeys() {
  chrome.storage.local.get(['pentest_keys'], async function (result) {
    const keys = result.pentest_keys || {};
    for (let i = 0; i < API_KEY_FIELDS.length; i++) {
      const f = API_KEY_FIELDS[i];
      let el = utils.get(f.id);
      if (el) {
        try {
          el.value = await decryptValue(keys[f.storageKey]);
        } catch (e) {
          el.value = keys[f.storageKey] || '';
        }
      }
    }
  });
}

function clearApiKeys() {
  chrome.storage.local.remove(['pentest_keys'], function () {
    API_KEY_FIELDS.forEach(function (f) {
      let el = utils.get(f.id);
      if (el) el.value = '';
    });
    utils.showToast('配置已清除', 'success');
  });
}

export {
  handleAssetScan,
  scanAllEngines,
  switchAssetSource,
  toggleCustomQueryMode,
  shodanHostLookup,
  saveApiKeys,
  loadApiKeys,
  clearApiKeys,
  exportData,
  applySearchFilter,
  currentAssetSource,
  lastAssetResults,
};
