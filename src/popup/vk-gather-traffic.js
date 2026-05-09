// 灵眸 - API Traffic Monitor
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const API_TRAFFIC_GROUP = 'API Traffic';
let apiTrafficRunning = false;
let apiTrafficTimer = null;
const apiTrafficFilters = { method: 'ALL', status: 'ALL' };

let _gatherData = {};
let _getCurrentTab = function () {
  return '';
};
let _renderSubTabs = null;
let _renderGatherTab = null;

export function initTrafficDeps(getGatherData, getCurrentTab, renderSubTabs, renderGatherTab) {
  _gatherData = typeof getGatherData === 'function' ? getGatherData : () => getGatherData;
  _getCurrentTab = getCurrentTab;
  _renderSubTabs = renderSubTabs;
  _renderGatherTab = renderGatherTab;
}

export { API_TRAFFIC_GROUP, apiTrafficRunning };

function applyApiTrafficFilter(list) {
  if (!list) return list;
  return list.filter(function (item) {
    let meta = item._meta || {};
    if (apiTrafficFilters.method !== 'ALL') {
      const itemMethod = (meta.method || item.name || '').toUpperCase();
      if (itemMethod.indexOf(apiTrafficFilters.method) !== 0) return false;
    }
    if (apiTrafficFilters.status !== 'ALL') {
      const code = meta.status || 0;
      if (apiTrafficFilters.status === '2xx' && (code < 200 || code >= 300)) return false;
      if (apiTrafficFilters.status === '3xx' && (code < 300 || code >= 400)) return false;
      if (apiTrafficFilters.status === '4xx' && (code < 400 || code >= 500)) return false;
      if (apiTrafficFilters.status === '5xx' && code < 500) return false;
      if (apiTrafficFilters.status === 'err' && code >= 200 && code < 400) return false;
    }
    return true;
  });
}

async function collectApiTraffic() {
  const tab = await utils.requireTabId();
  if (!tab) return;
  const result = await chrome.tabs
    .sendMessage(tab.id, { type: 'VK_API_TRAFFIC_COLLECT' })
    .catch(function () {
      return null;
    });
  if (!result || !result.entries || result.entries.length === 0) return;
  const existing = _gatherData()[API_TRAFFIC_GROUP] || [];
  const existingKeys = {};
  existing.forEach(function (e) {
    existingKeys[e.value] = true;
  });
  const newEntries = result.entries.filter(function (e) {
    if (existingKeys[`${e.url} ${e.method}`]) return false;
    existingKeys[`${e.url} ${e.method}`] = true;
    return true;
  });
  if (newEntries.length === 0) return;
  const items = newEntries.map(function (e) {
    const statusColor =
      e.status >= 200 && e.status < 300 ? 'green' : e.status >= 400 ? 'red' : 'orange';
    return {
      name: `${e.method} [${e.status}]`,
      value: e.url,
      color: statusColor,
      _meta: {
        contentType: e.contentType,
        duration: e.duration,
        status: e.status,
        method: e.method,
        reqBody: e.reqBody || '',
        reqHeaders: e.reqHeaders || {},
        resBody: e.resBody || '',
      },
    };
  });
  _gatherData()[API_TRAFFIC_GROUP] = (existing || []).concat(items);
  if (_renderSubTabs) _renderSubTabs();
  if (_getCurrentTab() === API_TRAFFIC_GROUP && _renderGatherTab) _renderGatherTab();
  updateApiTrafficStatus();
}

function updateApiTrafficStatus() {
  let el = utils.get('gather-api-status');
  if (!el) return;
  const count = (_gatherData()[API_TRAFFIC_GROUP] || []).length;
  if (apiTrafficRunning) {
    el.textContent = `监听中... 已捕获 ${count} 个请求`;
    el.style.color = '#e67e22';
  } else {
    el.textContent = count > 0 ? `监听已停止，共捕获 ${count} 个请求` : '未启动监听';
    el.style.color = '';
  }
}

export async function startApiTraffic() {
  const tab = await utils.requireTabId();
  if (!tab) {
    utils.showToast('无法获取当前标签页', 'error');
    return;
  }
  const result = await chrome.tabs
    .sendMessage(tab.id, { type: 'VK_API_TRAFFIC_START' })
    .catch(function () {
      return null;
    });
  if (result && result.status === 'already_running') {
    utils.showToast('API 流量监听已在运行', 'info');
    return;
  }
  apiTrafficRunning = true;
  utils.toggleBtnPair('gather-api-start-btn', 'gather-api-stop-btn', true);
  updateApiTrafficStatus();
  apiTrafficTimer = setInterval(async function () {
    await collectApiTraffic();
  }, 3000);
  utils.showToast('API 流量监听已启动', 'success');
}

export async function stopApiTraffic() {
  if (apiTrafficTimer) {
    clearInterval(apiTrafficTimer);
    apiTrafficTimer = null;
  }
  apiTrafficRunning = false;
  const tab = await utils.requireTabId();
  if (tab) {
    await chrome.tabs.sendMessage(tab.id, { type: 'VK_API_TRAFFIC_STOP' }).catch(function (e) {
      console.debug('API traffic stop failed', e);
    });
    await collectApiTraffic();
  }
  utils.toggleBtnPair('gather-api-start-btn', 'gather-api-stop-btn', false);
  updateApiTrafficStatus();
  utils.showToast('API 流量监听已停止', 'info');
}

export function setApiFilter(key, value) {
  apiTrafficFilters[key] = value;
  if (_getCurrentTab() === API_TRAFFIC_GROUP && _renderGatherTab) _renderGatherTab();
}

export { applyApiTrafficFilter };
