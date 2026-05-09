// 灵眸 - Remote Payload Management
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const STORAGE_KEY = 'remotePayloads';
const URL_CONFIG_KEY = 'payloadRemoteUrl';
const VERSION_KEY = 'payloadVersion';
const DEFAULT_REMOTE_URL = '';

function loadRemotePayloads(callback) {
  chrome.storage.local.get([STORAGE_KEY], function (result) {
    if (!result[STORAGE_KEY]) {
      callback(null);
      return;
    }
    try {
      callback(JSON.parse(JSON.stringify(result[STORAGE_KEY])));
    } catch (e) {
      callback(null);
    }
  });
}

function saveRemotePayloads(data) {
  chrome.storage.local.set({ [STORAGE_KEY]: JSON.parse(JSON.stringify(data)) });
}

function getVersionInfo(callback) {
  chrome.storage.local.get([VERSION_KEY], function (result) {
    callback(result[VERSION_KEY] || null);
  });
}

function saveVersionInfo(versionData) {
  chrome.storage.local.set({ [VERSION_KEY]: versionData });
}

function getRemoteUrl(callback) {
  chrome.storage.local.get([URL_CONFIG_KEY], function (result) {
    callback(result[URL_CONFIG_KEY] || DEFAULT_REMOTE_URL);
  });
}

function setRemoteUrl(url) {
  chrome.storage.local.set({ [URL_CONFIG_KEY]: url });
}

function validatePayloadData(data) {
  if (!data || typeof data !== 'object') return { valid: false, error: '无效的 JSON 格式' };
  if (!data.version) return { valid: false, error: '缺少 version 字段' };
  if (!data.payloads || typeof data.payloads !== 'object') return { valid: false, error: '缺少 payloads 字段' };
  const payloads = data.payloads;
  const validKeys = ['xss', 'lfi', 'xss_scan', 'context_payloads', 'sink_patterns', 'sanitizer_patterns'];
  const foundKeys = Object.keys(payloads).filter(function (k) { return validKeys.indexOf(k) !== -1; });
  if (foundKeys.length === 0) return { valid: false, error: 'payloads 中无有效分类' };
  return { valid: true, keys: foundKeys };
}

async function fetchRemotePayloads(url) {
  const result = await utils.fetchUrlJson({ url: url, timeout: 15000 });
  if (!result || !result.success) return { ok: false, error: (result && result.error) || '请求失败' };
  return { ok: true, data: result.data };
}

function countPayloads(data) {
  const counts = {};
  if (!data || !data.payloads) return counts;
  const p = data.payloads;
  if (p.xss) counts.xss = Object.keys(p.xss).length;
  if (p.lfi) counts.lfi = Object.keys(p.lfi).length;
  if (p.xss_scan) counts.xss_scan = p.xss_scan.length;
  if (p.context_payloads) counts.context_payloads = Object.keys(p.context_payloads).length;
  if (p.sink_patterns) counts.sink_patterns = p.sink_patterns.length;
  return counts;
}

async function updatePayloads(statusCallback) {
  const url = await new Promise(function (resolve) { getRemoteUrl(resolve); });
  if (!url) return { ok: false, error: '未配置远程 Payload 地址' };

  if (statusCallback) statusCallback('正在获取远程 Payload...');
  const fetchResult = await fetchRemotePayloads(url);
  if (!fetchResult.ok) return { ok: false, error: fetchResult.error };

  if (statusCallback) statusCallback('正在校验...');
  const validation = validatePayloadData(fetchResult.data);
  if (!validation.valid) return { ok: false, error: validation.error };

  if (statusCallback) statusCallback('正在保存...');
  saveRemotePayloads(fetchResult.data);
  saveVersionInfo({ version: fetchResult.data.version, updated: fetchResult.data.updated, fetchedAt: new Date().toISOString() });

  const stats = countPayloads(fetchResult.data);
  stats.version = fetchResult.data.version;
  stats.ok = true;
  return stats;
}

export {
  loadRemotePayloads,
  saveRemotePayloads,
  fetchRemotePayloads,
  validatePayloadData,
  getVersionInfo,
  saveVersionInfo,
  getRemoteUrl,
  setRemoteUrl,
  updatePayloads,
  countPayloads,
  STORAGE_KEY,
  URL_CONFIG_KEY,
};
