// 灵眸 - XSS Scanner Data Tables
'use strict';

import { loadRemotePayloads } from './vk-payload-remote.js';
import { loadJsonData } from './vk-data-loader.js';

const SEVERITY_CONFIG = {
  critical: { label: '严重', color: '#e74c3c', bg: '#fdecea', darkBg: 'rgba(231,76,60,0.15)' },
  high: { label: '高危', color: '#e67e22', bg: '#fef9e7', darkBg: 'rgba(230,126,34,0.15)' },
  medium: { label: '中危', color: '#f39c12', bg: '#fef9e7', darkBg: 'rgba(243,156,18,0.15)' },
  low: { label: '低危', color: '#27ae60', bg: '#e8f8f0', darkBg: 'rgba(39,174,96,0.15)' },
  info: { label: '信息', color: '#4A90E2', bg: '#eaf2fb', darkBg: 'rgba(74,144,226,0.15)' },
};

var _localData = null;

async function ensureLoaded() {
  if (_localData) return _localData;
  _localData = await loadJsonData('data/xss-data.json') || {
    XSS_SCAN_PAYLOADS: [],
    CONTEXT_PAYLOADS: {},
    SINK_PATTERNS: [],
    SANITIZER_PATTERNS: [],
  };
  return _localData;
}

var _remoteScanPayloads = null;
var _remoteContextPayloads = null;
var _remoteSinkPatterns = null;
var _remoteSanitizerPatterns = null;

loadRemotePayloads(function (data) {
  if (!data || !data.payloads) return;
  if (data.payloads.xss_scan) _remoteScanPayloads = data.payloads.xss_scan;
  if (data.payloads.context_payloads) _remoteContextPayloads = data.payloads.context_payloads;
  if (data.payloads.sink_patterns) _remoteSinkPatterns = data.payloads.sink_patterns;
  if (data.payloads.sanitizer_patterns) _remoteSanitizerPatterns = data.payloads.sanitizer_patterns;
});

async function getXssScanPayloads() {
  var data = await ensureLoaded();
  return _remoteScanPayloads || data.XSS_SCAN_PAYLOADS;
}

async function getContextPayloads() {
  var data = await ensureLoaded();
  return _remoteContextPayloads || data.CONTEXT_PAYLOADS;
}

async function getSinkPatterns() {
  var data = await ensureLoaded();
  return _remoteSinkPatterns || data.SINK_PATTERNS;
}

async function getSanitizerPatterns() {
  var data = await ensureLoaded();
  return _remoteSanitizerPatterns || data.SANITIZER_PATTERNS;
}

function getEffectiveScanPayloads() {
  return _remoteScanPayloads || null;
}

function getEffectiveContextPayloads() {
  return _remoteContextPayloads || null;
}

function getEffectiveSinkPatterns() {
  return _remoteSinkPatterns || null;
}

function getEffectiveSanitizerPatterns() {
  return _remoteSanitizerPatterns || null;
}

export {
  SEVERITY_CONFIG,
  getXssScanPayloads,
  getContextPayloads,
  getSinkPatterns,
  getSanitizerPatterns,
  getEffectiveScanPayloads,
  getEffectiveContextPayloads,
  getEffectiveSinkPatterns,
  getEffectiveSanitizerPatterns,
};
