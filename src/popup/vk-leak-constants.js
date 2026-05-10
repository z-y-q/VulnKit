// vk-leak-constants.js -- 灵眸 Chrome Extension
// Shared constants for leak detection rules
'use strict';

var SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
var CONFIDENCE_ORDER = { confirmed: 3, likely: 2, suspected: 1 };

var SEVERITY_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

var CONFIDENCE_LABELS = {
  confirmed: '确认',
  likely: '可能',
  suspected: '疑似',
};

var SEVERITY_COLOR = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'cyan',
  info: 'grey',
};

var CATEGORY_LABELS = {
  secret: '密钥/凭证',
  'crypto-vuln': '加解密漏洞',
  hardcode: '硬编码漏洞',
  pii: '敏感信息 (PII)',
  exposure: '信息暴露',
};

export {
  SEVERITY_ORDER,
  CONFIDENCE_ORDER,
  SEVERITY_LABELS,
  CONFIDENCE_LABELS,
  SEVERITY_COLOR,
  CATEGORY_LABELS,
};
