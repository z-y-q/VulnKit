// vk-leak-dom-rules.js -- 灵眸 Chrome Extension
// DOM-specific leak detection rules (applied to DOM HTML)
'use strict';

var DOM_LEAK_RULES = [
  {
    id: 'dom-html-comment-secret',
    name: 'HTML 注释中的秘密',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /<!--\s*(?:(?:password|secret|key|token|todo|fixme)[^>]*?)\s*-->/gi,
    description: 'HTML 注释中可能包含敏感信息。',
    exploit: '直接查看页面源码即可获取。',
    recommendation: '清理 HTML 注释中的敏感内容。',
  },
  {
    id: 'dom-email',
    name: '邮箱地址',
    category: 'pii',
    severity: 'low',
    confidence: 'suspected',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    description: '页面中暴露的邮箱地址。',
    exploit: '可用于社工或钓鱼。',
    recommendation: '对公开页面中的邮箱进行评估。',
  },
  {
    id: 'dom-hidden-input',
    name: '隐藏表单域',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /<input[^>]+type\s*=\s*["']hidden["'][^>]+value\s*=\s*["'][^"']+["']/gi,
    description: '隐藏表单域可能包含敏感值。',
    exploit: '修改隐藏域值可能绕过前端验证。',
    recommendation: '服务端必须验证所有表单提交值。',
  },
  {
    id: 'dom-data-attribute',
    name: 'data-* 属性中的敏感值',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /data-(?:token|key|secret|config|api)\s*=\s*["']([^"']+)["']/gi,
    description: 'HTML data 属性中可能包含敏感数据。',
    exploit: '直接查看 DOM 即可获取。',
    recommendation: '避免在 data 属性中存储敏感信息。',
  },
  {
    id: 'dom-srcdoc',
    name: 'srcdoc 中的内容',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /srcdoc\s*=\s*["']/gi,
    description: 'srcdoc 属性使用（可能嵌入任意 HTML）。',
    exploit: '如果内容可控则可能产生 XSS。',
    recommendation: '确保 srcdoc 内容经过适当转义。',
  },
];

export { DOM_LEAK_RULES };
