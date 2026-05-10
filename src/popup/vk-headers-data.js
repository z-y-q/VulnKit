// vk-headers-data.js -- 灵眸 Chrome Extension
// Pure data constants for security headers analysis

var CATEGORY_LABELS = {
  security: '安全防护',
  privacy: '隐私保护',
  'cross-origin': '跨域控制',
  caching: '缓存控制',
  legacy: '遗留兼容',
  infoleak: '信息泄露',
  monitoring: '监控报告',
};

var SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', weight: 10, category: 'security' },
  { name: 'Strict-Transport-Security', weight: 8, category: 'security' },
  { name: 'X-Frame-Options', weight: 7, category: 'security' },
  { name: 'X-Content-Type-Options', weight: 5, category: 'security' },
  { name: 'Content-Security-Policy-Report-Only', weight: 5, category: 'security' },
  { name: 'Clear-Site-Data', weight: 3, category: 'privacy' },
  { name: 'Referrer-Policy', weight: 6, category: 'privacy' },
  { name: 'Permissions-Policy', weight: 5, category: 'privacy' },
  { name: 'X-Robots-Tag', weight: 2, category: 'privacy' },
  { name: 'Cross-Origin-Opener-Policy', weight: 4, category: 'cross-origin' },
  { name: 'Cross-Origin-Resource-Policy', weight: 4, category: 'cross-origin' },
  { name: 'Cross-Origin-Embedder-Policy', weight: 4, category: 'cross-origin' },
  { name: 'X-Permitted-Cross-Domain-Policies', weight: 3, category: 'cross-origin' },
  { name: 'Cache-Control', weight: 3, category: 'caching' },
  { name: 'Pragma', weight: 2, category: 'legacy' },
  { name: 'X-XSS-Protection', weight: 3, category: 'legacy' },
  { name: 'X-Download-Options', weight: 2, category: 'security' },
  { name: 'Report-To', weight: 2, category: 'monitoring' },
  { name: 'NEL', weight: 2, category: 'monitoring' },
];

var SERVER_SIGNATURES = [
  'apache',
  'nginx',
  'iis',
  'tomcat',
  'express',
  'openresty',
  'caddy',
  'liteSpeed',
  'cloudflare',
  'microsoft',
  'jetty',
  'weblogic',
  'websphere',
];

var FRAMEWORK_SIGNATURES = [
  'php',
  'asp.net',
  'django',
  'rails',
  'spring',
  'laravel',
  'next.js',
  'nuxt',
  'struts',
];

var CATEGORY_ICONS = {
  security:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  privacy:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  'cross-origin':
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  caching:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  legacy:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  monitoring:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
};

var STATUS_ICONS = {
  pass: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#27ae60" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  warn: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#f39c12" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  miss: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#e74c3c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
};

export {
  CATEGORY_LABELS,
  SECURITY_HEADERS,
  SERVER_SIGNATURES,
  FRAMEWORK_SIGNATURES,
  CATEGORY_ICONS,
  STATUS_ICONS,
};
