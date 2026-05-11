// vk-categories.js -- Tab category configuration for 灵眸
'use strict';

var TAB_CATEGORIES = [
  {
    id: 'recon',
    label: '侦察',
    color: '#4A90E2',
    tabs: ['favicon', 'gather', 'subdomain', 'sniff'],
  },
  {
    id: 'scan',
    label: '扫描',
    color: '#e74c3c',
    tabs: ['xssscan', 'cors', 'waf', 'cookie-audit', 'headers', 'redirect', 'fuzz', 'graphql'],
  },
  {
    id: 'exploit',
    label: '利用',
    color: '#e67e22',
    tabs: ['jsctrl', 'payload', 'encoding', 'spoof'],
  },
  {
    id: 'framework',
    label: '框架分析',
    color: '#27ae60',
    tabs: ['vue', 'ruoyi', 'react', 'angular', 'sourcemap'],
  },
  {
    id: 'tools',
    label: '工具',
    color: '#9b59b6',
    tabs: ['asset', 'links', 'multiurl', 'history', 'exif', 'source-loader'],
  },
  {
    id: 'report',
    label: '统一报告',
    color: '#999',
    tabs: ['report'],
  },
];

var TAB_TO_CATEGORY = {};
TAB_CATEGORIES.forEach(function (cat) {
  cat.tabs.forEach(function (tabId) {
    TAB_TO_CATEGORY[tabId] = cat;
  });
});

function getCategoryForTab(tabId) {
  return TAB_TO_CATEGORY[tabId] || null;
}

function getAllCategories() {
  return TAB_CATEGORIES;
}

export { TAB_CATEGORIES, TAB_TO_CATEGORY, getCategoryForTab, getAllCategories };
