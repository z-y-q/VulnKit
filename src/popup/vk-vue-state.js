// vk-vue-state.js -- 灵眸 Chrome Extension
// Shared state, constants, and utilities for Vue analysis modules
window.VulnKitVueState = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var ROLE_VALS_RE = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
  var MENU_KEYWORDS = [
    'menu',
    'menulist',
    'menuList',
    'menuData',
    'permission',
    'permissions',
    'permList',
    'menuIds',
    'menu_ids',
    'menuId',
    'isAdmin',
    'isadmin',
    'role',
    'roles',
    'getMenu',
    'getMenus',
    'getPermission',
    'getUserInfo',
    'navList',
    'sideMenu',
    'sidebar',
  ];

  var lastVueResult = '';
  var permInterceptActive = false;
  var permCapturedData = [];
  var permSelectedIndex = -1;
  var permViewMode = 'list';
  var permRefreshTimer = null;
  var permCapturedLength = -1;
  var lastCompareHiddenRoutes = [];
  var lastJsMatchContexts = [];
  var jsSearchFoundPaths = [];

  function switchVueSubTab(tab) {
    utils.switchSubTabs('vue-stab', 'vstab', 'vstab', tab);
  }

  return {
    utils: utils,
    ROLE_VALS_RE: ROLE_VALS_RE,
    MENU_KEYWORDS: MENU_KEYWORDS,
    switchVueSubTab: switchVueSubTab,
    get lastVueResult() { return lastVueResult; },
    set lastVueResult(v) { lastVueResult = v; },
    get permInterceptActive() { return permInterceptActive; },
    set permInterceptActive(v) { permInterceptActive = v; },
    get permCapturedData() { return permCapturedData; },
    set permCapturedData(v) { permCapturedData = v; },
    get permSelectedIndex() { return permSelectedIndex; },
    set permSelectedIndex(v) { permSelectedIndex = v; },
    get permViewMode() { return permViewMode; },
    set permViewMode(v) { permViewMode = v; },
    get permRefreshTimer() { return permRefreshTimer; },
    set permRefreshTimer(v) { permRefreshTimer = v; },
    get permCapturedLength() { return permCapturedLength; },
    set permCapturedLength(v) { permCapturedLength = v; },
    get lastCompareHiddenRoutes() { return lastCompareHiddenRoutes; },
    set lastCompareHiddenRoutes(v) { lastCompareHiddenRoutes = v; },
    get lastJsMatchContexts() { return lastJsMatchContexts; },
    set lastJsMatchContexts(v) { lastJsMatchContexts = v; },
    get jsSearchFoundPaths() { return jsSearchFoundPaths; },
    set jsSearchFoundPaths(v) { jsSearchFoundPaths = v; },
    Detect: null,
    PermInject: null,
    Perm: null,
    JsSearch: null,
    Compare: null,
    Store: null,
  };
})();
