// vk-vue-state.js -- 灵眸 Chrome Extension
// Shared state, constants, and utilities for Vue analysis modules

import { utilsProxy as utils } from './vk-namespace.js';

export const ROLE_VALS_RE = /^(admin|superadmin|user|vip|normal|guest|member|manager)$/i;
export const VUE_ROOT_SELECTOR = '#app,[data-v-app],[id^="app"],#root,#application,#main';
export const MENU_KEYWORDS = [
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

export const vueState = {
  lastVueResult: '',
  permInterceptActive: false,
  permCapturedData: [],
  permSelectedIndex: -1,
  permViewMode: 'list',
  permRefreshTimer: null,
  permCapturedLength: -1,
  lastCompareHiddenRoutes: [],
  lastJsMatchContexts: [],
  jsSearchFoundPaths: [],
  // Registration slots for cross-module references
  Detect: null,
  PermInject: null,
  Perm: null,
  JsSearch: null,
  Compare: null,
  Store: null,
};

export function switchVueSubTab(tab) {
  utils.switchSubTabs('vue-stab', 'vstab', 'vstab', tab);
}
