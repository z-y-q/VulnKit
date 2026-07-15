// ESLint flat config — 灵眸 v6（WXT + Svelte 5 + TS）
// 对齐 docs/个人版项目优化路线.md §3.2：CI lint 门禁。
// 策略：用 recommended（非类型检查，避免 tsconfig project 复杂性），tsc/svelte-check 已覆盖类型。
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';

export default [
  {
    ignores: [
      'public/**',        // inject 生成物（tsc strict 已检查）
      '.output/**',       // wxt 构建产物
      '.wxt/**',          // wxt 生成
      'coverage/**',      // 测试覆盖率
      'src/inject/**',    // MAIN world 脚本（tsconfig.inject strict 已检查）
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs['flat/recommended'],
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
        // WXT 注入的全局
        chrome: 'readonly',
        browser: 'readonly',
        defineBackground: 'readonly',
        defineContentScript: 'readonly',
        createShadowRootUi: 'readonly',
      },
    },
    rules: {
      // 项目大量使用 any（注入脚本/三方类型），类型由 tsc/svelte-check 把关
      '@typescript-eslint/no-explicit-any': 'off',
      // Svelte 5 runes（$state/$derived 等）与未使用变量检测冲突较多，交由 tsc
      '@typescript-eslint/no-unused-vars': 'off',
      // §4.3 已对大列表手动加稳定 key；强制所有 each（含静态小列表）过严
      'svelte/require-each-key': 'off',
      // 建议性规则（prefer $derived），对现有代码误报多
      'svelte/prefer-svelte-reactivity': 'off',
      // 正则中的 \/ 等转义无功能影响，低价值噪音
      'no-useless-escape': 'off',
      // eslint 10 新规则，对 Svelte 5 响应式（$state/$effect 内赋值）误报
      'no-useless-assignment': 'off',
      // sanitizeFilename 有意过滤控制字符 \x00-\x1f；re-export type、属性内 JS 转义均为合法
      'no-control-regex': 'off',
      'no-import-assign': 'off',
      'svelte/no-useless-mustaches': 'off',
      'svelte/prefer-writable-derived': 'off',
      // sourcemap-phase1 webpack chunk hook 用 arguments/hasOwnProperty 是动态代码兼容写法
      'prefer-rest-params': 'off',
      'no-prototype-builtins': 'off',
    },
  },
  {
    // .svelte 文件用 typescript-eslint parser 解析 <script lang="ts">
    files: ['**/*.svelte'],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
      },
    },
  },
  {
    // 测试与入口脚本放宽 node 环境
    files: ['test/**', 'eslint.config.js', 'vitest.config.ts', 'wxt.config.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
];
