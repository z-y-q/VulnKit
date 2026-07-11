import {
  defineConfig,
  presetUno,
  presetIcons,
} from 'unocss';

export default defineConfig({
  presets: [
    presetUno({ dark: 'class' }),
    presetIcons({
      scale: 1.2,
      cdn: 'https://esm.sh/',
    }),
  ],
  shortcuts: {
    // ===== 按钮 =====
    'btn': 'px-3 py-1.5 rounded-md text-sm font-medium cursor-pointer transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed active:scale-[0.98]',
    'btn-primary': 'btn bg-blue-500 text-white hover:bg-blue-600 active:bg-blue-700 shadow-sm hover:shadow',
    'btn-danger': 'btn bg-red-500 text-white hover:bg-red-600 active:bg-red-700 shadow-sm hover:shadow',
    'btn-ghost': 'btn bg-transparent text-current hover:bg-gray-100 dark:hover:bg-gray-700',
    'btn-sm': 'px-2 py-1 rounded-md text-xs',

    // ===== 卡片 =====
    'card': 'bg-white dark:bg-gray-800 rounded-lg border border-gray-200/80 dark:border-gray-700/70 p-3 shadow-sm',
    'card-hover': 'card hover:shadow-md hover:border-gray-300 dark:hover:border-gray-600 transition-all duration-150',
    'card-flat': 'bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200/60 dark:border-gray-700/50 p-3',

    // ===== 输入 =====
    'input': 'w-full px-2.5 py-1.5 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all',

    // ===== 徽章 =====
    'badge': 'inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium',
    'badge-success': 'badge bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    'badge-warning': 'badge bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
    'badge-danger': 'badge bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'badge-info': 'badge bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    'badge-muted': 'badge bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
  },
  theme: {
    colors: {
      primary: '#4A90E2',
      danger: '#e74c3c',
      warning: '#e67e22',
      success: '#27ae60',
    },
  },
});
