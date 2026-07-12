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
    'btn': 'px-3.5 py-2 rounded-lg text-sm font-semibold cursor-pointer transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed active:scale-[0.97] shadow-sm',
    'btn-primary': 'btn bg-gradient-to-r from-blue-500 to-blue-600 text-white hover:from-blue-600 hover:to-blue-700 shadow-md hover:shadow-lg shadow-blue-500/25',
    'btn-danger': 'btn bg-gradient-to-r from-red-500 to-red-600 text-white hover:from-red-600 hover:to-red-700 shadow-md hover:shadow-lg shadow-red-500/25',
    'btn-success': 'btn bg-gradient-to-r from-emerald-500 to-emerald-600 text-white hover:from-emerald-600 hover:to-emerald-700 shadow-md hover:shadow-lg shadow-emerald-500/25',
    'btn-ghost': 'btn bg-transparent text-current hover:bg-gray-100/80 dark:hover:bg-gray-700/50',
    'btn-soft': 'btn bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 shadow-none',
    'btn-sm': 'px-2.5 py-1 rounded-lg text-xs font-medium',
    'btn-xs': 'px-1.5 py-0.5 rounded-md text-[10px] font-medium',

    // ===== 卡片 =====
    'card': 'bg-white dark:bg-gray-800/80 rounded-xl border border-gray-200/60 dark:border-gray-700/50 p-3.5 shadow-sm backdrop-blur-sm',
    'card-hover': 'card hover:shadow-md hover:border-gray-300/70 dark:hover:border-gray-600 transition-all duration-200',
    'card-flat': 'bg-gray-50/80 dark:bg-gray-800/40 rounded-xl border border-gray-200/40 dark:border-gray-700/30 p-3.5',
    'card-glass': 'bg-white/60 dark:bg-gray-800/40 rounded-xl border border-white/30 dark:border-gray-700/30 p-3.5 shadow-lg backdrop-blur-md',

    // ===== 输入 =====
    'input': 'w-full px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-gray-600/60 bg-gray-50/50 dark:bg-gray-800/50 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 dark:focus:border-blue-500 transition-all duration-200 shadow-sm',

    // ===== 徽章 =====
    'badge': 'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold',
    'badge-success': 'badge bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300',
    'badge-warning': 'badge bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
    'badge-danger': 'badge bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
    'badge-info': 'badge bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
    'badge-muted': 'badge bg-gray-100 text-gray-600 dark:bg-gray-700/60 dark:text-gray-400',

    // ===== 面板容器 =====
    'panel-section': 'space-y-3',
    'panel-label': 'block text-[11px] font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1.5',
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
