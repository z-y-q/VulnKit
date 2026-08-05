import {
  defineConfig,
  presetUno,
  presetIcons,
} from 'unocss';
import { PANEL_ICON_CLASSES } from './src/lib/panels/icons';

export default defineConfig({
  // 动态拼接的 i-lucide-* 类名在此显式声明，保证 UnoCSS 一定生成（扫描器看不到运行时插值）
  safelist: PANEL_ICON_CLASSES,
  presets: [
    presetUno({ dark: 'class' }),
    presetIcons({
      scale: 1.2,
      cdn: 'https://esm.sh/',
    }),
  ],
  shortcuts: {
    // ===== 按钮 =====
    'btn': 'px-3.5 py-2 rounded-lg text-sm font-semibold cursor-pointer transition-all duration-[var(--vk-dur)] ease-[var(--vk-ease)] disabled:opacity-40 disabled:cursor-not-allowed active:scale-[0.97] shadow-sm',
    'btn-primary': 'btn bg-gradient-to-r from-blue-500 to-blue-600 text-white hover:from-blue-600 hover:to-blue-700 shadow-md hover:shadow-lg',
    'btn-danger': 'btn bg-gradient-to-r from-red-500 to-red-600 text-white hover:from-red-600 hover:to-red-700 shadow-md hover:shadow-lg',
    'btn-success': 'btn bg-gradient-to-r from-emerald-500 to-emerald-600 text-white hover:from-emerald-600 hover:to-emerald-700 shadow-md hover:shadow-lg',
    'btn-ghost': 'btn bg-transparent text-current hover:bg-gray-100/80 dark:hover:bg-gray-700/50',
    'btn-soft': 'btn bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 shadow-none',
    'btn-link': 'inline-flex items-center text-xs text-primary hover:underline active:scale-[0.97] transition-transform duration-[var(--vk-dur-fast)] ease-[var(--vk-ease)] cursor-pointer',
    'btn-sm': 'px-2.5 py-1 rounded-lg text-xs font-medium',
    'btn-xs': 'px-1.5 py-0.5 rounded-md text-[10px] font-medium',

    // ===== 卡片 =====
    'card': 'bg-white dark:bg-gray-800/80 rounded-xl border border-gray-200/60 dark:border-gray-700/50 p-3.5 shadow-[var(--vk-shadow-sm)] backdrop-blur-sm',
    'card-hover': 'card hover:shadow-[var(--vk-shadow-md)] hover:border-gray-300/70 dark:hover:border-gray-600 transition-all duration-[var(--vk-dur)] ease-[var(--vk-ease)]',
    'card-flat': 'bg-gray-50/80 dark:bg-gray-800/40 rounded-xl border border-gray-200/40 dark:border-gray-700/30 p-3.5',
    'card-glass': 'bg-white/60 dark:bg-gray-800/40 rounded-xl border border-white/30 dark:border-gray-700/30 p-3.5 shadow-[var(--vk-shadow-lg)] backdrop-blur-md',
    'result-row': 'card p-2.5 space-y-1.5 cursor-pointer hover:border-primary active:scale-[0.99] transition-all duration-[var(--vk-dur)] ease-[var(--vk-ease)]',

    // ===== 输入 =====
    'input': 'w-full px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-gray-600/60 bg-gray-50/50 dark:bg-gray-800/50 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 dark:focus:border-blue-500 transition-all duration-[var(--vk-dur)] ease-[var(--vk-ease)] shadow-sm',

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
    'panel-heading': 'text-sm font-semibold text-gray-700 dark:text-gray-200',

    // ===== 分段控件（Apple 风格互斥切换组） =====
    'seg': 'inline-flex items-center gap-0.5 p-0.5 rounded-lg bg-gray-100/80 dark:bg-gray-800/60',
    'seg-btn': 'px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-all duration-[var(--vk-dur-fast)] ease-[var(--vk-ease)] active:scale-[0.97]',
    'seg-btn-active': 'seg-btn bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm',
    'seg-btn-inactive': 'seg-btn text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200',

    // ===== 多选 chip（与 seg 配对：seg=互斥，chip=多选；描边胶囊，激活实心） =====
    'chip': 'inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium cursor-pointer transition-all duration-[var(--vk-dur-fast)] ease-[var(--vk-ease)] active:scale-[0.96] border disabled:opacity-40 disabled:cursor-not-allowed',
    'chip-active': 'chip bg-primary text-white border-transparent',
    'chip-inactive': 'chip text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-600/60 bg-white/50 dark:bg-gray-800/40 hover:border-gray-300 dark:hover:border-gray-500',
  },
  theme: {
    colors: {
      // 与 src/styles/shared.css 的 --vk-* token 数值对齐（保留 /opacity 修饰符可用）
      primary: '#4A90E2',
      danger: '#ef4444',
      warning: '#f59e0b',
      success: '#10b981',
    },
  },
});
