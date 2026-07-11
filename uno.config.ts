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
    'btn': 'px-3 py-1.5 rounded text-sm font-medium cursor-pointer transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed',
    'btn-primary': 'btn bg-blue-500 text-white hover:bg-blue-600 active:bg-blue-700',
    'btn-danger': 'btn bg-red-500 text-white hover:bg-red-600 active:bg-red-700',
    'btn-ghost': 'btn bg-transparent text-current hover:bg-gray-100 dark:hover:bg-gray-700',
    'btn-sm': 'px-2 py-1 rounded text-xs',
    'card': 'bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3',
    'input': 'w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-1 focus:ring-blue-500',
    'badge': 'inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium',
    'badge-success': 'badge bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    'badge-warning': 'badge bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    'badge-danger': 'badge bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    'badge-info': 'badge bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
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
