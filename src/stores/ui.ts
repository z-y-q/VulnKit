import { writable } from 'svelte/store';

// ===== UI Store =====
export interface ToastItem {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
  duration?: number;
}

/** 主题 store — dark 模式开关 */
function createThemeStore() {
  const store = writable(false);

  // 初始化主题
  if (typeof window !== 'undefined') {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const saved = localStorage.getItem('lingmou-theme');
    const isDark = saved ? saved === 'dark' : prefersDark;
    store.set(isDark);
    document.documentElement.classList.toggle('dark', isDark);
  }

  function toggle() {
    store.update(v => {
      const next = !v;
      localStorage.setItem('lingmou-theme', next ? 'dark' : 'light');
      document.documentElement.classList.toggle('dark', next);
      return next;
    });
  }

  return { subscribe: store.subscribe, toggle };
}

export const themeStore = createThemeStore();

/** 当前活跃面板 store */
export const activePanelStore = writable<string>('encoding');

// ===== Toast Store =====
let _toastId = 0;
function createToastStore() {
  const toasts = writable<ToastItem[]>([]);

  function show(message: string, type: ToastItem['type'] = 'info', duration = 2000) {
    const id = _toastId++;
    toasts.update(t => [...t, { id, message, type, duration }]);
    setTimeout(() => {
      toasts.update(t => t.filter(item => item.id !== id));
    }, duration);
  }

  function dismiss(id: number) {
    toasts.update(t => t.filter(item => item.id !== id));
  }

  return { subscribe: toasts.subscribe, show, dismiss };
}

export const toastStore = createToastStore();
