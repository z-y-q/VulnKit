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

// ===== Auto-Run 信号 store =====
// 右键菜单 / Popup 一键操作写入后，由 side-panel 转发到这里；
// 被命中的扫描面板挂载时检测到 signal.panel === 自身 id 即自动触发扫描，
// 消费后 clear()，避免后续手动切到该面板时误触发。
export interface AutoRunSignal {
  panel: string;
  url: string;
  nonce: number;
}

function createAutoRunStore() {
  const { subscribe, set } = writable<AutoRunSignal | null>(null);
  return {
    subscribe,
    fire: (s: AutoRunSignal) => set(s),
    clear: () => set(null),
  };
}

export const autoRunStore = createAutoRunStore();

// ===== Toast Store =====
let _toastId = 0;
function createToastStore() {
  const toasts = writable<ToastItem[]>([]);

  function show(message: string, type: ToastItem['type'] = 'info', duration?: number) {
    // 去重：相同 message+type 在窗口期内只弹一次，避免并发扫描刷屏
    let dup = false;
    toasts.update(t => {
      dup = t.some(item => item.message === message && item.type === type);
      return t;
    });
    if (dup) return;

    // 错误/警告停留更久，给用户读完和操作的时间（对齐 §8.4）
    const auto = duration ?? (type === 'error' ? 7000 : type === 'warning' ? 5000 : 3000);
    const id = _toastId++;
    toasts.update(t => [...t, { id, message, type, duration: auto }]);
    setTimeout(() => {
      toasts.update(t => t.filter(item => item.id !== id));
    }, auto);
  }

  function dismiss(id: number) {
    toasts.update(t => t.filter(item => item.id !== id));
  }

  return { subscribe: toasts.subscribe, show, dismiss };
}

export const toastStore = createToastStore();
