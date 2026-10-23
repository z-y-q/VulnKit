/**
 * §7.2 通用 storage-backed store 工厂
 * 为面板状态提供 browser.storage.local 持久化 + Svelte store 响应式接口
 */
import { writable, type Writable } from 'svelte/store';

export interface StorageStore<T> extends Writable<T> {
  /** 强制从 storage 重新加载（初始化时自动调用一次） */
  refresh(): Promise<void>;
  /** 更新部分字段并持久化 */
  update(updater: (current: T) => T): void;
  /** 直接设置并持久化 */
  set(value: T): void;
}

/**
 * 创建一个由 browser.storage.local 支持的响应式 store
 * @param key storage key
 * @param defaultValue 默认值（storage 为空时使用）
 */
export function createStore<T extends Record<string, any>>(
  key: string,
  defaultValue: T,
): StorageStore<T> {
  const store = writable<T>({ ...defaultValue });
  let initialized = false;

  async function load(): Promise<T> {
    try {
      const result = await browser.storage.local.get(key);
      return result[key] ? { ...defaultValue, ...result[key] } : { ...defaultValue };
    } catch {
      return { ...defaultValue };
    }
  }

  async function save(value: T): Promise<void> {
    try {
      await browser.storage.local.set({ [key]: value });
    } catch {
      // 静默失败：storage 配额/权限问题不应阻塞 UI
    }
  }

  async function refresh() {
    const loaded = await load();
    store.set(loaded);
    initialized = true;
  }

  // 初始化加载
  refresh();

  // 监听其他页面/面板对同一 key 的修改，保持同步
  if (typeof browser !== 'undefined' && browser.storage?.onChanged) {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[key] && initialized) {
        store.set({ ...defaultValue, ...changes[key].newValue });
      }
    });
  }

  return {
    subscribe: store.subscribe,
    refresh,
    set: (value: T) => {
      store.set(value);
      save(value);
    },
    update: (updater: (current: T) => T) => {
      let updated: T;
      store.update((current) => {
        updated = updater(current);
        return updated;
      });
      save(updated!);
    },
  };
}
