/**
 * §7.2 面板状态 store：payload 面板
 * 防止面板切换时丢失分类选择、搜索词、展开状态、SQLi 参数、反弹 shell 配置
 */
import { createStore } from '@/lib/core/storage-store';

type CategoryKey = 'xss' | 'sqli' | 'lfi' | 'reverse_shell' | 'webshell' | 'cmdref';

interface PayloadState {
  activeCategory: CategoryKey;
  searchText: string;
  expandedSubs: Record<string, boolean>;
  sqliColumns: number;
  sqliTable: string;
  revIp: string;
  revPort: string;
}

const DEFAULT_STATE: PayloadState = {
  activeCategory: 'xss',
  searchText: '',
  expandedSubs: {},
  sqliColumns: 3,
  sqliTable: 'users',
  revIp: '',
  revPort: '4444',
};

export const payloadStateStore = createStore<PayloadState>('lingmou:payload-state', DEFAULT_STATE);
