/**
 * §7.2 面板状态 store：HAE 规则引擎面板
 * 防止面板切换时丢失输入文本、匹配结果、筛选设置
 */
import { createStore } from '@/lib/core/storage-store';
import type { HaeMatch } from '@/lib/scanners/hae-engine';

interface HaeState {
  inputText: string;
  matches: HaeMatch[];
  groupFilter: string;
  onlySensitive: boolean;
}

const DEFAULT_STATE: HaeState = {
  inputText: '',
  matches: [],
  groupFilter: 'all',
  onlySensitive: false,
};

export const haeStateStore = createStore<HaeState>('lingmou:hae-state', DEFAULT_STATE);
