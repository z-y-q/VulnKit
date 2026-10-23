/**
 * §7.2 面板状态 store：source-loader 面板
 * 防止面板切换时丢失已加载的源码、搜索词、URL 队列
 */
import { createStore } from '@/lib/core/storage-store';

interface SourceLoaderState {
  url: string;
  source: string;
  searchText: string;
  showLineNumbers: boolean;
  pendingUrls: string[];
}

const DEFAULT_STATE: SourceLoaderState = {
  url: '',
  source: '',
  searchText: '',
  showLineNumbers: true,
  pendingUrls: [],
};

export const sourceLoaderStateStore = createStore<SourceLoaderState>('lingmou:source-loader-state', DEFAULT_STATE);
