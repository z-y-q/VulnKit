<script lang="ts">
  import { getAppVersion } from '@/lib/core/app-version';
  import TaskCenterPopover from '@/components/layout/TaskCenterPopover.svelte';

  let version = $derived(getAppVersion());
  let time = $state('');

  function updateTime() {
    const now = new Date();
    time = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
  }

  $effect(() => {
    updateTime();
    const interval = setInterval(updateTime, 30000);
    return () => clearInterval(interval);
  });
</script>

<footer class="flex items-center justify-between px-4 py-1.5 text-[11px] text-gray-400 dark:text-gray-500 border-t border-gray-200/40 dark:border-gray-700/20 bg-gray-50/80 dark:bg-slate-900/40 shrink-0 vk-glass">
  <div class="flex items-center gap-1.5">
    <div class="w-3 h-3 rounded bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center text-white text-[6px] font-bold shadow-sm">灵</div>
    <span class="font-medium">v{version}</span>
  </div>
  <div class="flex items-center gap-2">
    <TaskCenterPopover />
    <span class="font-mono tabular-nums">{time}</span>
  </div>
</footer>
