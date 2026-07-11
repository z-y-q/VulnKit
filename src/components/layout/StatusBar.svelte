<script lang="ts">
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

<footer class="flex items-center justify-between px-3 py-1 text-xs text-gray-400 dark:text-gray-500 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0">
  <span>灵眸 v6.0</span>
  <span>{time}</span>
</footer>
