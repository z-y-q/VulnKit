<script lang="ts">
  // 严重级别徽章 — 统一所有扫描面板的风险着色
  export type Sev = 'critical' | 'high' | 'danger' | 'medium' | 'warning' | 'low' | 'info' | 'safe';

  let {
    severity,
    label,
  }: { severity: Sev | string; label?: string } = $props();

  const COLORS: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-red-500 text-white',
    danger: 'bg-red-500 text-white',
    warning: 'bg-yellow-500 text-white',
    medium: 'bg-yellow-500 text-white',
    low: 'bg-blue-500 text-white',
    info: 'bg-blue-500 text-white',
    safe: 'bg-gray-400 text-white',
  };

  const LABELS: Record<string, string> = {
    critical: '严重',
    high: '高危',
    danger: '危险',
    warning: '警告',
    medium: '中危',
    low: '低危',
    info: '信息',
    safe: '安全',
  };

  let cls = $derived(COLORS[severity] ?? 'bg-gray-400 text-white');
  let text = $derived(label ?? LABELS[severity] ?? severity);
</script>

<span class="badge text-xs {cls}">{text}</span>
