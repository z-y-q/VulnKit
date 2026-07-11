<script lang="ts">
  // 严重级别徽章 — 统一所有扫描面板的风险着色
  // 颜色/标签/排序全部来自 @/lib/types/severity（全项目唯一真相源）
  import { SEVERITY_COLORS, normalizeSeverity, severityLabel } from '@/lib/types/severity';

  let {
    severity,
    label,
  }: { severity: string; label?: string } = $props();

  let sev = $derived(normalizeSeverity(severity));
  let cls = $derived(SEVERITY_COLORS[sev]);
  let text = $derived(label ?? severityLabel(severity));
</script>

<span class="badge text-xs {cls}">{text}</span>
