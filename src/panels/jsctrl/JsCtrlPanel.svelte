<script lang="ts">
  // JS 控制面板
  // 1. JS 启用/禁用（declarativeNetRequest）
  // 2. 反调试扫描 + 绕过（scripting MAIN world）
  // 3. 复制限制解除（scripting insertCSS + 事件拦截）
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTab, execInTab, insertCss } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { confirmStore } from '@/stores/confirm';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { toMarkdownTable } from '@/lib/actions/serializers';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';

  interface AntiDebugDetection { type: string; desc: string }

  let jsBlocked = $state(false);
  let detections = $state<AntiDebugDetection[]>([]);
  let scannedCount = $state(0);
  let bypassed = $state(false);
  let uncopyLog = $state<Record<string, number> | null>(null);

  // 启动时查询当前 JS 阻断状态
  $effect(() => {
    sendMessage({ type: 'QUERY_JS_BLOCK' }).then(r => {
      jsBlocked = !!r?.blocked;
    }).catch(() => {
      /* background 未就绪，忽略 */
    });
  });

  async function toggleJs(enable: boolean) {
    const r = await sendMessage({ type: 'TOGGLE_JS', enable });
    if (r.success) {
      jsBlocked = !enable;
      toastStore.show(`${enable ? '已启用' : '已禁用'} JavaScript，请刷新页面`, 'success');
    } else {
      toastStore.show(`操作失败: ${r.error || '未知错误'}`, 'error');
    }
  }

  async function resetAllRules() {
    if (!(await confirmStore.ask({
      title: '清除 JS 阻断规则',
      message: '确定一键清除所有 JS 阻断规则？',
      confirmLabel: '清除',
      variant: 'danger',
    }))) return;
    const r = await sendMessage({ type: 'TOGGLE_JS', enable: true });
    if (r.success) {
      jsBlocked = false;
      toastStore.show('已清除所有 JS 阻断规则，请刷新页面', 'success');
    } else {
      toastStore.show(`操作失败: ${r.error || '未知错误'}`, 'error');
    }
  }

  // —— TaskController 接管反调试扫描状态机 ——
  const controller = createTaskController<void, void>({
    run: async (_input, ctx) => {
      detections = [];
      bypassed = false;
      const tab = await getActiveTab();
      if (!tab?.id) throw new Error('无法获取当前标签页');

      ctx.reportProgress({ phase: '扫描内联脚本' });
      // Phase 1: 内联脚本扫描（MAIN world）
      const inline = await execInTab<{ detections: any[]; externalUrls: string[] }>(
        tab.id,
        function () {
          const detections: any[] = [];
          const isNative = (fn: any) => /\[native code\]/.test(Function.prototype.toString.call(fn));
          if (!isNative(Function.prototype.constructor))
            detections.push({ type: 'Function劫持', desc: 'Function.prototype.constructor 已被重写' });
          if (!isNative(setInterval))
            detections.push({ type: '定时器劫持', desc: 'setInterval 已被重写，可能用于反调试' });
          if (!isNative(setTimeout))
            detections.push({ type: '定时器劫持', desc: 'setTimeout 已被重写，可能用于反调试' });
          if (!isNative(console.log))
            detections.push({ type: 'Console劫持', desc: 'console.log 已被重写' });

          const inlinePats: [RegExp, string, string][] = [
            [/debugger/, 'debugger语句', '检测到 inline script 中的 debugger 语句'],
            [/outerWidth\s*-\s*innerWidth\s*>\s*\d+/, 'DevTools检测', '通过窗口尺寸差检测开发者工具'],
            [/Firebug|firebug|chrome\.devtools/, 'DevTools检测', '检测到 Firebug/DevTools 探测代码'],
            [/new\s+Image.*onerror.*devtools/i, 'DevTools检测', '通过 Image.onerror 检测开发者工具'],
          ];
          const found: Record<number, boolean> = {};
          const scripts = document.querySelectorAll('script');
          const externalUrls: string[] = [];
          for (let i = 0; i < scripts.length; i++) {
            if ((scripts[i] as HTMLScriptElement).src) externalUrls.push((scripts[i] as HTMLScriptElement).src);
            const text = scripts[i].textContent || '';
            if (!text) continue;
            for (let p = 0; p < inlinePats.length; p++) {
              if (!found[p] && inlinePats[p][0].test(text)) {
                detections.push({ type: inlinePats[p][1], desc: inlinePats[p][2] });
                found[p] = true;
              }
            }
          }
          return { detections, externalUrls };
        },
        { world: 'MAIN' },
      );

      let allDetections: AntiDebugDetection[] = [...(inline?.detections || [])];

      // Phase 2: 外部 JS 扫描（background fetch）
      const externalUrls = inline?.externalUrls || [];
      const antiDebugPatterns: { regex: RegExp; type: string; desc: string }[] = [
        { regex: /\bdebugger\b/, type: 'debugger语句', desc: '外部 JS 中包含 debugger 语句' },
        { regex: /outerWidth\s*-\s*innerWidth\s*>\s*\d+/, type: 'DevTools检测', desc: '外部 JS 通过窗口尺寸差检测 DevTools' },
        { regex: /Firebug|firebug|chrome\.devtools/i, type: 'DevTools检测', desc: '外部 JS 包含 Firebug/DevTools 探测' },
        { regex: /setInterval\s*\(\s*function\s*\([^)]*\)\s*\{[^}]*debugger/, type: 'debugger循环', desc: '外部 JS 包含 setInterval + debugger 循环' },
        { regex: /constructor\s*=\s*function/, type: 'Function劫持', desc: '外部 JS 包含 constructor 重写代码' },
        { regex: /new\s+Image.*onerror.*devtools/i, type: 'DevTools检测', desc: '外部 JS 通过 Image.onerror 检测开发者工具' },
      ];
      const seenTypes: Record<string, boolean> = {};
      for (const d of allDetections) seenTypes[d.type] = true;

      ctx.reportProgress({ total: Math.min(externalUrls.length, 10), completed: 0, phase: '扫描外部 JS' });
      let scanned = 0;
      for (let u = 0; u < externalUrls.length && scanned < 10; u++) {
        if (ctx.signal.aborted) break;
        const fr = await sendMessage({ type: 'FETCH_URL', url: externalUrls[u], timeout: 12000 });
        const data = (fr as any).data;
        if (data && data.length > 0) {
          scanned++;
          ctx.reportProgress({ completed: scanned });
          for (const p of antiDebugPatterns) {
            if (p.regex.test(data) && !seenTypes[p.type]) {
              seenTypes[p.type] = true;
              allDetections.push({ type: p.type, desc: p.desc });
            }
          }
        }
      }

      detections = allDetections;
      scannedCount = scanned;
    },
  }, { centerPanel: 'jsctrl', centerLabel: '反调试扫描' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let scanning = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function scanAntiDebug() {
    const r = await controller.start();
    if (r.status === 'succeeded') {
      if (detections.length === 0) {
        toastStore.show(`未检测到反调试（已扫描 ${scannedCount} 个外部 JS）`, 'success');
      } else {
        toastStore.show(`检测到 ${detections.length} 项反调试`, 'warning');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  // —— 导出序列化器 ——
  function jsctrlMd(items: AntiDebugDetection[]): string {
    return toMarkdownTable(['类型', '描述'], items.map(d => [d.type, d.desc]));
  }
  function jsctrlText(items: AntiDebugDetection[]): string {
    return items.map(d => `[${d.type}] ${d.desc}`).join('\n');
  }

  async function bypassAntiDebug() {
    if (!(await confirmStore.ask({
      title: '绕过反调试',
      message: '即将重写 Function.prototype 并覆盖 console 方法绕过反调试，是否继续？',
      confirmLabel: '绕过',
      variant: 'danger',
    }))) return;
    const tab = await getActiveTab();
    if (!tab?.id) return;
    const ok = await execInTab(
      tab.id,
      function () {
        const nativeConsoleLog = (function () {
          const iframe = document.createElement('iframe');
          iframe.style.display = 'none';
          document.head.appendChild(iframe);
          const log = (iframe.contentWindow as any).console.log;
          document.head.removeChild(iframe);
          return log;
        })();
        const OriginalFunction = Function.prototype.constructor;
        Function.prototype.constructor = function () {
          const args = Array.prototype.slice.call(arguments);
          if (args.length > 0 && typeof args[0] === 'string') {
            args[0] = (args[0] as string).replace(/debugger/g, '');
            if (/^\s*$/.test(args[0] as string)) return function () {};
          }
          return new (Function.prototype.bind.apply(OriginalFunction, [null].concat(args) as any))();
        };
        const originalEval = window.eval;
        window.eval = function (code: any) {
          if (typeof code === 'string') code = code.replace(/debugger/g, '');
          return originalEval.call(window, code);
        };
        const originalSetInterval = window.setInterval;
        const originalSetTimeout = window.setTimeout;
        const cleanCallback = (fn: any) => {
          if (typeof fn === 'string') return fn.replace(/debugger/g, '');
          if (typeof fn === 'function') {
            const s = fn.toString();
            if (s.includes('debugger')) {
              try {
                const cleaned = s.replace(/debugger/g, '');
                return new Function(
                  cleaned.replace(/^function\s*\w*\s*\([^)]*\)\s*\{/, '').replace(/\}$/, ''),
                );
              } catch {
                return function () {};
              }
            }
          }
          return fn;
        };
        window.setInterval = function (fn: any, delay: number) {
          const args = Array.prototype.slice.call(arguments, 2);
          return (originalSetInterval as any).apply(window, [cleanCallback(fn), delay].concat(args));
        } as any;
        window.setTimeout = function (fn: any, delay: number) {
          const args = Array.prototype.slice.call(arguments, 2);
          return (originalSetTimeout as any).apply(window, [cleanCallback(fn), delay].concat(args));
        } as any;
        if (!(console.log as any).restore) {
          console.log = nativeConsoleLog as any;
          (console.log as any).restore = true;
        }
        return true;
      },
      { world: 'MAIN' },
    );
    if (ok) {
      bypassed = true;
      toastStore.show('反调试绕过已注入（刷新后失效）', 'success');
    } else {
      toastStore.show('注入失败', 'error');
    }
  }

  async function removeCopyRestrictions() {
    const tab = await getActiveTab();
    if (!tab?.id) {
      toastStore.show('无法获取当前标签页', 'error');
      return;
    }
    await insertCss(tab.id, '.__vk-hidden { display: none !important; }');
    const log = await execInTab<Record<string, number>>(
      tab.id,
      function () {
        const log: Record<string, number> = {};
        const allEls = document.querySelectorAll('*');
        let userSelect = 0;
        for (let i = 0; i < allEls.length; i++) {
          const style = window.getComputedStyle(allEls[i]);
          const us = style.getPropertyValue('user-select') || style.getPropertyValue('-webkit-user-select');
          if (us === 'none' || us === '-webkit-none') userSelect++;
        }
        log.userSelect = userSelect;
        const eventAttrs = ['oncopy', 'oncut', 'onpaste', 'onselectstart', 'oncontextmenu', 'ondragstart', 'onbeforecopy', 'onbeforecut', 'onbeforepaste'];
        let inlineAttrs = 0;
        for (let j = 0; j < allEls.length; j++) {
          for (let a = 0; a < eventAttrs.length; a++) {
            if ((allEls[j] as any).hasAttribute(eventAttrs[a])) {
              (allEls[j] as any).removeAttribute(eventAttrs[a]);
              inlineAttrs++;
            }
          }
        }
        log.inlineAttrs = inlineAttrs;
        const blockEvents = ['copy', 'cut', 'paste', 'selectstart', 'contextmenu', 'dragstart'];
        blockEvents.forEach(function (evt) {
          document.addEventListener(evt, function (e) { e.stopImmediatePropagation(); }, true);
          document.body.addEventListener(evt, function (e) { e.stopImmediatePropagation(); }, true);
        });
        log.captureListeners = blockEvents.length;
        let pointer = 0;
        for (let k = 0; k < allEls.length; k++) {
          const s = window.getComputedStyle(allEls[k]);
          if (s.getPropertyValue('pointer-events') === 'none') {
            const tag = allEls[k].tagName.toLowerCase();
            const transparent = s.getPropertyValue('opacity') === '0' || s.getPropertyValue('background') === 'rgba(0, 0, 0, 0)' || (s as any).backgroundColor === 'transparent';
            if (transparent && (tag === 'div' || tag === 'span' || tag === 'a' || tag === 'img')) {
              (allEls[k] as any).classList.add('__vk-hidden');
              pointer++;
            }
          }
        }
        log.pointerOverlays = pointer;
        return log;
      },
      { world: 'MAIN' },
    );
    if (log) {
      await insertCss(
        tab.id,
        '*, *::before, *::after { -webkit-user-select: auto !important; user-select: auto !important; -webkit-user-drag: auto !important; }',
      );
      uncopyLog = log;
      toastStore.show('复制限制已解除', 'success');
    } else {
      toastStore.show('操作失败', 'error');
    }
  }
</script>

<div class="space-y-4">
  <!-- JS 开关 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium">JavaScript 控制</div>
        <div class="text-xs text-gray-500">
          {jsBlocked ? '⛔ JavaScript 已禁用（刷新页面生效）' : '✅ JavaScript 正常运行'}
        </div>
      </div>
      <div class="flex gap-1">
        <button class="btn btn-sm" class:bg-gray-400={jsBlocked} disabled={jsBlocked} onclick={() => toggleJs(false)}>禁用 JS</button>
        <button class="btn btn-sm btn-primary" disabled={!jsBlocked} onclick={() => toggleJs(true)}>启用 JS</button>
        <button class="btn btn-sm text-red-500" onclick={resetAllRules}>一键清除</button>
      </div>
    </div>
  </div>

  <!-- 反调试 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">反调试检测</div>
      <div class="flex gap-1">
        {#if scanning}
          <button class="btn btn-sm btn-danger" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
        {:else}
          <button class="btn btn-sm btn-primary" onclick={scanAntiDebug}>扫描反调试</button>
        {/if}
        <button class="btn btn-sm" disabled={detections.length === 0 || bypassed} onclick={bypassAntiDebug}>绕过</button>
        <ExportMenu items={detections} module="jsctrl" serializers={{ markdown: jsctrlMd, text: jsctrlText }} />
      </div>
    </div>
    {#if cs.status === 'failed'}
      <ErrorState error={cs.error!} onRetry={scanAntiDebug} />
    {:else if detections.length > 0}
      <div class="space-y-1">
        {#each detections as d}
          <div class="text-xs">
            <span class="font-semibold text-yellow-600 dark:text-yellow-500">[{d.type}]</span> {d.desc}
          </div>
        {/each}
        {#if scannedCount > 0}
          <div class="text-xs text-gray-400">已扫描 {scannedCount} 个外部 JS 文件</div>
        {/if}
      </div>
    {:else if !scanning}
      <div class="text-xs text-gray-400">点击「扫描反调试」检测页面中的反调试手段</div>
    {/if}
  </div>

  <!-- 复制限制解除 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">解除复制限制</div>
      <button class="btn btn-sm btn-primary" onclick={removeCopyRestrictions}>解除</button>
    </div>
    {#if uncopyLog}
      <div class="space-y-1 text-xs">
        {#if uncopyLog.userSelect > 0}<div>✓ 解除 <b>{uncopyLog.userSelect}</b> 个元素的 user-select: none</div>{/if}
        {#if uncopyLog.inlineAttrs > 0}<div>✓ 移除 <b>{uncopyLog.inlineAttrs}</b> 个内联事件拦截</div>{/if}
        {#if uncopyLog.pointerOverlays > 0}<div>✓ 隐藏 <b>{uncopyLog.pointerOverlays}</b> 个透明遮罩层</div>{/if}
        {#if uncopyLog.captureListeners}<div>✓ 注册 <b>{uncopyLog.captureListeners}</b> 种 capture 事件拦截</div>{/if}
      </div>
    {:else}
      <div class="text-xs text-gray-400">移除禁选/禁右键/禁复制等限制</div>
    {/if}
  </div>
</div>
