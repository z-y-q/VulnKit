<script lang="ts">
  // 编码工具面板 — 灵眸 v6.0
  // 三个子视图：经典编码（Base64/URL/HTML/Hex）、JWT 解析、加密解密（占位）
  import { encodingTools } from '@/lib/crypto/encoding';
  import { decode as decodeJwt, type DecodedJwt } from '@/lib/crypto/jwt';
  import { toastStore } from '@/stores/ui';

  type View = 'classic' | 'jwt' | 'crypto';
  let view = $state<View>('classic');

  // —— 经典编码 ——
  type EncType = 'base64' | 'url' | 'html' | 'hex';
  let activeTab = $state<EncType>('base64');
  let mode = $state<'encode' | 'decode'>('encode');
  let input = $state('');
  let output = $state('');

  function transform() {
    try {
      const tool = encodingTools[activeTab];
      output = mode === 'encode' ? tool.encode(input) : tool.decode(input);
    } catch {
      output = '⚠️ 编码/解码失败（输入无效）';
    }
  }

  $effect(() => {
    // 依赖 input / activeTab / mode
    if (input) transform();
    else output = '';
  });

  function copyOutput() {
    if (!output) {
      toastStore.show('没有可复制的内容', 'warning');
      return;
    }
    navigator.clipboard.writeText(output).then(() => toastStore.show('已复制到剪贴板', 'success'));
  }

  function swap() {
    const tmp = input;
    input = output;
    output = tmp;
  }

  // —— JWT 解析 ——
  let jwtInput = $state('');
  let decoded = $state<DecodedJwt | null>(null);
  let jwtError = $state('');

  function parseJwt() {
    jwtError = '';
    if (!jwtInput.trim()) {
      decoded = null;
      return;
    }
    const result = decodeJwt(jwtInput.trim());
    if (result) {
      decoded = result;
    } else {
      decoded = null;
      jwtError = '无效的 JWT（格式应为 header.payload.signature）';
    }
  }

  $effect(() => {
    parseJwt();
  });

  function severityClass(sev: string): string {
    if (sev === 'high' || sev === 'critical') return 'text-red-500';
    if (sev === 'medium') return 'text-yellow-500';
    if (sev === 'low') return 'text-blue-500';
    return 'text-gray-500';
  }
</script>

<div class="space-y-3">
  <!-- 子视图切换 -->
  <div class="flex gap-1">
    {#each [{ id: 'classic', label: '经典编码' }, { id: 'jwt', label: 'JWT 解析' }, { id: 'crypto', label: '加密解密' }] as v}
      <button
        class="btn btn-sm {view === v.id ? 'bg-primary text-white' : 'btn-ghost'}"
        onclick={() => (view = v.id as View)}
      >
        {v.label}
      </button>
    {/each}
  </div>

  {#if view === 'classic'}
    <!-- 编码类型 -->
    <div class="flex gap-1 flex-wrap">
      {#each [{ id: 'base64', label: 'Base64' }, { id: 'url', label: 'URL' }, { id: 'html', label: 'HTML' }, { id: 'hex', label: 'Hex' }] as t}
        <button
          class="btn btn-xs {activeTab === t.id ? 'bg-primary text-white' : 'btn-ghost'}"
          onclick={() => (activeTab = t.id as EncType)}
        >
          {t.label}
        </button>
      {/each}
    </div>

    <div class="flex gap-1">
      <button class="btn btn-sm {mode === 'encode' ? 'bg-primary text-white' : 'btn-ghost'}" onclick={() => (mode = 'encode')}>编码</button>
      <button class="btn btn-sm {mode === 'decode' ? 'bg-primary text-white' : 'btn-ghost'}" onclick={() => (mode = 'decode')}>解码</button>
      <button class="btn btn-sm btn-ghost ml-auto" onclick={swap} title="输入输出互换">⇅</button>
    </div>

    <div>
      <label class="block text-xs text-gray-500 mb-1">输入</label>
      <textarea class="input font-mono text-xs" rows="3" placeholder="输入需要编码/解码的内容..." bind:value={input}></textarea>
    </div>

    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs text-gray-500">输出</span>
        {#if output}<button class="text-xs text-primary hover:underline" onclick={copyOutput}>复制</button>{/if}
      </div>
      <div class="input font-mono text-xs min-h-12 whitespace-pre-wrap break-all bg-gray-50 dark:bg-gray-900 py-2 px-3">
        {output || '<span class="text-gray-400">等待输入...</span>'}
      </div>
    </div>

  {:else if view === 'jwt'}
    <div>
      <label class="block text-xs text-gray-500 mb-1">JWT Token</label>
      <textarea class="input font-mono text-xs" rows="3" placeholder="粘贴 JWT（eyJ...）" bind:value={jwtInput}></textarea>
    </div>

    {#if jwtError}
      <div class="text-xs text-red-500">{jwtError}</div>
    {/if}

    {#if decoded}
      <!-- 算法 -->
      <div class="card p-2">
        <div class="text-xs text-gray-500 mb-1">Header / 算法</div>
        <div class="font-mono text-xs break-all">{decoded.header.alg} · {decoded.header.typ || 'JWT'}</div>
      </div>

      <!-- 安全发现 -->
      {#if decoded.findings.length > 0}
        <div class="card p-2 space-y-1">
          <div class="text-xs text-gray-500">安全发现（{decoded.findings.length}）</div>
          {#each decoded.findings as f}
            <div class="text-xs">
              <span class="font-semibold {severityClass(f.severity)}">[{f.severity.toUpperCase()}]</span>
              <span class="font-medium">{f.title}</span> — {f.detail}
            </div>
          {/each}
        </div>
      {/if}

      <!-- Payload -->
      <div>
        <div class="text-xs text-gray-500 mb-1">Payload</div>
        <pre class="input font-mono text-xs whitespace-pre-wrap break-all bg-gray-50 dark:bg-gray-900 py-2 px-3 max-h-60 overflow-auto">{JSON.stringify(decoded.payload, null, 2)}</pre>
      </div>
    {:else if !jwtError}
      <div class="text-xs text-gray-400 text-center py-4">粘贴 JWT 后自动解析</div>
    {/if}

  {:else}
    <div class="text-xs text-gray-400 text-center py-8">
      <div class="text-3xl mb-2">🔐</div>
      <div>加密解密（AES/DES/RC4/SM2/SM4/RSA）将在后续批次实现</div>
      <div class="mt-1">需引入 crypto-js / sm-crypto 第三方库</div>
    </div>
  {/if}
</div>
