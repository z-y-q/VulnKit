<script lang="ts">
  // 编码工具面板
  // 三个子视图：经典编码（Base64/URL/HTML/Hex）、JWT 解析、加密解密（占位）
  import { encodingTools } from '@/lib/crypto/encoding';
  import { decode as decodeJwt, verifySignature, forgeNoneToken, type DecodedJwt, type JwtVerifyResult } from '@/lib/crypto/jwt';
  import { toastStore } from '@/stores/ui';
  import { loadPrefs } from '@/lib/core/general-prefs';
  import { copyText } from '@/lib/actions/clipboard';

  type View = 'classic' | 'jwt' | 'crypto';
  let view = $state<View>('classic');

  // —— 经典编码 ——
  type EncType = 'base64' | 'url' | 'html' | 'hex';
  let activeTab = $state<EncType>('base64');

  // 从通用偏好读取默认编码 / 默认哈希（options 页可配）
  $effect(() => {
    loadPrefs().then(p => {
      activeTab = p.defaultEncoding as EncType;
      const hashMap: Record<string, HashAlgo> = { 'SHA-256': 'sha256', 'SHA-1': 'sha1', MD5: 'md5' };
      if (hashMap[p.defaultHash]) pHash.algo = hashMap[p.defaultHash];
    });
  });
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
    copyText(output, '已复制到剪贴板');
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

  // —— JWT 签名验证 ——
  let jwtKey = $state('');
  let jwtVerify = $state<JwtVerifyResult | null>(null);
  let jwtVerifying = $state(false);

  async function doVerifyJwt() {
    if (!jwtInput.trim()) { toastStore.show('请先粘贴 JWT', 'warning'); return; }
    jwtVerifying = true;
    jwtVerify = null;
    try {
      jwtVerify = await verifySignature(jwtInput.trim(), jwtKey);
    } catch (e: any) {
      jwtVerify = { valid: false, alg: '?', error: e.message || String(e) };
    } finally {
      jwtVerifying = false;
    }
  }

  function forgeNone() {
    if (!jwtInput.trim()) { toastStore.show('请先粘贴 JWT', 'warning'); return; }
    const forged = forgeNoneToken(jwtInput.trim());
    copyText(forged, 'alg=none PoC 已复制（仅用于授权测试）');
  }

  // —— 加密解密 ——
  import {
    aesEncrypt, aesDecrypt, desEncrypt, desDecrypt, rc4Encrypt, rc4Decrypt,
    sm2Encrypt, sm2Decrypt, sm4Encrypt, sm4Decrypt,
    rsaEncrypt, rsaDecrypt, rsaGenerateKeyPair, computeHash,
    bcryptHash, bcryptVerify,
    WEAK_ALGO_WARNINGS,
    type AesMode, type AesPadding, type HashAlgo,
  } from '@/lib/crypto/crypto-engine';

  type CryptoAlgo = 'aes' | 'des' | 'rc4' | 'sm2' | 'sm4' | 'rsa' | 'hash' | 'bcrypt';
  let cryptoAlgo = $state<CryptoAlgo>('aes');
  let cryptoMode = $state<'encrypt' | 'decrypt'>('encrypt');
  let cryptoInput = $state('');
  let cryptoOutput = $state('');
  let cryptoBusy = $state(false);

  // 各算法参数
  let pAes = $state({ mode: 'CBC' as AesMode, keySize: 128 as 128 | 192 | 256, padding: 'Pkcs7' as AesPadding, key: '', iv: '' });
  let pDes = $state({ mode: 'CBC' as 'CBC' | 'ECB', padding: 'Pkcs7' as AesPadding, key: '', iv: '', triple: false });
  let pRc4 = $state({ key: '' });
  let pSm2 = $state({ publicKey: '', privateKey: '', cipherMode: 1 as 0 | 1 });
  let pSm4 = $state({ key: '', mode: 'ecb' as 'ecb' | 'cbc', iv: '', padding: true });
  let pRsa = $state({ publicKeyPem: '', privateKeyPem: '' });
  let pHash = $state({ algo: 'sha256' as HashAlgo, output: 'hex' as 'hex' | 'base64', hmac: false, hmacKey: '' });
  let pBcrypt = $state({ cost: 10, hash: '' });

  const ALGO_LABELS: Record<CryptoAlgo, string> = {
    aes: 'AES', des: 'DES/3DES', rc4: 'RC4', sm2: 'SM2', sm4: 'SM4', rsa: 'RSA', hash: 'Hash', bcrypt: 'Bcrypt',
  };
  const CRYPTO_ALGOS: CryptoAlgo[] = ['aes', 'des', 'rc4', 'sm2', 'sm4', 'rsa', 'hash', 'bcrypt'];

  function weakWarning(): string | null {
    if (cryptoAlgo === 'des') return pDes.triple ? WEAK_ALGO_WARNINGS['3DES'] : WEAK_ALGO_WARNINGS.DES;
    if (cryptoAlgo === 'rc4') return WEAK_ALGO_WARNINGS.RC4;
    if (cryptoAlgo === 'aes' && pAes.mode === 'ECB') return WEAK_ALGO_WARNINGS['AES-ECB'];
    if (cryptoAlgo === 'hash' && (pHash.algo === 'md5')) return WEAK_ALGO_WARNINGS.MD5;
    if (cryptoAlgo === 'hash' && pHash.algo === 'sha1') return WEAK_ALGO_WARNINGS.SHA1;
    return null;
  }

  async function runCrypto() {
    if (!cryptoInput.trim() && cryptoAlgo !== 'rsa') {
      toastStore.show('请输入内容', 'warning'); return;
    }
    cryptoBusy = true;
    cryptoOutput = '';
    try {
      let result = '';
      const m = cryptoMode;
      switch (cryptoAlgo) {
        case 'aes': result = m === 'encrypt' ? aesEncrypt(cryptoInput, pAes) : aesDecrypt(cryptoInput, pAes); break;
        case 'des': result = m === 'encrypt' ? desEncrypt(cryptoInput, pDes) : desDecrypt(cryptoInput, pDes); break;
        case 'rc4': result = m === 'encrypt' ? rc4Encrypt(cryptoInput, pRc4.key) : rc4Decrypt(cryptoInput, pRc4.key); break;
        case 'sm2': result = m === 'encrypt' ? sm2Encrypt(cryptoInput, pSm2) : sm2Decrypt(cryptoInput, pSm2); break;
        case 'sm4': result = m === 'encrypt' ? sm4Encrypt(cryptoInput, pSm4) : sm4Decrypt(cryptoInput, pSm4); break;
        case 'rsa': result = m === 'encrypt' ? await rsaEncrypt(cryptoInput, pRsa.publicKeyPem) : await rsaDecrypt(cryptoInput, pRsa.privateKeyPem); break;
        case 'hash': result = computeHash(cryptoInput, pHash); break;
        case 'bcrypt':
          if (m === 'encrypt') {
            result = bcryptHash(cryptoInput, pBcrypt.cost);
          } else {
            const ok = bcryptVerify(cryptoInput, pBcrypt.hash || cryptoOutput);
            result = ok ? '✔ 口令匹配哈希' : '✗ 口令不匹配';
          }
          break;
      }
      cryptoOutput = result;
      toastStore.show('操作完成', 'success');
    } catch (e: any) {
      cryptoOutput = '⚠️ ' + (e.message || String(e));
      toastStore.show(e.message || '操作失败', 'error');
    } finally {
      cryptoBusy = false;
    }
  }

  async function genRsaKeyPair() {
    cryptoBusy = true;
    try {
      const kp = await rsaGenerateKeyPair(2048);
      pRsa.publicKeyPem = kp.publicKeyPem;
      pRsa.privateKeyPem = kp.privateKeyPem;
      toastStore.show('RSA 2048 位密钥对已生成', 'success');
    } catch (e: any) {
      toastStore.show('生成失败: ' + (e.message || ''), 'error');
    } finally {
      cryptoBusy = false;
    }
  }

  function copyCryptoOutput() {
    if (!cryptoOutput) return;
    copyText(cryptoOutput, '已复制');
  }
</script>

<div class="space-y-3">
  <!-- 子视图切换（分段控件） -->
  <div class="seg">
    {#each [{ id: 'classic', label: '经典编码' }, { id: 'jwt', label: 'JWT 解析' }, { id: 'crypto', label: '加密解密' }] as v}
      <button
        class={view === v.id ? 'seg-btn-active' : 'seg-btn-inactive'}
        onclick={() => (view = v.id as View)}
      >
        {v.label}
      </button>
    {/each}
  </div>

  {#if view === 'classic'}
   <div class="card p-3 space-y-3">
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

    <div class="flex items-center justify-between gap-2">
      <div class="seg">
        <button class={mode === 'encode' ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (mode = 'encode')}>编码</button>
        <button class={mode === 'decode' ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (mode = 'decode')}>解码</button>
      </div>
      <button class="btn btn-sm btn-ghost" onclick={swap} title="输入输出互换">⇅ 互换</button>
    </div>

    <div>
      <label for="enc-input" class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">输入</label>
      <textarea id="enc-input" class="input font-mono text-xs" rows="3" placeholder="输入需要编码/解码的内容..." bind:value={input}></textarea>
    </div>

    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs font-medium text-gray-600 dark:text-gray-300">输出</span>
        {#if output}<button class="text-xs text-primary hover:underline" onclick={copyOutput}>复制</button>{/if}
      </div>
      <div class="input font-mono text-xs min-h-12 whitespace-pre-wrap break-all bg-gray-50 dark:bg-gray-900 py-2 px-3">
        {output || '<span class="text-gray-500 dark:text-gray-400">等待输入...</span>'}
      </div>
    </div>
   </div>

  {:else if view === 'jwt'}
   <div class="card p-3 space-y-3">
    <div>
      <label for="enc-jwt" class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">JWT Token</label>
      <textarea id="enc-jwt" class="input font-mono text-xs" rows="3" placeholder="粘贴 JWT（eyJ...）" bind:value={jwtInput}></textarea>
    </div>

    {#if jwtError}
      <div class="text-xs text-red-500">{jwtError}</div>
    {/if}

    {#if decoded}
      <!-- 算法 -->
      <div class="card-flat p-3">
        <div class="text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Header / 算法</div>
        <div class="font-mono text-xs break-all">{decoded.header.alg} · {decoded.header.typ || 'JWT'}</div>
      </div>

      <!-- 安全发现 -->
      {#if decoded.findings.length > 0}
        <div class="card-flat p-3 space-y-1">
          <div class="text-xs font-medium text-gray-600 dark:text-gray-300">安全发现（{decoded.findings.length}）</div>
          {#each decoded.findings as f}
            <div class="text-xs">
              <span class="font-semibold {severityClass(f.severity)}">[{f.severity.toUpperCase()}]</span>
              <span class="font-medium">{f.title}</span> — {f.detail}
            </div>
          {/each}
        </div>
      {/if}

      <!-- 签名验证 -->
      <div class="card-flat p-3 space-y-2">
        <div class="text-xs font-medium text-gray-600 dark:text-gray-300">签名验证（HMAC / RSA / ECDSA）</div>
        <input
          class="input text-xs font-mono"
          placeholder={(decoded?.header.alg || '').startsWith('HS') ? 'HMAC 密钥' : 'RSA / EC PEM 公钥'}
          bind:value={jwtKey}
        />
        <div class="flex gap-1">
          <button class="btn btn-xs btn-primary flex-1" onclick={doVerifyJwt} disabled={jwtVerifying}>
            {jwtVerifying ? '验证中...' : '验证签名'}
          </button>
          <button class="btn btn-xs btn-danger" onclick={forgeNone} title="生成 alg=none 攻击 PoC（仅授权测试）">
            none PoC
          </button>
        </div>
        {#if jwtVerify}
          <div class="text-xs px-2 py-1 rounded {jwtVerify.valid ? 'bg-green-50 dark:bg-green-950/40 text-green-700 dark:text-green-400' : 'bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400'}">
            {#if jwtVerify.valid}
              ✅ 签名有效（{jwtVerify.alg}）{jwtVerify.error ? ' — ' + jwtVerify.error : ''}
            {:else}
              ❌ 签名无效或密钥不匹配（{jwtVerify.alg}）{jwtVerify.error ? ' — ' + jwtVerify.error : ''}
            {/if}
          </div>
        {/if}
      </div>

      <!-- Payload -->
      <div>
        <div class="text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Payload</div>
        <pre class="input font-mono text-xs whitespace-pre-wrap break-all bg-gray-50 dark:bg-gray-900 py-2 px-3 max-h-60 overflow-auto">{JSON.stringify(decoded.payload, null, 2)}</pre>
      </div>
    {:else if !jwtError}
      <div class="text-xs text-gray-500 dark:text-gray-400 text-center py-4">粘贴 JWT 后自动解析</div>
    {/if}
   </div>

  {:else}
   <div class="card p-3 space-y-3">
    <!-- 加密算法选择 -->
    <div class="flex gap-1 flex-wrap">
      {#each CRYPTO_ALGOS as a}
        <button
          class="btn btn-xs {cryptoAlgo === a ? 'bg-primary text-white' : 'btn-ghost'}"
          onclick={() => (cryptoAlgo = a)}
        >
          {ALGO_LABELS[a]}
        </button>
      {/each}
    </div>

    <!-- 加密/解密模式（Hash 除外） -->
    {#if cryptoAlgo !== 'hash'}
      <div class="seg">
        <button class={cryptoMode === 'encrypt' ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (cryptoMode = 'encrypt')}>加密</button>
        <button class={cryptoMode === 'decrypt' ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (cryptoMode = 'decrypt')}>解密</button>
      </div>
    {/if}

    <!-- 各算法参数 -->
    <div class="card-flat p-3 space-y-2">
      {#if cryptoAlgo === 'aes'}
        <div class="grid grid-cols-2 gap-2 text-xs">
          <label class="flex flex-col gap-0.5">模式
            <select class="input text-xs" bind:value={pAes.mode}>
              {#each ['CBC', 'ECB', 'CFB', 'OFB', 'CTR'] as m}<option value={m}>{m}</option>{/each}
            </select>
          </label>
          <label class="flex flex-col gap-0.5">密钥长度
            <select class="input text-xs" bind:value={pAes.keySize}>
              <option value={128}>128</option><option value={192}>192</option><option value={256}>256</option>
            </select>
          </label>
          <label class="flex flex-col gap-0.5 col-span-2">填充
            <select class="input text-xs" bind:value={pAes.padding}>
              {#each ['Pkcs7', 'ZeroPadding', 'NoPadding', 'Iso97971'] as m}<option value={m}>{m}</option>{/each}
            </select>
          </label>
          <label class="flex flex-col gap-0.5 col-span-2">密钥（不足自动补 0，超出截断）
            <input class="input text-xs font-mono" bind:value={pAes.key} placeholder="密钥" />
          </label>
          {#if pAes.mode !== 'ECB'}
            <label class="flex flex-col gap-0.5 col-span-2">IV（16 字节）
              <input class="input text-xs font-mono" bind:value={pAes.iv} placeholder="IV" />
            </label>
          {/if}
        </div>
      {:else if cryptoAlgo === 'des'}
        <div class="grid grid-cols-2 gap-2 text-xs">
          <label class="flex flex-col gap-0.5">模式
            <select class="input text-xs" bind:value={pDes.mode}>
              <option value="CBC">CBC</option><option value="ECB">ECB</option>
            </select>
          </label>
          <label class="flex flex-col gap-0.5">填充
            <select class="input text-xs" bind:value={pDes.padding}>
              {#each ['Pkcs7', 'ZeroPadding', 'NoPadding', 'Iso97971'] as m}<option value={m}>{m}</option>{/each}
            </select>
          </label>
          <label class="flex items-center gap-1 col-span-2">
            <input type="checkbox" bind:checked={pDes.triple} class="accent-blue-500" />
            <span>使用 3DES（Triple DES）</span>
          </label>
          <label class="flex flex-col gap-0.5 col-span-2">密钥（8 字节）
            <input class="input text-xs font-mono" bind:value={pDes.key} placeholder="密钥" />
          </label>
          {#if pDes.mode !== 'ECB'}
            <label class="flex flex-col gap-0.5 col-span-2">IV（8 字节）
              <input class="input text-xs font-mono" bind:value={pDes.iv} placeholder="IV" />
            </label>
          {/if}
        </div>
      {:else if cryptoAlgo === 'rc4'}
        <label class="flex flex-col gap-0.5 text-xs">密钥
          <input class="input text-xs font-mono" bind:value={pRc4.key} placeholder="RC4 密钥" />
        </label>
      {:else if cryptoAlgo === 'sm2'}
        <div class="grid grid-cols-2 gap-2 text-xs">
          <label class="flex flex-col gap-0.5 col-span-2">公钥（128/130 位十六进制，加密用）
            <input class="input text-xs font-mono" bind:value={pSm2.publicKey} placeholder="04..." />
          </label>
          <label class="flex flex-col gap-0.5 col-span-2">私钥（64 位十六进制，解密用）
            <input class="input text-xs font-mono" bind:value={pSm2.privateKey} placeholder="私钥" />
          </label>
          <label class="flex flex-col gap-0.5">Cipher 模式
            <select class="input text-xs" bind:value={pSm2.cipherMode}>
              <option value={1}>C1C2C3</option><option value={0}>C1C3C2</option>
            </select>
          </label>
        </div>
      {:else if cryptoAlgo === 'sm4'}
        <div class="grid grid-cols-2 gap-2 text-xs">
          <label class="flex flex-col gap-0.5">模式
            <select class="input text-xs" bind:value={pSm4.mode}>
              <option value="ecb">ECB</option><option value="cbc">CBC</option>
            </select>
          </label>
          <label class="flex items-center gap-1">
            <input type="checkbox" bind:checked={pSm4.padding} class="accent-blue-500" />
            <span>PKCS#5 填充</span>
          </label>
          <label class="flex flex-col gap-0.5 col-span-2">密钥（16 字符）
            <input class="input text-xs font-mono" bind:value={pSm4.key} placeholder="SM4 密钥" maxlength="16" />
          </label>
          {#if pSm4.mode === 'cbc'}
            <label class="flex flex-col gap-0.5 col-span-2">IV
              <input class="input text-xs font-mono" bind:value={pSm4.iv} placeholder="IV" />
            </label>
          {/if}
        </div>
      {:else if cryptoAlgo === 'rsa'}
        <div class="space-y-2 text-xs">
          <button class="btn btn-xs btn-primary" onclick={genRsaKeyPair} disabled={cryptoBusy}>
            {cryptoBusy ? '生成中...' : '生成 RSA 2048 密钥对'}
          </button>
          <label class="flex flex-col gap-0.5">公钥 PEM（加密）
            <textarea class="input text-xs font-mono" rows="2" bind:value={pRsa.publicKeyPem} placeholder="-----BEGIN PUBLIC KEY-----..."></textarea>
          </label>
          <label class="flex flex-col gap-0.5">私钥 PEM（解密）
            <textarea class="input text-xs font-mono" rows="2" bind:value={pRsa.privateKeyPem} placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
          </label>
          <div class="text-gray-400">RSA-OAEP + SHA-256，输出 Base64</div>
        </div>
      {:else if cryptoAlgo === 'hash'}
        <div class="grid grid-cols-2 gap-2 text-xs">
          <label class="flex flex-col gap-0.5">算法
            <select class="input text-xs" bind:value={pHash.algo}>
              {#each ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'] as a}<option value={a}>{a.toUpperCase()}</option>{/each}
            </select>
          </label>
          <label class="flex flex-col gap-0.5">输出
            <select class="input text-xs" bind:value={pHash.output}>
              <option value="hex">Hex</option><option value="base64">Base64</option>
            </select>
          </label>
          <label class="flex items-center gap-1 col-span-2">
            <input type="checkbox" bind:checked={pHash.hmac} class="accent-blue-500" />
            <span>HMAC</span>
          </label>
          {#if pHash.hmac}
            <label class="flex flex-col gap-0.5 col-span-2">HMAC 密钥
              <input class="input text-xs font-mono" bind:value={pHash.hmacKey} placeholder="HMAC 密钥" />
            </label>
          {/if}
        </div>
      {:else if cryptoAlgo === 'bcrypt'}
        <div class="space-y-2 text-xs">
          {#if cryptoMode === 'encrypt'}
            <label class="flex flex-col gap-0.5">Cost（成本因子 4-31，越大越慢越安全）
              <input type="number" min="4" max="31" class="input text-xs font-mono" bind:value={pBcrypt.cost} />
            </label>
            <div class="text-gray-400">对输入口令生成 Bcrypt 哈希（$2a$ 格式）</div>
          {:else}
            <label class="flex flex-col gap-0.5">Bcrypt 哈希
              <input class="input text-xs font-mono" bind:value={pBcrypt.hash} placeholder="$2a$10$...." />
            </label>
            <div class="text-gray-400">验证输入口令是否匹配该哈希</div>
          {/if}
        </div>
      {/if}

      {#if weakWarning()}
        <div class="text-xs text-amber-600 dark:text-amber-400">⚠️ {weakWarning()}</div>
      {/if}
    </div>

    <!-- 输入 -->
    <div>
      <label for="enc-crypto-input" class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">输入</label>
      <textarea id="enc-crypto-input" class="input font-mono text-xs" rows="3" placeholder={cryptoAlgo === 'hash' ? '输入待哈希内容' : '输入明文/密文'} bind:value={cryptoInput}></textarea>
    </div>

    <!-- 操作按钮 -->
    <button class="btn btn-sm btn-primary w-full" onclick={runCrypto} disabled={cryptoBusy}>
      {cryptoBusy ? '处理中...' : cryptoAlgo === 'hash' ? '计算哈希' : (cryptoMode === 'encrypt' ? '加密' : '解密')}
    </button>

    <!-- 输出 -->
    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs font-medium text-gray-600 dark:text-gray-300">输出</span>
        {#if cryptoOutput && !cryptoOutput.startsWith('⚠️')}<button class="text-xs text-primary hover:underline" onclick={copyCryptoOutput}>复制</button>{/if}
      </div>
      <div class="input font-mono text-xs min-h-12 whitespace-pre-wrap break-all bg-gray-50 dark:bg-gray-900 py-2 px-3">
        {cryptoOutput || '<span class="text-gray-500 dark:text-gray-400">等待操作...</span>'}
      </div>
    </div>
   </div>
  {/if}
</div>
