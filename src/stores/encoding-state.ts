/**
 * §7.2 面板状态 store：encoding 面板
 * 防止面板切换时丢失昂贵的用户输入（RSA 密钥生成、长加密文本、JWT token）
 * 状态包括：3 个视图（经典编码/JWT/加密）+ 各视图的输入/输出/算法参数
 */
import { createStore } from '@/lib/core/storage-store';
import type { AesMode, AesPadding, HashAlgo } from '@/lib/crypto/crypto-engine';

type View = 'classic' | 'jwt' | 'crypto';
type EncType = 'base64' | 'url' | 'html' | 'hex';
type CryptoAlgo = 'aes' | 'des' | 'rc4' | 'sm2' | 'sm4' | 'rsa' | 'hash' | 'bcrypt';

interface EncodingState {
  // 经典编码
  view: View;
  activeTab: EncType;
  mode: 'encode' | 'decode';
  input: string;
  output: string;

  // JWT
  jwtInput: string;
  jwtKey: string;

  // 加密
  cryptoAlgo: CryptoAlgo;
  cryptoMode: 'encrypt' | 'decrypt';
  cryptoInput: string;
  cryptoOutput: string;

  // 算法参数
  pAes: { mode: AesMode; keySize: 128 | 192 | 256; padding: AesPadding; key: string; iv: string };
  pDes: { mode: 'CBC' | 'ECB'; padding: AesPadding; key: string; iv: string; triple: boolean };
  pRc4: { key: string };
  pSm2: { publicKey: string; privateKey: string; cipherMode: 0 | 1 };
  pSm4: { key: string; mode: 'ecb' | 'cbc'; iv: string; padding: boolean };
  pRsa: { publicKeyPem: string; privateKeyPem: string };
  pHash: { algo: HashAlgo; output: 'hex' | 'base64'; hmac: boolean; hmacKey: string };
  pBcrypt: { cost: number; hash: string };
}

const DEFAULT_STATE: EncodingState = {
  view: 'classic',
  activeTab: 'base64',
  mode: 'encode',
  input: '',
  output: '',

  jwtInput: '',
  jwtKey: '',

  cryptoAlgo: 'aes',
  cryptoMode: 'encrypt',
  cryptoInput: '',
  cryptoOutput: '',

  pAes: { mode: 'CBC', keySize: 128, padding: 'Pkcs7', key: '', iv: '' },
  pDes: { mode: 'CBC', padding: 'Pkcs7', key: '', iv: '', triple: false },
  pRc4: { key: '' },
  pSm2: { publicKey: '', privateKey: '', cipherMode: 1 },
  pSm4: { key: '', mode: 'ecb', iv: '', padding: true },
  pRsa: { publicKeyPem: '', privateKeyPem: '' },
  pHash: { algo: 'sha256', output: 'hex', hmac: false, hmacKey: '' },
  pBcrypt: { cost: 10, hash: '' },
};

export const encodingStateStore = createStore<EncodingState>('lingmou:encoding-state', DEFAULT_STATE);
