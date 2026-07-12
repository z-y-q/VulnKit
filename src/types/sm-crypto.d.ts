declare module 'sm-crypto' {
  export interface Sm2CipherOptions {
    /** cipher mode: 0=C1C3C2, 1=C1C2C3 */
    cipherMode?: 0 | 1;
  }
  export const sm2: {
    doEncrypt(data: number[] | Uint8Array, publicKey: string, cipherMode?: number): string;
    doDecrypt(data: string, privateKey: string, cipherMode?: number, options?: { output?: 'array' | 'string' }): any;
    doSignature(data: string | number[], privateKey: string, options?: any): string;
    doVerifySignature(data: string | number[], signHex: string, publicKey: string, options?: any): boolean;
    generateKeyPairHex(): { privateKey: string; publicKey: string };
  };
  export const sm3: {
    (data: string | number[] | Uint8Array): string;
  };
  export const sm4: {
    encrypt(data: string, key: string, options?: { mode?: string; iv?: string; padding?: string }): string;
    decrypt(data: string, key: string, options?: { mode?: string; iv?: string; padding?: string }): string;
  };
}
