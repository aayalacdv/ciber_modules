/**
 * Module to compute RSA keys, encrypt and decrypt payloads  
 * The default public modulous is the number 65537
 *
 * @remarks An example function that runs different code in Node and Browser javascript
 *
 * @param - The name to say hello to
 *
 * @returns Kpriv, Kpub to the user
 */


import * as bigintCryptoUtils from "bigint-crypto-utils";
import * as bigintConversion from "bigint-conversion";

export const PUBLIC_EXP: bigint = 65537n;

export const generateRSAPrivateParams = async (): Promise<{
    p: bigint;
    q: bigint;
    n: bigint;
    eul: bigint;
  }> => {
    const p = await bigintCryptoUtils.prime(2048);
    const q = await bigintCryptoUtils.prime(2048);
    const eul = await computeEurlersTotient(p, q);
    const n = p * q;
  
    return { p: p, q: q, n: n, eul: eul };
  };
  
  const computeEurlersTotient = async (p: bigint, q: bigint): Promise<bigint> => {
    return (p - 1n) * (q - 1n);
  };
  
 const computeRSAPublicKey = async (
    eul: bigint,
    n: bigint
  ): Promise<{ e: bigint; n: bigint } | undefined> => {
    const { g } = bigintCryptoUtils.eGcd(PUBLIC_EXP, eul);
    if (g !== 1n) return undefined;
    return { e: PUBLIC_EXP, n: n };
  };
  
const computeRSAPrivateKey = async (
    eul: bigint,
    n: bigint
  ): Promise<{ d: bigint; n: bigint } | undefined> => {
    try {
      const d = await bigintCryptoUtils.modPow(PUBLIC_EXP, -1, eul);
      return { d: d, n: n };
    } catch (e) {
      return undefined;
    }
  };

  export const encryptPayload = (
    message: string,
    publicExp: bigint,
    n: bigint
  ): bigint => {
    const convertedMessage = bigintConversion.textToBigint(message);
    const encrypted = bigintCryptoUtils.modPow(
      convertedMessage,
      publicExp,
      n
    );
    return encrypted;
  };
  
  export const decryptPayload = (payload : bigint, d : bigint, n: bigint): string => {
      const decrypted = bigintCryptoUtils.modPow(payload, d, n)
      return bigintConversion.bigintToText(decrypted);
  
  }
  