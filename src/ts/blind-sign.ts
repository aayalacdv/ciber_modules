import * as bigintCryptoUtils from "bigint-crypto-utils";
import * as bigintConversion from "bigint-conversion";
import { decryptPayload, encryptPayload } from "./basic-RSA";


export const PUBLIC_EXP: bigint = 65537n;

const blindSignPayload = (
    payload: bigint,
    d: bigint,
    n: bigint
  ): bigint => {
    const encrypted = bigintCryptoUtils.modPow(
      payload,
      d,
      n
    );
    return encrypted;
  };
  
  
  const verifyBlindSign = (original : string, signed : bigint, d: bigint, n: bigint, r: bigint) : boolean => {
      const inverse = bigintCryptoUtils.modInv(r, n);
      const decrtypted = bigintCryptoUtils.modPow(signed * inverse, 1n,n)
      const originalMessage = encryptPayload(original, d, n); 
      const x = decryptPayload(originalMessage, PUBLIC_EXP, n);
      console.log(x);
      if(originalMessage !== decrtypted) return false;
      return true;
  
  } 