import * as bigintCryptoUtils from 'bigint-crypto-utils'
import { decryptPayload, encryptPayload } from './basic-RSA'
import * as bigintConversion from 'bigint-conversion'

export const PUBLIC_EXP: bigint = 65537n

export const maskPayload = (payload: string, e: bigint, n: bigint, r: bigint): bigint | undefined => {
  const converted = bigintConversion.textToBigint(payload)

  const { g } = bigintCryptoUtils.eGcd(r, n)
  if (g !== 1n) return undefined

  const encrypted = bigintCryptoUtils.modPow(converted * (r ** e), 1n, n)

  return encrypted
}

export const blindSignPayload = (
  payload: bigint,
  d: bigint,
  n: bigint
): bigint => {
  const encrypted = bigintCryptoUtils.modPow(
    payload,
    d,
    n
  )
  return encrypted
}

export const verifyBlindSign = (original: string, signed: bigint, d: bigint, n: bigint, r: bigint): boolean => {
  const inverse = bigintCryptoUtils.modInv(r, n)
  const decrtypted = bigintCryptoUtils.modPow(signed * inverse, 1n, n)
  const originalMessage = encryptPayload(original, d, n)
  const x = decryptPayload(originalMessage, PUBLIC_EXP, n)
  if (originalMessage !== decrtypted) return false
  return true
}
