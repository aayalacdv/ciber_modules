import * as bigintCryptoUtils from 'bigint-crypto-utils'
import * as bigintConversion from 'bigint-conversion'

const PUBLIC_EXP: bigint = 65537n

const generateRSAPrivateParams = async (): Promise<{
  p: bigint
  q: bigint
  n: bigint
  eul: bigint
}> => {
  const p = await bigintCryptoUtils.prime(1024)
  const q = await bigintCryptoUtils.prime(1024)
  const eul = await computeEurlersTotient(p, q)
  const n = p * q

  return { p: p, q: q, n: n, eul: eul }
}

const computeEurlersTotient = async (p: bigint, q: bigint): Promise<bigint> => {
  return (p - 1n) * (q - 1n)
}

const computeRSAPublicKey = async (
  eul: bigint,
  n: bigint
): Promise<{ e: bigint, n: bigint } | undefined> => {
  const { g } = bigintCryptoUtils.eGcd(PUBLIC_EXP, eul)
  if (g !== 1n) return undefined
  return { e: PUBLIC_EXP, n: n }
}

const computeRSAPrivateKey = async (
  eul: bigint,
  n: bigint
): Promise<{ d: bigint, n: bigint } | undefined> => {
  try {
    const d = await bigintCryptoUtils.modPow(PUBLIC_EXP, -1, eul)
    return { d: d, n: n }
  } catch (e) {
    return undefined
  }
}

/**
 * Returns RSA keys computed with helper functions defined beforehand
 *
 * @remarks An example function that runs different code in Node and Browser javascript
 *
 * @returns  An object containind RSA keys
 */

export const generateRSAKeys = async () => {
  const privParams = await generateRSAPrivateParams()
  const Kpub = await computeRSAPublicKey(privParams.eul, privParams.n)
  const Kpriv = await computeRSAPrivateKey(privParams.eul, privParams.n)

  return { publicKey: Kpub, privateKey: Kpriv }
}

/**
 * Returns RSA encrypted payload, it most be a string object
 *
 * @remarks An example function that runs different code in Node and Browser javascript
 *
 * @param message - string to encrypt
 * @param publicExp- public exponent
 * @param n - Euler's totient
 *
 * @returns returns a bigInt with the encrypted message
 */

export const encryptPayload = (
  message: string,
  publicExp: bigint,
  n: bigint
): bigint => {
  const convertedMessage = bigintConversion.textToBigint(message)
  const encrypted = bigintCryptoUtils.modPow(
    convertedMessage,
    publicExp,
    n
  )
  return encrypted
}

/**
 * Returns RSA decrypted payload
 *
 * @remarks An example function that runs different code in Node and Browser javascript
 *
 * @param payload-  bigInt encrypted object
 * @param d - private exponent
 * @param n - Euler's totient
 *
 * @returns returns a string with the decrypted payload
 */

export const decryptPayload = (payload: bigint, d: bigint, n: bigint): string => {
  const decrypted = bigintCryptoUtils.modPow(payload, d, n)
  return bigintConversion.bigintToText(decrypted)
}
