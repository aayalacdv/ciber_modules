/**
 * This module supports basic RSA operations for encrypting, decrypting, signing and verifying signatures
 * It also adds support for blind signing payloads and checking its validity
 * Another thing to remark is the secret sharing module that provides and implementation of threshold crypto based on bigint
 *
 * @remarks
 * This module runs perfectly in node.js and browsers
 *
 * @packageDocumentation
 */

export { generateRSAKeys, encryptPayload, decryptPayload } from './basic-RSA.js'
export { blindSignPayload, maskPayload, verifyBlindSign } from './blind-sign'
export { generateRandomPoli, computeShares, recoverSecret } from './secret-sharing'
