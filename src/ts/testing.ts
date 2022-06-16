import { blindSignPayload, verifyBlindSign, maskPayload } from './blind-sign'
import { decryptPayload, encryptPayload, generateRSAKeys } from './basic-RSA'

async function main () {
  // generate RSA Parameters for Alice
  const aliceKys = await generateRSAKeys()

//   // generate RSA Parameters for Bob
  const bobKeys = await generateRSAKeys()


  console.log(aliceKys)
  console.log(bobKeys)d

//   // //Alice sends an encrypted message to Bob
//   // const message = 'Hello bob this is Alice to encrypt';
//   // console.log(`This is the orginginal Message: ${message}`);
//   // const encrypted = encryptPayload(message, bobKeys.publicKey!.e, bobKeys.publicKey!.n);

//   // console.log(`This is the encrypted message: ${encrypted}`)
//   // //miramos que el mensaje se puede desencriptar con el mensaje de bob
//   // const decrypted = decryptPayload(encrypted, bobKeys.privateKey!.d, bobKeys.publicKey!.n);
//   // if(message === decrypted){
//   //     console.log('RSA encryption successfull')
//   //     console.log(`This is the decripted message: ${decrypted}`)
//   // }

//   // //Alice sings a message to authenticate with Bob
//   // const message2 = 'Hello bob this is Alice to sign';
//   // console.log(`This is the orginginal Message: ${message2}`);
//   // const signed = encryptPayload(message2, aliceKys.privateKey!.d, aliceKys.publicKey!.n );
//   // //miramos que el mensaje se puede desencriptar con el mensaje de bob
//   // const decrypted2 = decryptPayload(signed, aliceKys.publicKey!.e, aliceKys.publicKey!.n);
//   // if(message2 === decrypted2){
//   //     console.log('RSA signing successfull')
//   //     console.log(`This is the decripted message: ${decrypted2}`)
//   // }

//   // now we make some adjustsments for blind sign the message
//   // necesitamos un coprimo de n el módulo público de la entidad  firma este es r
//   // el mensaje que se encripta es lo mismo pero m*r^emodn

//   const message = 'Hello this is a blind signing test'
//   console.log(`original message: ${message}`)
//   const masked = maskPayload(message, aliceKys.publicKey!.e, aliceKys.publicKey!.n, 3n)
//   console.log(`masked message: ${masked}`)

//   const signed = blindSignPayload(masked!, aliceKys.privateKey!.d, aliceKys.publicKey!.n)
//   console.log(`signed message: ${signed}`)

//   const isValidSignature = verifyBlindSign(message, signed, aliceKys.privateKey!.d, aliceKys.publicKey!.n, 3n)
//   console.log(`is a valid signature: ${isValidSignature}`)
}

main()
