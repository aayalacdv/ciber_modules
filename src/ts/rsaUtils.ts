import * as bigintCryptoUtils from "bigint-crypto-utils";
import * as bigintConversion from "bigint-conversion";

const publicExp: bigint = 65537n;

const generateRSAPrivateParams = async (): Promise<{
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
  const { g } = bigintCryptoUtils.eGcd(publicExp, eul);
  if (g !== 1n) return undefined;
  return { e: publicExp, n: n };
};

const computeRSAPrivateKey = async (
  eul: bigint,
  n: bigint
): Promise<{ d: bigint; n: bigint } | undefined> => {
  try {
    const d = await bigintCryptoUtils.modPow(publicExp, -1, eul);
    return { d: d, n: n };
  } catch (e) {
    return undefined;
  }
};

const encryptPayload = (
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

const decryptPayload = (payload : bigint, d : bigint, n: bigint): string => {
    const decrypted = bigintCryptoUtils.modPow(payload, d, n)
    return bigintConversion.bigintToText(decrypted);

}

const maskPayload = (payload: string, e : bigint, n: bigint, r : bigint) : bigint | undefined => {
    const converted = bigintConversion.textToBigint(payload); 

    const { g } = bigintCryptoUtils.eGcd(r, n);
    if(g !== 1n) return undefined; 

    const encrypted = bigintCryptoUtils.modPow(converted*(r**e), 1n, n);

    return encrypted;
}


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
    const x = decryptPayload(originalMessage, publicExp, n);
    console.log(x);
    if(originalMessage !== decrtypted) return false;
    return true;

} 


async function main() {
  //generate RSA Parameters for Alice
  const AlicePrivParams = await generateRSAPrivateParams(); 
  const AliceKpub = await computeRSAPublicKey(AlicePrivParams.eul, AlicePrivParams.n);
  const AliceKpriv = await computeRSAPrivateKey(AlicePrivParams.eul, AlicePrivParams.n);

//   //generate RSA Parameters for Bob 
//   const BobPrivParams = await generateRSAPrivateParams(); 
//   const BobKpub = await computeRSAPublicKey(BobPrivParams.eul, BobPrivParams.n);
//   const BobKpriv= await computeRSAPrivateKey(BobPrivParams.eul, BobPrivParams.n);


//   //Alice sends an encrypted message to Bob
//   const message = 'Hello bob this is Alice to encrypt'; 
//   console.log(`This is the orginginal Message: ${message}`);
//   const encrypted = encryptPayload(message, BobKpub!.e, BobPrivParams.n );
//   console.log(`This is the encrypted message: ${encrypted}`)
//   //miramos que el mensaje se puede desencriptar con el mensaje de bob
//   const decrypted = decryptPayload(encrypted, BobKpriv!.d, BobPrivParams.n);
//   if(message === decrypted){
//       console.log('RSA encryption successfull')
//       console.log(`This is the decripted message: ${decrypted}`)
//   }

//   //Alice sings a message to authenticate with Bob
//   const message2 = 'Hello bob this is Alice to sign'; 
//   console.log(`This is the orginginal Message: ${message2}`);
//   const signed = encryptPayload(message2, AliceKpriv!.d, AlicePrivParams.n );
//   //miramos que el mensaje se puede desencriptar con el mensaje de bob
//   const decrypted2 = decryptPayload(signed, AliceKpub!.e, AlicePrivParams.n);
//   if(message2 === decrypted2){
//       console.log('RSA signing successfull')
//       console.log(`This is the decripted message: ${decrypted}`)
//   }


  //now we make some adjustsments for blind sign the message
  //necesitamos un comprimo de n el módulo público de la entidad  firma este es r
  // el mensaje que se encripta es lo mismo pero m*r^emodn 

  const message = 'Hello this is a blind signing test'; 
  console.log(`original message: ${message}`)
  const masked = maskPayload(message, AliceKpub!.e, AlicePrivParams.n, 3n); 
  console.log(`masked message: ${masked}`)

  const signed = blindSignPayload(masked!, AliceKpriv!.d, AlicePrivParams.n);
  console.log(`signed message: ${signed}`)
  

  const isValidSignature = verifyBlindSign(message, signed, AliceKpriv!.d, AlicePrivParams.n, 3n);
  console.log(`is a valid signature: ${isValidSignature}`)

}

main();
