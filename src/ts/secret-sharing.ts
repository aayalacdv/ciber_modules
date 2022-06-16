import * as bigintCryptoUtils from "bigint-crypto-utils";
//will be generating random numbers from 1 to 20
const MIN_VALUE = 1
const MAX_VALUE = 21

const getRandomInt = () => {
    return Math.floor(Math.random() * (MAX_VALUE - MIN_VALUE)) + MIN_VALUE;
}


const computeLagrangeCoefficient = ( selection : number, indexes : number[]) => {

    const coefficients = indexes.filter((n) => n !== selection)
    
    let numerator : number = 1
    let denominator : number = 1 
    coefficients.forEach((c) => {
         numerator = numerator * c 
         denominator = denominator * (c - selection)
    })

    return { n : numerator, d: denominator} 

}

const S = 11
const p = 17


const minimimumShares = 3
const shareDivisions = 5




const generateRandomPoli = (minimumShares: number, S : number) => {

    let coefficients = []

    for(let i = 1; i < minimimumShares; i = i + 1){
        const randInt = getRandomInt()
        coefficients.push(randInt)
    }


    return [S, ...coefficients] 

}


const computeShares = ( coefficients : number [], shareDivisions: number, p: number) => {


    let shares = []

    for(let i = 1; i <= shareDivisions; i = i + 1){
        let sum = 0
        coefficients.forEach((c : number, index) => {
            sum = sum + c*Math.pow(i,index)
        })

        //compute the modulus and then add it to the array 
        const mod = bigintCryptoUtils.modPow(sum, 1, p)

        shares.push(mod)
    }

    return shares
}


const recoverSecret = (shares : bigint[], indexes: number[], p : number) => {
    
    let coeff : any = []

    indexes.forEach((i) => {
        const index = computeLagrangeCoefficient(i, indexes)
        coeff.push(index)
    })



    let top : bigint= 0n
    let bottom : bigint = 1n

    //compute denominator 
    indexes.forEach((index , i) => {
        bottom = bottom * BigInt(coeff[i].d)
    })

    //compute numerator 
    indexes.forEach((index , i) => {
        top = top +  (bottom * BigInt(coeff[i].n)/BigInt(coeff[i].d)) * shares[index - 1] 
    })


    const inverse = bigintCryptoUtils.modInv(bottom, p);
    const secret = bigintCryptoUtils.modPow(top* inverse, 1n,p)

    return secret


}


const poli = generateRandomPoli(minimimumShares, S)

const shares = computeShares(poli, shareDivisions, p)

console.log(shares)

const selected = [1, 3, 5]


const secret = recoverSecret(shares, selected, p)
console.log(secret)
