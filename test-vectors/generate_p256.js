let elliptic = require("elliptic");
let sha3 = require("js-sha3");
let ec = new elliptic.ec("p256");
let BN = require("bn.js");

// let keyPair = ec.genKeyPair();
let keyPair = ec.keyFromPrivate(
  "97ddae0f3a25b92268175400149d75d6887b9cefaf28ea2c078e05cdc15a3c0a"
);
let privKey = keyPair.getPrivate("hex");
let pubKey = keyPair.getPublic();
console.log(`Private key: ${privKey}`);
console.log("Public key :", pubKey.encode("hex").substr(2));
console.log(`Public key (X): ${pubKey.getX()}`);
console.log(`Public key (Y): ${pubKey.getY()}`);
console.log("Public key (compressed):", pubKey.encodeCompressed("hex"));

console.log();

// must remove 0x prefix first
// let msgHash =
//   "7e3c112faca3d4b2835b41ca65d13929b66abb2a084eb09e8e6cb702d207c867";
let msgHash =
  "6c60199eb5930834eb3b627742170983b150bde46bca7957d1dd0f767fe3acbb";
let signature = ec.sign(msgHash, privKey, "hex", { canonical: true });
console.log(`Msg hash: ${msgHash}`);
// console.log("Signature:", signature);
console.log(`Signature (r): ${signature.r}`);
console.log(`Signature (s): ${signature.s}`);
const P256_N_DIV_2 = new BN(
  "57896044605178124381348723474703786764998477612067880171211129530534256022184",
  10
);
if (signature.s.gt(P256_N_DIV_2)) {
  throw `malleability check fail`;
}

let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
let pubKeyRecovered = ec.recoverPubKey(
  hexToDecimal(msgHash),
  signature,
  signature.recoveryParam,
  "hex"
);
console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));

let validSig = ec.verify(msgHash, signature, pubKeyRecovered);
if (!validSig) {
  throw "Signature valid?";
}