// https://github.dev/oxen-io/session-desktop/blob/afb9a46d48bd797333964b6a25d33535c0d9e618/ts/util/accountManager.ts#L34

import libSodiumWrappers, { KeyPair } from "libsodium-wrappers-sumo";
import { mn_decode, mn_encode } from "./mnemonic";

await libSodiumWrappers.ready;

const sodium = libSodiumWrappers;

/**
 * @param size must be divisible by 8
 */
async function generateSeed(size = 16) {
  // Note: 4 bytes are converted into 3 seed words, so length 12 seed words
  // (13 - 1 checksum) are generated using 12 * 4 / 3 = 16 bytes.
  //   const seedSize = 32;
  if (size % 4) throw "Seed size must be divisible by 4";
  const seed = sodium.randombytes_buf(size);

  return seed;
}

function deriveMnemonic(seed: Uint8Array) {
  return mn_encode(Buffer.from(seed).toString("hex"));
}

function deriveSeed(mnemonic: string) {
  return new Uint8Array(Buffer.from(mn_decode(mnemonic), "hex"));
}

async function generateKeyPair(seed: Uint8Array) {
  let extendedSeed = new Uint8Array(32);
  extendedSeed.set(seed);

  const ed25519KeyPair = sodium.crypto_sign_seed_keypair(new Uint8Array(extendedSeed));

  const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519KeyPair.publicKey);

  const x25519SecretKey = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519KeyPair.privateKey);

  // session address consists of a `05` prefix byte and a public key
  return {
    pub: x25519PublicKey,
    sec: x25519SecretKey,
  };
}

let prefixHex = process.argv[2] || "55";
let prefixByte = Buffer.from(prefixHex, "hex").readUint8();
let prefixLength = 1;

let mnemonicLength = parseFloat(process.argv[3]);
mnemonicLength = isNaN(mnemonicLength) ? 16 : mnemonicLength;

console.log(`Starting a search for addresses that start with "${prefixHex}" byte`);
console.log("Seed size is set to", mnemonicLength);

while (true) {
  let seed = await generateSeed(mnemonicLength);
  let { pub } = await generateKeyPair(seed);

  let p = 0;
  for (; p < prefixLength; p += 1) {
    if (pub[p] !== prefixByte) {
      break;
    }
  }

  if (p === prefixLength) {
    console.log("Length", prefixLength);
    console.log("05" + Buffer.from(pub).toString("hex"));
    console.log(deriveMnemonic(seed));

    prefixLength += 1;
  }
}
