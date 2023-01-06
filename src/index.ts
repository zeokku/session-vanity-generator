// https://github.dev/oxen-io/session-desktop/blob/afb9a46d48bd797333964b6a25d33535c0d9e618/ts/util/accountManager.ts#L34

import libSodiumWrappers from "libsodium-wrappers-sumo";
import { mn_decode, mn_encode } from "./mnemonic";

await libSodiumWrappers.ready;

const sodium = libSodiumWrappers;

async function generateSeed(size = 16) {
  // Note: 4 bytes are converted into 3 seed words, so length 12 seed words
  // (13 - 1 checksum) are generated using 12 * 4 / 3 = 16 bytes.
  //   const seedSize = 16;
  const seed = sodium.randombytes_buf(size);

  return seed;
}

function deriveMnemonic(seed: Uint8Array) {
  return mn_encode(Buffer.from(seed).toString("hex"));
}

function deriveSeed(mnemonic: string) {
  return new Uint8Array(Buffer.from(mn_decode(mnemonic), "hex"));
}

// move outside function so we don't allocate buffer each time
let extendedSeed = new Uint8Array(32);
async function derivePublicKey(seed: Uint8Array) {
  extendedSeed.set(seed);

  const ed25519KeyPair = sodium.crypto_sign_seed_keypair(extendedSeed);

  const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519KeyPair.publicKey);

  return x25519PublicKey;
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

let vanityPrefix = process.argv[2] || "1234";
let seedLength = parseFloat(process.argv[3]);
seedLength = isNaN(seedLength) ? 16 : seedLength;

if (seedLength % 4) throw "Seed size must be divisible by 4";

console.log("Seed size set to", seedLength);
console.log(`Starting a search for addresses that start with '${vanityPrefix}'...`);

let newHexPubKey = '';
let seed;

while (newHexPubKey.substring(0, vanityPrefix.length) !== vanityPrefix) {
  seed = await generateSeed(seedLength);
  let pub = await derivePublicKey(seed);
  newHexPubKey = Buffer.from(pub).toString("hex");
}

let mnemonic = await deriveMnemonic(seed);
console.log("Session id: 05" + newHexPubKey);
console.log("Recovery phrase: " + mnemonic);
