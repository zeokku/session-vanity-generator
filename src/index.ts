// https://github.dev/oxen-io/session-desktop/blob/afb9a46d48bd797333964b6a25d33535c0d9e618/ts/util/accountManager.ts#L34

import libSodiumWrappers, { KeyPair } from "libsodium-wrappers-sumo";
import { mn_decode, mn_encode } from "./mnemonic";

async function getSodiumRenderer(): Promise<typeof libSodiumWrappers> {
  await libSodiumWrappers.ready;
  return libSodiumWrappers;
}

export type SessionKeyPair = {
  /**
   * The curve25519 pubkey with prepended 5
   */
  pubKey: ArrayBufferLike;

  /**
   * The curve25519 secret key
   */
  privKey: ArrayBufferLike;

  ed25519KeyPair: KeyPair;
};

async function sessionGenerateKeyPair(seed: ArrayBuffer): Promise<SessionKeyPair> {
  const sodium = await getSodiumRenderer();

  const ed25519KeyPair = sodium.crypto_sign_seed_keypair(new Uint8Array(seed));
  const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519KeyPair.publicKey);
  // prepend version byte (coming from `processKeys(raw_keys)`)
  const origPub = new Uint8Array(x25519PublicKey);
  const prependedX25519PublicKey = new Uint8Array(33);
  prependedX25519PublicKey.set(origPub, 1);
  prependedX25519PublicKey[0] = 5;
  const x25519SecretKey = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519KeyPair.privateKey);

  // prepend with 05 the public key
  const x25519KeyPair = {
    pubKey: prependedX25519PublicKey.buffer,
    privKey: x25519SecretKey.buffer,
    ed25519KeyPair,
  };

  return x25519KeyPair;
}

async function generateMnemonic(seedSize = 16) {
  // Note: 4 bytes are converted into 3 seed words, so length 12 seed words
  // (13 - 1 checksum) are generated using 12 * 4 / 3 = 16 bytes.
  //   const seedSize = 32;
  if (seedSize % 8) throw "Seed size must be divisible by 8";

  const seed = (await getSodiumRenderer()).randombytes_buf(seedSize);
  const hex = Buffer.from(seed).toString("hex"); // toHex(seed);
  return mn_encode(hex);
}

const generateMnemonicAndKeyPair = async (mnemonic: string) => {
  // if (generatedRecoveryPhrase === '') {

  let seedHex = mn_decode(mnemonic);
  // handle shorter than 32 bytes seeds
  const privKeyHexLength = 32 * 2;
  if (seedHex.length !== privKeyHexLength) {
    seedHex = seedHex.concat("0".repeat(32));
    seedHex = seedHex.substring(0, privKeyHexLength);
  }
  const seed = Buffer.from(seedHex, "hex"); //fromHex(seedHex);
  const keyPair = await sessionGenerateKeyPair(seed);
  const newHexPubKey = Buffer.from(keyPair.pubKey).toString("hex"); //StringUtils.decode(keyPair.pubKey, "hex");

  //   setGeneratedRecoveryPhrase(mnemonic);
  //   setHexGeneratedPubKey(newHexPubKey); // our 'frontend' sessionID
  // }

  return newHexPubKey;
};

let mnemonic = await generateMnemonic();
let pubAddress = await generateMnemonicAndKeyPair(mnemonic);

console.clear();
console.log(mnemonic, mnemonic.split(/\s/g).length);
console.log(pubAddress);
