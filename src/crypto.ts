import { sha256 as SHA256 } from "@noble/hashes/sha2";
import * as aes from "@noble/ciphers/aes";
import { hmac } from "@noble/hashes/hmac";
import { assertBuffer, isEqualBytes } from "./utils";

function encrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);
  const cipher = aes.cbc(key, iv);

  return cipher.encrypt(data);
}

function decrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);

  const cipher = aes.cbc(key, iv);
  return cipher.decrypt(data);
}

function calculateMAC(key: Uint8Array, data: Uint8Array): Uint8Array {
  assertBuffer(key);
  assertBuffer(data);

  return hmac(SHA256, key, data);
}

function hash(data: Uint8Array): Uint8Array {
  assertBuffer(data);

  return SHA256(data);
}

// Salts always end up being 32 bytes
function deriveSecrets(
  input: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  chunks: number = 3
): Uint8Array[] {
  // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
  assertBuffer(input);
  assertBuffer(salt);
  assertBuffer(info);
  if (salt.byteLength != 32) {
    throw new Error("Got salt of incorrect length");
  }

  if (!(chunks >= 1 && chunks <= 3)) {
    throw new Error("Invalid number of chunks");
  }

  const PRK = calculateMAC(salt, input);
  const infoArray = new Uint8Array(info.byteLength + 1 + 32);
  infoArray.set(new Uint8Array(info), 32);
  infoArray[infoArray.length - 1] = 1;
  const signed: Uint8Array[] = [calculateMAC(PRK, infoArray.slice(32))];
  if (chunks > 1) {
    infoArray.set(new Uint8Array(signed[signed.length - 1]));
    infoArray[infoArray.length - 1] = 2;
    signed.push(calculateMAC(PRK, infoArray));
  }
  if (chunks > 2) {
    infoArray.set(new Uint8Array(signed[signed.length - 1]));
    infoArray[infoArray.length - 1] = 3;
    signed.push(calculateMAC(PRK, infoArray));
  }
  return signed;
}

function verifyMAC(
  data: Uint8Array,
  key: Uint8Array,
  mac: Uint8Array,
  length: number
): void {
  const calculatedMac = calculateMAC(key, data).slice(0, length);
  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error("Bad MAC length");
  }

  if (!isEqualBytes(mac, calculatedMac)) {
    throw new Error("Bad MAC");
  }
}

export function randomBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

export { deriveSecrets, decrypt, encrypt, hash, calculateMAC, verifyMAC };
