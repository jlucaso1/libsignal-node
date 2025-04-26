import { assertBuffer, isEqualBytes } from "./utils";

// AES-CBC encryption using Web Crypto API
export async function encrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"]
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    data
  );

  return new Uint8Array(ciphertext);
}

// AES-CBC decryption using Web Crypto API
export async function decrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    data
  );

  return new Uint8Array(plaintext);
}

// HMAC-SHA256 using Web Crypto API
export async function calculateMAC(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  assertBuffer(key);
  assertBuffer(data);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );

  const mac = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(mac);
}

// SHA-256 hash using Web Crypto API
export async function hash(data: Uint8Array): Promise<Uint8Array> {
  assertBuffer(data);

  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

// Salts always end up being 32 bytes
// HKDF implementation using Web Crypto API
export async function deriveSecrets(
 input: Uint8Array,
 salt: Uint8Array,
 info: Uint8Array,
 chunks: number = 3
): Promise<Uint8Array[]> {
 // Returns the first 3 32-byte chunks (RFC 5869)
 assertBuffer(input);
 assertBuffer(salt);
 assertBuffer(info);
 if (salt.byteLength != 32) {
   throw new Error("Got salt of incorrect length");
 }
 if (!(chunks >= 1 && chunks <= 3)) {
   throw new Error("Invalid number of chunks");
 }

 // Import the input key material
 const importedKey = await crypto.subtle.importKey(
   "raw",
   input,
   { name: "HKDF" },
   false,
   ["deriveBits"]
 );

 // Derive 32 * chunks bytes
 const derivedBits = await crypto.subtle.deriveBits(
   {
     name: "HKDF",
     hash: "SHA-256",
     salt,
     info,
   },
   importedKey,
   32 * chunks * 8 // bits
 );

 // Split into 32-byte chunks
 const out = [];
 const arr = new Uint8Array(derivedBits);
 for (let i = 0; i < chunks; i++) {
   out.push(arr.slice(i * 32, (i + 1) * 32));
 }
 return out;
}

export async function verifyMAC(
  data: Uint8Array,
  key: Uint8Array,
  mac: Uint8Array,
  length: number
): Promise<void> {
  const calculatedMac = (await calculateMAC(key, data)).slice(0, length);
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