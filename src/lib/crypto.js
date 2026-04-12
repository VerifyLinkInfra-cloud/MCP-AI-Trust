/**
 * VLI AI Trust Protocol — Cryptographic Primitives
 *
 * Ed25519 signing, SHA-256 hashing, deterministic canonicalization.
 * Zero external dependencies — uses Node.js built-in crypto.
 */
import { createHash, generateKeyPairSync, sign, verify, randomBytes } from "crypto";

/**
 * Generate an Ed25519 keypair.
 * @returns {{ publicKey: string, privateKey: string }} hex-encoded keys
 */
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return {
    publicKey: publicKey.toString("hex"),
    privateKey: privateKey.toString("hex"),
  };
}

/**
 * SHA-256 hash of a string.
 * @param {string} data
 * @returns {string} hex digest
 */
export function sha256(data) {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Canonicalize an object (RFC 8785 JCS-like: sorted keys, deterministic JSON).
 * @param {object} obj
 * @returns {string}
 */
export function canonicalize(obj) {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(val) {
  if (val === null || typeof val !== "object") return val;
  if (Array.isArray(val)) return val.map(sortKeys);
  return Object.keys(val).sort().reduce((acc, key) => {
    acc[key] = sortKeys(val[key]);
    return acc;
  }, {});
}

/**
 * Sign data with an Ed25519 private key.
 * @param {string} data — the data to sign
 * @param {string} privateKeyHex — hex-encoded PKCS8 DER private key
 * @returns {string} hex-encoded signature
 */
export function signData(data, privateKeyHex) {
  const keyObj = {
    key: Buffer.from(privateKeyHex, "hex"),
    format: "der",
    type: "pkcs8",
  };
  return sign(null, Buffer.from(data, "utf8"), keyObj).toString("hex");
}

/**
 * Verify an Ed25519 signature.
 * @param {string} data
 * @param {string} signatureHex
 * @param {string} publicKeyHex — hex-encoded SPKI DER public key
 * @returns {boolean}
 */
export function verifySignature(data, signatureHex, publicKeyHex) {
  try {
    const keyObj = {
      key: Buffer.from(publicKeyHex, "hex"),
      format: "der",
      type: "spki",
    };
    return verify(null, Buffer.from(data, "utf8"), keyObj, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/**
 * Generate a random ID with prefix.
 * @param {string} prefix
 * @returns {string}
 */
export function randomId(prefix = "evt") {
  return prefix + "-" + randomBytes(12).toString("hex");
}

/**
 * Build a Merkle root from an array of hex hash strings.
 * @param {string[]} leaves
 * @returns {string} hex root hash
 */
export function buildMerkleRoot(leaves) {
  if (leaves.length === 0) return sha256("empty");
  if (leaves.length === 1) return leaves[0];

  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256(left + right));
    }
    level = next;
  }
  return level[0];
}
