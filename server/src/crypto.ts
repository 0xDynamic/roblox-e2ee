import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "crypto";

export const VERSION = 1;
export const SALT = new TextEncoder().encode("v1|roblox-e2ee");
export const KEY_LEN = 32;

export const b64e = (u8: Uint8Array) => Buffer.from(u8).toString("base64");
export const b64d = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
export const now = () => Math.floor(Date.now() / 1000);

export function genKeypair() {
    const sk = x25519.utils.randomSecretKey();
    const pk = x25519.getPublicKey(sk);
    return {
        sk,
        pk,
    };
}

// ecdh shared secret
export function ecdh(sk: Uint8Array, peerPk: Uint8Array) {
    // return 32 bytes
    return x25519.getSharedSecret(sk, peerPk);
}

// derive symmetric key via HKDF-SHA256
export function deriveKey(ss: Uint8Array, info: string) {
    return hkdf(sha256, ss, SALT, new TextEncoder().encode(info), KEY_LEN);
}

export type AAD = Record<string, unknown>;

export type AeadEncryptResult = {
    ct: Uint8Array;
    tag: Uint8Array;
};

// XChaCha20-Poly1305 AEAD (noble)
export function aeadEncrypt(
    key: Uint8Array,
    nonce24: Uint8Array,
    plaintext: Uint8Array,
    aad: AAD,
): AeadEncryptResult {
    const a = new TextEncoder().encode(JSON.stringify(aad ?? {}));
    const cipher = xchacha20poly1305(key, nonce24, a);
    const sealed = cipher.encrypt(plaintext);
    const tag = sealed.subarray(sealed.length - 16);
    const ct = sealed.subarray(0, sealed.length - 16);
    return {
        ct,
        tag,
    };
}

export function aeadDecrypt(
    key: Uint8Array,
    nonce24: Uint8Array,
    ct: Uint8Array,
    tag: Uint8Array,
    aad: AAD,
): Uint8Array {
    const a = new TextEncoder().encode(JSON.stringify(aad ?? {}));
    const cipher = xchacha20poly1305(key, nonce24, a);
    const sealed = new Uint8Array(ct.length + 16);
    sealed.set(ct, 0);
    sealed.set(tag, ct.length);
    const opened = cipher.decrypt(sealed);
    if (!opened) throw new Error("AEAD auth failed");
    return opened;
}

export const randomNonce24 = () => randomBytes(24);
export const randomBytes32 = () => randomBytes(32);
