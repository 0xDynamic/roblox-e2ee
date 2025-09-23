import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hex } from "@scure/base";

const key = new Uint8Array(32);
const nonce = new Uint8Array(24);
const pt = new Uint8Array([...Array(64).keys()]);

const cipher = xchacha20poly1305(key, nonce);
const sealed = cipher.encrypt(pt);
const tag = sealed.subarray(sealed.length - 16);
const ct = sealed.subarray(0, sealed.length - 16);

console.log("CT (first 16B):", hex.encode(ct.subarray(0, 16)));
console.log("TAG:", hex.encode(tag));

const opened = cipher.decrypt(sealed);
console.log("OPEN OK:", !!opened && opened.length === pt.length);
