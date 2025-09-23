import { genKeypair, b64e } from "./crypto";

type KeyEntry = {
    kid: string;
    sk: Uint8Array;
    pk: Uint8Array;
    createdAt: number;
};

const KEYS: KeyEntry[] = [];
const ROTATE_INTERVAL = 24 * 3600;
const TTL_KEEP_OLD = 7 * 24 * 3600;

function init() {
    rotate();
    setInterval(() => rotate(), ROTATE_INTERVAL).unref?.();
}

function rotate() {
    const { sk, pk } = genKeypair();
    const kid = b64e(pk).slice(0, 12);
    KEYS.unshift({ kid, sk, pk, createdAt: Math.floor(Date.now() / 1000) });
    const now = Math.floor(Date.now() / 1000);
    while (KEYS.length > 1) {
        const lastKey = KEYS[KEYS.length - 1];
        if (!lastKey || now - lastKey.createdAt <= TTL_KEEP_OLD) {
            break;
        }
        KEYS.pop();
    }
}

function getPublicKeys() {
    return KEYS.map((k) => ({
        kid: k.kid,
        pk: b64e(k.pk),
        createdAt: k.createdAt,
    }));
}

function findSkByKid(kid: string) {
    for (const k of KEYS) if (k.kid === kid) return k.sk;
    return null;
}

init();

export { getPublicKeys, findSkByKid };
