import { Elysia, t, type Static } from "elysia";
import { cors } from "@elysiajs/cors";
import { getPublicKeys, findSkByKid } from "./keyManager";
import {
    b64d,
    b64e,
    deriveKey,
    ecdh,
    aeadDecrypt,
    aeadEncrypt,
    now,
    randomNonce24,
} from "./crypto";
import { ReplayCache } from "./replayCache";

const app = new Elysia().use(cors());

const AAD = t.Object(
    {
        v: t.Number(),
        ts: t.Number(),
        res: t.Optional(t.Boolean()),
    },
    {
        additionalProperties: true,
    },
);

const EnvelopeSchema = t.Object({
    v: t.Literal(1),
    kid: t.String(),
    epk: t.String(),
    n: t.String(),
    aad: AAD,
    ct: t.String(),
    tag: t.String(),
});

type Envelope = Static<typeof EnvelopeSchema>;

const replay = new ReplayCache(120);

app.get("/e2ee/keys", () => ({
    v: 1,
    keys: getPublicKeys(),
}));

app.post(
    "/secure",
    async ({ body, request, set }) => {
        const { v, kid, epk, n, aad, ct, tag } = body as Envelope;

        const mark = `${epk}|${n}`;
        if (!replay.check(mark)) {
            set.status = 400;
            return { error: "replay detected" };
        }

        if (!Number.isFinite(aad.ts) || Math.abs(now() - Number(aad.ts)) > 60) {
            set.status = 400;
            return { error: "timestamp skew" };
        }

        // lấy server SK theo kid
        const sk = findSkByKid(kid);
        if (!sk) {
            set.status = 400;
            return { error: "unknown kid" };
        }

        const epkU8 = b64d(epk);
        const nonce = b64d(n);
        const ctU8 = b64d(ct);
        const tagU8 = b64d(tag);

        const ss = ecdh(sk, epkU8);
        const info = `req|${new URL(request.url).pathname}`;
        const key = deriveKey(ss, info);

        const pt = aeadDecrypt(key, nonce, ctU8, tagU8, aad);
        const req = JSON.parse(new TextDecoder().decode(pt));

        const result = { ok: true, echo: req, serverTime: now() };

        const respNonce = randomNonce24();
        const aadResp = { v: 1, res: true };
        const { ct: rct, tag: rtag } = aeadEncrypt(
            key,
            respNonce,
            new TextEncoder().encode(JSON.stringify(result)),
            aadResp,
        );

        return {
            v: 1,
            n: b64e(respNonce),
            aad: aadResp,
            ct: b64e(rct),
            tag: b64e(rtag),
        };
    },
    {
        body: EnvelopeSchema,
    },
);

app.listen(3000);
console.log("E2EE server on http://localhost:3000");
