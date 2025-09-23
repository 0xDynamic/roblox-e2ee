# Roblox ↔ Bun End-to-End Encryption (E2EE)

A secure End-to-End Encryption (E2EE) layer for sending requests between **Roblox executor clients (Luau)** and a **Bun + TypeScript + Elysia.js server**.

It uses modern cryptography primitives:
- 🔑 **X25519** for key exchange (ECDH)
- 🌐 **HKDF-SHA256** for key derivation
- 🔒 **XChaCha20-Poly1305** for authenticated encryption (AEAD)

---

## ✨ Features

- **Application-layer E2EE**: Payloads remain encrypted even if HTTPS/TLS is intercepted or replaced.
- **Replay protection**:
  - Server caches `{epk|nonce}` combinations.
  - Rejects duplicates and stale timestamps.
- **Route binding**:
  - Key derivation is bound to the request path (prevents ciphertext replay across endpoints).
- **Key rotation**:
  - Server rotates static keys periodically.
  - Clients fetch `GET /e2ee/keys` and use the latest `kid`.
- **Metadata reduction**:
  - Route name is **not** exposed in AAD (server derives it from path).
  - Only minimal metadata is visible (`kid`, `nonce`, `epk`).
- **Padding**:
  - Random padding added to plaintext to reduce size correlation.
- **Forward secrecy (configurable)**:
  - Client always uses ephemeral keys.
  - Server rotates static keys regularly (can be adjusted for stronger FS).

---

## 📂 Repository Structure

roblox-e2ee/
├── README.md
├── LICENSE
├── .gitignore
│
├── server/ # Bun + TypeScript (Elysia.js)
│ ├── package.json
│ ├── tsconfig.json
│ └── src/
│ ├── server.ts # Elysia server entry
│ ├── crypto.ts # X25519, HKDF, XChaCha20-Poly1305 wrappers
│ ├── keyManager.ts # Key rotation & management
│ ├── replayCache.ts # Replay protection
│ └── test_vectors.ts # Sanity test with RFC vectors
│
└── client/ # Roblox client (Executors / Luau modules)
├── README.md
├── init.lua # Public API: secure_post(path, body)
├── http.lua # HTTP adapter for executors
├── util.lua # JSON, Base64, nonce, padding
├── sha256.lua # SHA-256 + HMAC
├── hkdf.lua # HKDF-SHA256
├── chacha20.lua # ChaCha20 stream cipher
├── poly1305.lua # Poly1305 MAC
├── aead_xchacha.lua # AEAD wrapper
├── x25519_adapter.lua # Executor-native or Luau X25519
└── xchacha_impl.lua # (Optional) Pure-Luau XChaCha20-Poly1305

---

## 🚀 Getting Started

### 1. Server Setup (Bun + TypeScript)

#### Install dependencies
```bash
cd server
bun install
```

#### Run the server
```bash
bun run start
```

Endpoints:
- `GET /e2ee/keys`: List of public keys ({ kid, pk, createdAt }
- `POST /secure`: Accepts encrypted envelope, returns encrypted response

### 2. Client Setup (Roblox Executor / Luau Modules)
- Copy the client/ folder into your executor environment (or paste modules individually).
- Ensure your executor provides native crypto APIs for X25519 and XChaCha20-Poly1305, or plug in the provided pure-Luau modules.

#### Initialize the E2EE client
```lua
local e2ee = require("client.init")

-- Send a secure request
local resp = e2ee.secure_post("/secure", { user = "ExecutorUser", score = 1337 })

-- Pretty-print result
print(game:GetService("HttpService"):JSONEncode(resp))
```

### Envelope format
```json
{
  "v": 1,               // protocol version
  "kid": "abc123",      // key id (server public key used)
  "epk": "<b64>",       // client ephemeral public key
  "n": "<b64>",         // nonce (24B, XChaCha20)
  "aad": {              // additional authenticated data
    "v": 1,
    "ts": 1700000000    // unix timestamp
  },
  "ct": "<b64>",        // ciphertext
  "tag": "<b64>"        // Poly1305 tag
}
```
- Server validates: version, kid, replay-cache, timestamp skew
- Route binding: symmetric key derived with `HKDF(..., info="req|<path>")`

### Disclaimer: This is a proof-of-concept implementation. Do not use in production without proper security review.
