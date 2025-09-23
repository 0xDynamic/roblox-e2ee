# Roblox ↔️ Bun E2EE

End-to-End Encryption (E2EE) layer for requests between a Roblox executor (Client) and Bun + TypeScript + Elysia.js (Server)

- 📡 **Crypto**: X25519 (ECDH) + HKDF-SHA256 → XChaCha20-Poly1305 (AEAD)
- 🔒 **Security**:
  - Replay protection (nonce + epk cache, timestamp check)
  - Key rotation (server exposes multiple `kid` public keys)
  - Padding to hide payload sizes
  - Non-exposure route/metadata inside AAD
- 🛠 **Client**: Luau modules (For executors or pure Luau)
- 🛠 **Server**: Bun + Elysia.js, Noble crypto libs

## 📂 Repo structure

- `server/` → Bun + TypeScript server
- `client/` → Roblox executor / Luau modules

## 🚀 Quickstart

### Server
```bash
cd server
bun install
bun run src/server.ts
