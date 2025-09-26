local M = {}

local MOD = 2^32

local function rshift(x, n) return math.floor((x % MOD) / 2^n) end
local function rotr(x, n)
    -- ((x >> n) | (x << (32 - n))) & 0xffffffff
    local rn = bit32.rshift(x, n)
    local ln = bit32.lshift(x, 32 - n)
    return bit32.band(bit32.bor(rn, ln), 0xffffffff)
end

local function bxor(a, b) return bit32.bxor(a, b) end
local function band(a, b) return bit32.band(a, b) end
local function bor(a, b)  return bit32.bor(a, b) end
local function bnot(a)    return bit32.bnot(a) end

local K = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function to_bytes32(n)
    -- big-endian 4 bytes
    local b1 = bit32.band(bit32.rshift(n, 24), 0xff)
    local b2 = bit32.band(bit32.rshift(n, 16), 0xff)
    local b3 = bit32.band(bit32.rshift(n, 8),  0xff)
    local b4 = bit32.band(n, 0xff)
    return string.char(b1, b2, b3, b4)
end

local function from_bytes32(s, i)
    -- big-endian 4 bytes to u32
    local b1 = string.byte(s, i)
    local b2 = string.byte(s, i+1)
    local b3 = string.byte(s, i+2)
    local b4 = string.byte(s, i+3)
    return bit32.bor(
        bit32.lshift(b1, 24),
        bit32.lshift(b2, 16),
        bit32.lshift(b3, 8),
        b4
    )
end

-- encode 64-bit big-endian (hi:lo) without string.pack
local function to_bytes64_be_u53bits(total_bits)
    local hi = math.floor(total_bits / 2^32)
    local lo = total_bits - hi * 2^32
    return to_bytes32(hi) .. to_bytes32(lo)
end

function M.sha256(msg)
    local H = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    }

    local bitlen = #msg * 8
    -- padding
    msg = msg .. "\128"  -- 0x80
    local k = (56 - (#msg % 64)) % 64
    msg = msg .. string.rep("\0", k) .. to_bytes64_be_u53bits(bitlen)

    for i = 1, #msg, 64 do
        local w = {}
        for j = 0, 15 do
            w[j] = from_bytes32(msg, i + 4*j)
        end
        for j = 16, 63 do
            local wjm15 = w[j-15]
            local wjm2  = w[j-2]
            local s0 = bxor(rotr(wjm15,7), rotr(wjm15,18), rshift(wjm15,3))
            local s1 = bxor(rotr(wjm2,17),  rotr(wjm2,19),  rshift(wjm2,10))
            w[j] = ( (w[j-16] + s0 + w[j-7] + s1) % MOD )
        end

        local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
        for j = 0, 63 do
            local S1 = bxor(rotr(e,6), rotr(e,11), rotr(e,25))
            local ch = bxor(band(e,f), band(bnot(e), g))
            local t1 = ( (h + S1 + ch + K[j+1] + w[j]) % MOD )
            local S0 = bxor(rotr(a,2), rotr(a,13), rotr(a,22))
            local maj = bxor(band(a,b), band(a,c), band(b,c))
            local t2 = ( (S0 + maj) % MOD )
            h = g; g = f; f = e;
            e = (d + t1) % MOD
            d = c; c = b; b = a;
            a = (t1 + t2) % MOD
        end

        H[1] = (H[1] + a) % MOD
        H[2] = (H[2] + b) % MOD
        H[3] = (H[3] + c) % MOD
        H[4] = (H[4] + d) % MOD
        H[5] = (H[5] + e) % MOD
        H[6] = (H[6] + f) % MOD
        H[7] = (H[7] + g) % MOD
        H[8] = (H[8] + h) % MOD
    end

    return to_bytes32(H[1])..to_bytes32(H[2])..to_bytes32(H[3])..to_bytes32(H[4])..
           to_bytes32(H[5])..to_bytes32(H[6])..to_bytes32(H[7])..to_bytes32(H[8])
end

function M.hmac_sha256(key, msg)
    if #key > 64 then key = M.sha256(key) end
    if #key < 64 then key = key .. string.rep("\0", 64 - #key) end

    local okey, ikey = {}, {}
    for i = 1, 64 do
        local k = string.byte(key, i)
        okey[i] = string.char(bit32.bxor(k, 0x5c))
        ikey[i] = string.char(bit32.bxor(k, 0x36))
    end
    okey = table.concat(okey)
    ikey = table.concat(ikey)

    return M.sha256(okey .. M.sha256(ikey .. msg))
end

return M
