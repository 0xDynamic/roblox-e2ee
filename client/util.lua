local HttpService = game:GetService("HttpService")
local _ctr = 0
local _session_salt = HttpService:GenerateGUID(false) .. HttpService:GenerateGUID(false)

local function now() return os.time() end

local function b64e(b) return HttpService:Base64Encode(b) end
local function b64d(s) return HttpService:Base64Decode(s) end
local function jenc(t) return HttpService:JSONEncode(t) end
local function jdec(s) return HttpService:JSONDecode(s) end

local function nonce24() -- 8 bytes counter + 16 bytes session salt (=> 24 bytes)
  _ctr += 1
  local packed = string.pack(">I8", _ctr)
  local remain = 24 - 8
  packed ..= string.sub(_session_salt, 1, remain)
  return packed
end

local function padPlaintext(ptStr, minPad, maxPad)
    minPad = minPad or 0; maxPad = maxPad or 128
    local toAdd = math.random(minPad, maxPad)
    local pad = ""
    for i = 1,toAdd do pad ..= string.char(math.random(0,255)) end
    return ptStr, toAdd
end

return {
    now = now,
    b64e = b64e,
    b64d = b64d,
    jenc = jenc,
    jdec = jdec,
    nonce24 = nonce24,
    padPlaintext = padPlaintext
}