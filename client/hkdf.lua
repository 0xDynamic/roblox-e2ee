local sha = require(script.Parent.sha256)

local M = {}
function M.hkdf(ikm, salt, info, len)
    local prk = sha.hmac_sha256(salt, ikm)
    local t, okm, i = "", "", 1
    while #okm < len do
        t = sha.hmac_sha256(prk, t .. info .. string.char(i))
        okm ..= t
        i += 1
    end
    return string.sub(okm, 1, len)
end
return M
