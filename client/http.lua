local http = rawget(getgenv() or _G, "http_request") or (syn and syn.request) or (http and http.request) or request
assert(http, "No http_request/syn.request/request exposed in executor")
return http