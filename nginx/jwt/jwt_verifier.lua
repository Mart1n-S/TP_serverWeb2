local jwt = require "resty.jwt"

local function get_token_from_cookie()
    local cookie = ngx.var.http_cookie
    if not cookie then return nil end

    local token = string.match(cookie, "auth_token=([^;]+)")
    return token
end

local token = get_token_from_cookie()
if not token then
    ngx.log(ngx.ERR, "❌ Aucun JWT trouvé dans les cookies")
    return ngx.redirect("/jwt/login.html")
end

local jwt_obj = jwt:verify("supersecret", token)

if not jwt_obj.verified then
    ngx.log(ngx.ERR, "❌ JWT invalide : " .. (jwt_obj.reason or "inconnu"))
    return ngx.redirect("/jwt/login.html")
end

ngx.log(ngx.ERR, "✅ JWT vérifié pour " .. (jwt_obj.payload.sub or "inconnu"))
