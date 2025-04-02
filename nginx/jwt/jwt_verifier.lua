local jwt = require "resty.jwt"

-- 🔐 Lire la clé depuis un fichier monté (en lecture seule)
local function read_secret_key(path)
    local file = io.open(path, "r")
    if not file then
        ngx.log(ngx.ERR, "❌ Impossible d'ouvrir le fichier de clé JWT à " .. path)
        return nil
    end
    local key = file:read("*a")
    file:close()
    return (key and key:gsub("%s+", "")) or nil
end

local secret_key = read_secret_key("/etc/nginx/jwt-secret.key")

if not secret_key then
    ngx.log(ngx.ERR, "❌ Clé secrète JWT non trouvée")
    return ngx.exit(500)
end

local function get_token_from_cookie()
    local cookie = ngx.var.http_cookie
    if not cookie then return nil end
    return string.match(cookie, "auth_token=([^;]+)")
end

local token = get_token_from_cookie()
if not token then
    ngx.log(ngx.ERR, "❌ Aucun JWT trouvé dans les cookies")
    return ngx.redirect("/jwt/login.html")
end

local jwt_obj = jwt:verify(secret_key, token)

if not jwt_obj.verified then
    ngx.log(ngx.ERR, "❌ JWT invalide : " .. (jwt_obj.reason or "inconnu"))
    return ngx.redirect("/jwt/login.html")
end

ngx.log(ngx.ERR, "✅ JWT vérifié pour " .. (jwt_obj.payload.sub or "inconnu"))
