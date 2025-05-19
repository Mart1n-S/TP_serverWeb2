FROM openresty/openresty:alpine

# Installer opm + dépendances nécessaires à lua-resty-jwt
RUN apk add --no-cache git curl perl openntpd tzdata && \
    opm get SkyLothar/lua-resty-jwt

# Configurer fuseau horaire (Europe/Paris)
RUN cp /usr/share/zoneinfo/Europe/Paris /etc/localtime && \
    echo "Europe/Paris" > /etc/timezone

# Copier la configuration NGINX
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copier le script Lua de vérification du JWT
COPY jwt/jwt_verifier.lua /usr/local/openresty/nginx/html/jwt_verifier.lua

# Copier les certificats SSL
COPY ssl/ /etc/nginx/ssl/

# Copier le dossier contenant login.html et potentiellement d’autres fichiers
COPY jwt/ /usr/local/openresty/nginx/html/jwt/

# Exposer le port HTTPS
EXPOSE 443

# Lancement d'OpenResty en mode "daemon off"
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]