FROM php:8.2-apache

# Installer les dépendances nécessaires pour PostgreSQL, Composer, et PHP extensions
RUN apt-get update && apt-get install -y \
    libpq-dev \
    git \
    unzip \
    curl \
    && docker-php-ext-install pdo pdo_pgsql

# Installer Composer globalement
RUN curl -sS https://getcomposer.org/installer | php && \
    mv composer.phar /usr/local/bin/composer

# Copier les fichiers PHP dans le dossier web
COPY html/ /var/www/html/

# Installer firebase/php-jwt avec Composer
WORKDIR /var/www/html
RUN composer require firebase/php-jwt

# Activer mod_rewrite (si besoin pour Apache)
RUN a2enmod rewrite

# Définir une variable d’environnement accessible en PHP via getenv()
ENV HO=local

# Droits (optionnel)
RUN chown -R www-data:www-data /var/www/html
