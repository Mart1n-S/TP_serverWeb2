FROM php:8.2-apache

# Installer les dépendances nécessaires pour PostgreSQL + PHP extensions
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Copier les fichiers PHP dans le dossier web
COPY html/ /var/www/html/

# Activer mod_rewrite (si besoin pour Apache)
RUN a2enmod rewrite

# Définir une variable d’environnement accessible en PHP via getenv()
ENV HO=local

# Droits (optionnel)
RUN chown -R www-data:www-data /var/www/html
