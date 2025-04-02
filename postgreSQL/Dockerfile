FROM postgres:16

# Installation de l'extension PL/Python (nécessite apt)
RUN apt-get update && apt-get install -y postgresql-plpython3-16

# Variables d’environnement
ENV POSTGRES_DB=authCB
ENV POSTGRES_USER=authcb
ENV POSTGRES_PASSWORD=authcb

# Script SQL à exécuter au démarrage
COPY setup-db.sql /docker-entrypoint-initdb.d/
