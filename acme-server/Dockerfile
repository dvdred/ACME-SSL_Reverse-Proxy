FROM python:3.11-alpine

# Installa dipendenze
RUN apk add --no-cache \
    curl \
    openssl \
    tzdata \
    bash \
    nginx \
    cronie \
    gcc \
    musl-dev \
    libffi-dev

# Installa librerie Python
RUN pip install --no-cache-dir requests cryptography

# Crea directory necessarie
RUN mkdir -p /var/www/acme-challenge /certs /var/log /scripts

# Copia configurazione nginx per challenge
COPY nginx.conf /etc/nginx/nginx.conf

# Copia scripts Python
COPY scripts/zerossl-cert.py /scripts/zerossl-cert.py
COPY scripts/manage-certs.py /scripts/manage-certs.py
COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/renew.sh /renew.sh

# Fix line endings e permessi
RUN sed -i 's/\r$//' /entrypoint.sh && \
    sed -i 's/\r$//' /renew.sh && \
    sed -i 's/\r$//' /scripts/zerossl-cert.py && \
    sed -i 's/\r$//' /scripts/manage-certs.py && \
    chmod +x /entrypoint.sh /renew.sh /scripts/zerossl-cert.py /scripts/manage-certs.py

# Setup cron per rinnovo automatico
RUN echo "0 3 * * * /renew.sh >> /var/log/acme-renew.log 2>&1" > /etc/crontabs/root

EXPOSE 80

VOLUME ["/certs"]

CMD ["/bin/bash", "/entrypoint.sh"]