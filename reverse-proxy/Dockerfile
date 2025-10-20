FROM nginx:alpine

RUN apk add --no-cache \
    bash \
    openssl \
    netcat-openbsd \
    tzdata

RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY templates/default.conf.template /etc/nginx/templates/
COPY scripts/reload-cron.sh /reload-cron.sh
COPY scripts/startup.sh /startup.sh

RUN sed -i 's/\r$//' /reload-cron.sh /startup.sh && \
    chmod +x /reload-cron.sh /startup.sh

RUN mkdir -p /etc/nginx/certs /var/log/nginx

RUN echo "0 4 * * * /reload-cron.sh >> /var/log/nginx-reload.log 2>&1" > /etc/crontabs/root

EXPOSE 443

CMD ["/startup.sh"]