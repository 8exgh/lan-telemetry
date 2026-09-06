FROM alpine:3.23
RUN deluser guest \
    && addgroup -g 10001 guest && adduser -D -u 10001 -G guest guest \
    && mkdir -p /srv/shared \
    && printf 'Internal file server\nMaintenance window: Sunday 02:00\n' > /srv/shared/README.txt
USER 10001:10001
WORKDIR /home/guest
CMD ["/bin/sleep", "infinity"]
