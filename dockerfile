FROM alpine:3.20

RUN apk add --no-cache ca-certificates

RUN mkdir -p /var/lib/candy

# Default image target: Linux amd64 binary prebuilt into dist/.
COPY dist/candygo-linux-amd64 /usr/bin/candygo
RUN chmod +x /usr/bin/candygo

ENTRYPOINT ["/usr/bin/candygo"]
CMD ["-c", "/etc/candy.cfg"]
