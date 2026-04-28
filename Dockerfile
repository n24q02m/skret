FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY skret /usr/local/bin/skret
ENTRYPOINT ["skret"]
