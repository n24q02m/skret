# alpine 3.23
FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f
RUN apk add --no-cache ca-certificates
COPY skret /usr/local/bin/skret
ENTRYPOINT ["skret"]
