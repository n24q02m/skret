# alpine 3.23
FROM alpine@sha256:4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b
RUN apk add --no-cache ca-certificates
COPY skret /usr/local/bin/skret
ENTRYPOINT ["skret"]
