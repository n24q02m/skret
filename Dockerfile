# alpine 3.24
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
LABEL org.opencontainers.image.source="https://github.com/n24q02m/skret"
RUN apk add --no-cache ca-certificates
# The dockers_v2 build context nests the prebuilt binaries one directory per
# platform (linux/amd64/skret, linux/arm64/skret) rather than dropping a single
# one at the root, so this path has to name the platform being built. buildx
# fills TARGETPLATFORM in; declaring the ARG is what brings it into scope.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/skret /usr/local/bin/skret
ENTRYPOINT ["/usr/local/bin/skret"]
