# alpine 3.23
FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f
LABEL org.opencontainers.image.source="https://github.com/n24q02m/skret"
RUN apk add --no-cache ca-certificates
# The dockers_v2 build context nests the prebuilt binaries one directory per
# platform (linux/amd64/skret, linux/arm64/skret) rather than dropping a single
# one at the root, so this path has to name the platform being built. buildx
# fills TARGETPLATFORM in; declaring the ARG is what brings it into scope.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/skret /usr/local/bin/skret
ENTRYPOINT ["skret"]
