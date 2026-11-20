# alpine 3.24
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.source="https://github.com/n24q02m/skret"
RUN apk add --no-cache ca-certificates
# The dockers_v2 build context nests the prebuilt binaries one directory per
# platform (linux/amd64/skret, linux/arm64/skret) rather than dropping a single
# one at the root, so this path has to name the platform being built. buildx
# fills TARGETPLATFORM in; declaring the ARG is what brings it into scope.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/skret /usr/local/bin/skret
ENTRYPOINT ["/usr/local/bin/skret"]
