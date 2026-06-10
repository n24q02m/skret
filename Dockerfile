# alpine 3.23
FROM alpine@sha256:33154315cf4402e697f065e6ec2156e292187e633908ccfede9c66279b6fa956
RUN apk add --no-cache ca-certificates
COPY skret /usr/local/bin/skret
ENTRYPOINT ["skret"]
