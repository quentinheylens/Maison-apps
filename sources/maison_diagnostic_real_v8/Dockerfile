# Rebuild stable Tailscale with the reviewed upstream compression security fix.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS tailnet
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOSUMDB=sum.golang.org GOMAXPROCS=2
WORKDIR /src
ADD --checksum=sha256:862f12b3177d5e961f2a86cf82fb1ff3551786afcaf95f2dc9a8318889f98732 https://codeload.github.com/tailscale/tailscale/tar.gz/refs/tags/v1.104.4 /tmp/source.tar.gz
RUN tar --strip-components=1 -xzf /tmp/source.tar.gz
RUN --mount=type=secret,id=proxy_ca,required=true SSL_CERT_FILE=/run/secrets/proxy_ca go get github.com/klauspost/compress@v1.20.2
RUN --mount=type=secret,id=proxy_ca,required=true SSL_CERT_FILE=/run/secrets/proxy_ca go test -short -timeout 180s github.com/klauspost/compress/zstd github.com/klauspost/compress/flate
RUN --mount=type=secret,id=proxy_ca,required=true SSL_CERT_FILE=/run/secrets/proxy_ca GOOS=linux GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w -X tailscale.com/version.longStamp=1.104.4-maison-compress-1.20.2 -X tailscale.com/version.shortStamp=1.104.4' -o /out/ ./cmd/tailscale ./cmd/tailscaled
RUN --mount=type=secret,id=proxy_ca,required=true SSL_CERT_FILE=/run/secrets/proxy_ca go mod verify && go version -m /out/tailscale && go version -m /out/tailscaled
FROM ghcr.io/quentinheylens/maison-apps/maison_diagnostic_gateway_v6@sha256:e30a5010a21628fc30eaf3f1a88969bca2fcc6df3aca60b9163514428dbe90a8 AS python-runtime
# Reuse the hardened runtime, without inheriting any simulation or transaction code.
FROM scratch
COPY --from=python-runtime /usr /usr
COPY --from=python-runtime /lib /lib
COPY --from=python-runtime /bin /bin
COPY --from=python-runtime /sbin /sbin
COPY --from=python-runtime /etc /etc
COPY --from=python-runtime /var /var
COPY --from=python-runtime /tmp /tmp
COPY --from=python-runtime /app/yaml /app/yaml
COPY --from=python-runtime /app/PyYAML-LICENSE /app/PyYAML-LICENSE
COPY --from=tailnet /out/tailscale /usr/local/bin/tailscale
COPY --from=tailnet /out/tailscaled /usr/local/bin/tailscaled
COPY --from=tailnet /src/LICENSE /usr/share/licenses/tailscale/LICENSE
WORKDIR /app
COPY gateway /app/gateway
COPY diagnostic_real /app/diagnostic_real
COPY installation-profile.json /app/installation-profile.json
ENV PATH=/usr/local/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-m", "diagnostic_real.entrypoint"]
