# One image holds every OpenBastion binary (ADR-0033): the code is built once, and each Compose
# service runs the one it is. Built from the repository root:
#   docker build -f deploy/docker-compose/Dockerfile .

# -- build: every binary, static, from go.work and go.sum ----------------------------------
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN mkdir -p /out && go build -ldflags="-s -w" -o /out/ \
      ./services/access/api-gateway/cmd/api-gateway \
      ./services/access/authentication/cmd/authentication \
      ./services/access/authorization/cmd/authorization \
      ./services/access/session-broker/cmd/session-broker \
      ./services/proxy/ssh-proxy/cmd/ssh-proxy \
      ./services/vault/password-vault/cmd/password-vault \
      ./services/recording-audit/audit-service/cmd/audit-service \
      ./services/recording-audit/command-recorder/cmd/command-recorder \
      ./pkg/mtls/cmd/openbastion-pki \
      ./cli/openbastion-cli \
      ./test/integration/cmd/demo-ssh-target
# The directories the volumes are mounted on, owned by the unprivileged user: an empty named
# volume takes the ownership of the directory it is mounted on.
RUN mkdir -p /rootfs/pki /rootfs/var/lib/openbastion/anchors /rootfs/var/lib/openbastion/archives \
 && chown -R 65532:65532 /rootfs

# -- tools: the build image, with a shell, for the one-off certificate job only -------------
FROM build AS tools
RUN cp /out/openbastion-pki /usr/local/bin/

# -- runtime: no shell, no package manager, not root ------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /rootfs/ /
USER 65532:65532
