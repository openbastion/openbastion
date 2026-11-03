# syntax=docker/dockerfile:1.7
# One image holds every OpenBastion binary (ADR-0033): the code is built once, and each Compose
# service runs the one it is. Built from the repository root:
#   docker build -f deploy/docker-compose/Dockerfile .

# -- build: every binary, static, from go.work and go.sum ----------------------------------
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
# The generated Protobuf stubs are not in git (docs/development/contributing.md): the image
# generates them, so a clean clone builds. Versions mirror `make proto-tools`.
ARG BUF_VERSION=v1.75.0
ARG PROTOC_GEN_GO_VERSION=v1.36.4
ARG PROTOC_GEN_GO_GRPC_VERSION=v1.5.1
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install github.com/bufbuild/buf/cmd/buf@${BUF_VERSION} \
 && GOBIN=/usr/local/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION} \
 && GOBIN=/usr/local/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    buf generate
# The version stamped in every binary (ADR-0063): make scan-images and the CI pass VERSION+<commit>,
# or the release; "dev" otherwise (.git is not in the build context).
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out && go build -ldflags="-s -w -X github.com/openbastion/openbastion/pkg/buildinfo.Version=${VERSION}" -o /out/ \
      ./services/access/api-gateway/cmd/api-gateway \
      ./services/access/authentication/cmd/authentication \
      ./services/access/authorization/cmd/authorization \
      ./services/access/session-broker/cmd/session-broker \
      ./services/proxy/ssh-proxy/cmd/ssh-proxy \
      ./services/vault/password-vault/cmd/password-vault \
      ./services/recording-audit/audit-service/cmd/audit-service \
      ./services/recording-audit/command-recorder/cmd/command-recorder \
      ./services/recording-audit/video-recorder/cmd/video-recorder \
      ./pkg/mtls/cmd/openbastion-pki \
      ./cli/openbastion-cli \
      ./test/integration/cmd/demo-ssh-target
# The directories the volumes are mounted on, owned by the unprivileged user: an empty named
# volume takes the ownership of the directory it is mounted on.
RUN mkdir -p /rootfs/pki /rootfs/var/lib/openbastion/anchors /rootfs/var/lib/openbastion/archives \
 && chown -R 65532:65532 /rootfs

# -- ui: the Admin UI (ADR-0036), built from its lockfile ------------------------------------
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS ui
WORKDIR /openbastion-icons
COPY web/openbastion-icons/package.json web/openbastion-icons/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/openbastion-icons/ ./
RUN npm run build

WORKDIR /ui
COPY web/admin-ui/package.json web/admin-ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/admin-ui/ ./
RUN npm run build

# -- tools: the build image, with a shell, for the one-off certificate job only -------------
FROM build AS tools
RUN cp /out/openbastion-pki /usr/local/bin/

# -- runtime: no shell, no package manager, not root ------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
COPY --from=build /out/ /usr/local/bin/
COPY --from=ui /ui/dist/ /usr/local/share/openbastion/admin-ui/
COPY --from=build --chown=65532:65532 /rootfs/ /
USER 65532:65532
