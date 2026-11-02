# syntax=docker/dockerfile:1.7
# Development image of the Base44 sandbox stack (deploy/base44/docker-compose.yml) — not a
# deployment image. The `warm` stage only fills the module cache and the build cache so that a
# service's `go run` starts in seconds; nothing of it lands in the final image. Every service
# bind-mounts the repository at /src and runs the CLONED SOURCE, so an edit is picked up by the
# next `go run` (or by restarting the service: Go has no hot reload).
#
# The Protobuf contracts are not generated in git (`make proto-gen`, .gitignore keeps *.pb.go
# out): buf and its two plugins are installed here, and the `proto` service generated the
# packages into the bind-mounted source before the Go services start.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS warm
ARG BUF_VERSION=v1.75.0
ARG PROTOBUF_GO_VERSION=v1.36.4
ARG PROTOBUF_GRPC_VERSION=v1.5.1
ENV CGO_ENABLED=0 GOWORK=/src/go.work
RUN GOMODCACHE=/tmp/tool-modcache GOCACHE=/tmp/tool-build-cache go install github.com/bufbuild/buf/cmd/buf@${BUF_VERSION} \
 && GOMODCACHE=/tmp/tool-modcache GOCACHE=/tmp/tool-build-cache go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_GO_VERSION} \
 && GOMODCACHE=/tmp/tool-modcache GOCACHE=/tmp/tool-build-cache go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOBUF_GRPC_VERSION} \
 && rm -rf /tmp/tool-modcache /tmp/tool-build-cache
ENV PATH="/go/bin:${PATH}"
WORKDIR /src
COPY . .
# Generate the contracts, then every module of the workspace (go.work) once: the cache is what we
# keep.
RUN set -e; buf generate; for m in $(awk '/^[[:space:]]+\.\//{print $1}' go.work); do echo "warm $m"; (cd "$m" && go build ./...); done

FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb
RUN apk add --no-cache bash curl openssl
ENV CGO_ENABLED=0 GOWORK=/src/go.work
COPY --from=warm /go/bin/buf /go/bin/protoc-gen-go /go/bin/protoc-gen-go-grpc /usr/local/bin/
COPY --from=warm /go/pkg/mod /go/pkg/mod
COPY --from=warm /root/.cache/go-build /root/.cache/go-build
WORKDIR /src
# bash provides the TCP healthchecks; curl serves the HTTP healthchecks and seed; openssl is available for local TLS diagnostics.
