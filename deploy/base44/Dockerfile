# Development image of the Base44 sandbox stack (deploy/base44/docker-compose.yml) — not a
# deployment image. The `warm` stage only fills the module cache and the build cache so that a
# service's `go run` starts in seconds; nothing of it lands in the final image. Every service
# bind-mounts the repository at /src and runs the CLONED SOURCE, so an edit is picked up by the
# next `go run` (or by restarting the service: Go has no hot reload).
#
# The Protobuf contracts are not generated in git (`make proto-gen`, .gitignore keeps *.pb.go
# out): buf and its two plugins are installed here, and the `proto` service generated the
# packages into the bind-mounted source before the Go services start.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS warm
ARG BUF_VERSION=v1.75.0
ARG PROTOBUF_GO_VERSION=v1.36.4
ARG PROTOBUF_GRPC_VERSION=v1.5.1
ENV GOWORK=/src/go.work
RUN go install github.com/bufbuild/buf/cmd/buf@${BUF_VERSION} \
 && go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_GO_VERSION} \
 && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOBUF_GRPC_VERSION}
ENV PATH="/go/bin:${PATH}"
WORKDIR /src
COPY . .
# Generate the contracts, then every module of the workspace (go.work) once: the cache is what we
# keep.
RUN set -e; buf generate; for m in $(awk '/^[[:space:]]+\.\//{print $1}' go.work); do echo "warm $m"; (cd "$m" && go build ./...); done

FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b
ENV GOWORK=/src/go.work
COPY --from=warm /go/bin/buf /go/bin/protoc-gen-go /go/bin/protoc-gen-go-grpc /usr/local/bin/
COPY --from=warm /go/pkg/mod /go/pkg/mod
COPY --from=warm /root/.cache/go-build /root/.cache/go-build
WORKDIR /src
# curl and openssl come with the golang image: Compose healthchecks and the seed use them.
