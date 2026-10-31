# Development image of the Base44 sandbox stack (docker-compose.base44.yml) — not a
# deployment image. The `warm` stage only fills the module cache and the build cache so that a
# service's `go run` starts in seconds; nothing of it lands in the final image. Every service
# bind-mounts the repository at /src and runs the CLONED SOURCE, so an edit is picked up by the
# next `go run` (or by restarting the service: Go has no hot reload).
FROM golang:1.27.1@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS warm
ENV GOWORK=/src/go.work
WORKDIR /src
COPY . .
# Every module of the workspace (go.work), built once: the cache is what we keep.
RUN set -e; for m in $(awk '/^[[:space:]]+\.\//{print $1}' go.work); do echo "warm $m"; (cd "$m" && go build ./...); done

FROM golang:1.27.1@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2
ENV GOWORK=/src/go.work
COPY --from=warm /go/pkg/mod /go/pkg/mod
COPY --from=warm /root/.cache/go-build /root/.cache/go-build
WORKDIR /src
# curl and openssl come with the golang image: Compose healthchecks and the seed use them.
