# Keep the upstream PostgreSQL 16 image reproducible, but refresh Debian security
# updates at build time. The upstream digest pins the multi-platform index; each
# platform receives its corresponding upstream manifest.
# The upstream PostgreSQL image still ships gosu built with Go 1.24.6. Rebuild the same
# upstream utility from its pinned source release with the patched Go toolchain so Trivy
# does not leave a HIGH stdlib finding in the runtime image.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gosu-build
ARG GOSU_COMMIT=29b939aa5bd4dc588af765b8248f6e39150d2565
RUN apk add --no-cache git
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    git init /src/gosu \
    && git -C /src/gosu fetch --depth 1 https://github.com/tianon/gosu.git "${GOSU_COMMIT}" \
    && git -C /src/gosu checkout --detach FETCH_HEAD \
    && cd /src/gosu \
    && go mod download \
    && CGO_ENABLED=0 go build -trimpath -o /out/gosu .

FROM postgres:16-bookworm@sha256:ce3efec6bc404f6b15ebf5d9bed6b45a9d4655aea238d7dacc3467ccb05a1175
COPY --from=gosu-build /out/gosu /usr/local/bin/gosu

USER root

# CVE fixes can land in Debian security between upstream PostgreSQL image builds.
# Fail the build unless the fixed apt packages are installed; never silently keep
# the vulnerable versions when the security repository is unavailable.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes --only-upgrade apt libapt-pkg6.0 \
    && apt_version="$(dpkg-query -W -f='${Version}' apt)" \
    && libapt_version="$(dpkg-query -W -f='${Version}' libapt-pkg6.0)" \
    && dpkg --compare-versions "$apt_version" ge 2.6.2 \
    && dpkg --compare-versions "$libapt_version" ge 2.6.2 \
    && printf 'apt=%s libapt-pkg6.0=%s\n' "$apt_version" "$libapt_version" \
    && rm -rf /var/lib/apt/lists/*
