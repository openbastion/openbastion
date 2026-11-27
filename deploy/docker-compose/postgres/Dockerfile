# Keep the upstream PostgreSQL 16 image reproducible, but refresh Debian security
# updates at build time. The upstream digest pins the multi-platform index; each
# platform receives its corresponding upstream manifest.
# The upstream PostgreSQL image still ships gosu built with Go 1.24.6. Rebuild the same
# upstream utility from its immutable Go module pseudo-version with the patched toolchain so
# Trivy does not leave a HIGH stdlib finding in the runtime image. The Go module proxy and
# checksum database avoid a direct git fetch from GitHub during container builds.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gosu-build
ARG GOSU_VERSION=v0.0.0-20261025094355-29b939aa5bd4
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out CGO_ENABLED=0 go install -trimpath "github.com/tianon/gosu@${GOSU_VERSION}"

FROM postgres:16-bookworm@sha256:ce3efec6bc404f6b15ebf5d9bed6b45a9d4655aea238d7dacc3467ccb05a1175
COPY --from=gosu-build /out/gosu /usr/local/bin/gosu

USER root

# CVE fixes can land in Debian security between upstream PostgreSQL image builds.
# Fail the build unless the fixed apt packages are installed; never silently keep
# the vulnerable versions when the security repository is unavailable.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes --only-upgrade \
        apt libapt-pkg6.0 \
        libpam-modules libpam-modules-bin libpam-runtime libpam0g \
    && apt_version="$(dpkg-query -W -f='${Version}' apt)" \
    && libapt_version="$(dpkg-query -W -f='${Version}' libapt-pkg6.0)" \
    && pam_modules_version="$(dpkg-query -W -f='${Version}' libpam-modules)" \
    && pam_modules_bin_version="$(dpkg-query -W -f='${Version}' libpam-modules-bin)" \
    && pam_runtime_version="$(dpkg-query -W -f='${Version}' libpam-runtime)" \
    && pam_version="$(dpkg-query -W -f='${Version}' libpam0g)" \
    && dpkg --compare-versions "$apt_version" ge 2.6.2 \
    && dpkg --compare-versions "$libapt_version" ge 2.6.2 \
    && for version in "$pam_modules_version" "$pam_modules_bin_version" "$pam_runtime_version" "$pam_version"; do \
        dpkg --compare-versions "$version" ge 1.5.2-6+deb12u3; \
    done \
    && printf 'apt=%s libapt-pkg6.0=%s libpam=%s\n' "$apt_version" "$libapt_version" "$pam_version" \
    && rm -rf /var/lib/apt/lists/*
