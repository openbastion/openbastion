# Keep the upstream PostgreSQL 16 image reproducible, but refresh Debian security
# updates at build time. The upstream digest pins the multi-platform index; each
# platform receives its corresponding upstream manifest.
FROM postgres:16-bookworm@sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938

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
