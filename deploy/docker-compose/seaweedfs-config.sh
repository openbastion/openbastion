#!/bin/sh
set -eu

: "${VIDEO_RECORDER_S3_ACCESS_KEY:?VIDEO_RECORDER_S3_ACCESS_KEY is required}"
: "${VIDEO_RECORDER_S3_SECRET_KEY:?VIDEO_RECORDER_S3_SECRET_KEY is required}"

case "$VIDEO_RECORDER_S3_ACCESS_KEY$VIDEO_RECORDER_S3_SECRET_KEY" in
  *[!0-9a-f]*)
    echo "seaweedfs-config: S3 credentials must contain only lowercase hexadecimal characters" >&2
    exit 1
    ;;
esac
if [ "${#VIDEO_RECORDER_S3_ACCESS_KEY}" -ne 64 ] || [ "${#VIDEO_RECORDER_S3_SECRET_KEY}" -ne 64 ]; then
  echo "seaweedfs-config: S3 credentials must each be 64 hexadecimal characters" >&2
  exit 1
fi

umask 077
printf '{"identities":[{"name":"video-recorder","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Admin","Read","Write","List"]}]}\n' \
  "$VIDEO_RECORDER_S3_ACCESS_KEY" "$VIDEO_RECORDER_S3_SECRET_KEY" > /config/s3.json
chown 1000:1000 /config/s3.json
chmod 0400 /config/s3.json
