#!/bin/sh
set -eu

: "${PGPASSWORD:?PG_SUPERUSER_PASSWORD is required}"
: "${PG_PASSWORD_VIDEO_RECORDER:?PG_PASSWORD_VIDEO_RECORDER is required}"

attempt=0
until pg_isready --timeout=2 --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" --dbname="$PGDATABASE" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "video-recorder-db-init: PostgreSQL did not accept connections within 30 seconds" >&2
    exit 1
  fi
  sleep 1
done

db_owner=$(psql --no-password --set=ON_ERROR_STOP=1 --tuples-only --no-align \
  --command="SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'video_recorder'")
if [ -n "$db_owner" ] && [ "$db_owner" != video_recorder ]; then
  echo "video-recorder-db-init: existing video_recorder database has an unexpected owner" >&2
  exit 1
fi

psql --no-password --set=ON_ERROR_STOP=1 <<'SQL'
\getenv video_password PG_PASSWORD_VIDEO_RECORDER
SELECT format('ALTER ROLE video_recorder LOGIN PASSWORD %L', :'video_password')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'video_recorder')
\gexec
SELECT format('CREATE ROLE video_recorder LOGIN PASSWORD %L', :'video_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'video_recorder')
\gexec
SELECT format('CREATE DATABASE video_recorder OWNER video_recorder')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'video_recorder')
\gexec
REVOKE ALL ON DATABASE video_recorder FROM PUBLIC;
SQL
