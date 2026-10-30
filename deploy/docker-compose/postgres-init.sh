#!/bin/sh
# One database per service, each owned by its own role, nothing shared (ADR-0002, ADR-0033).
# Run once by the postgres image, on an empty data directory. Identifiers are quoted:
# "authorization" is a reserved word.
set -eu
for svc in authentication authorization session_broker password_vault audit_service command_recorder; do
  var="PG_PASSWORD_$(echo "$svc" | tr a-z A-Z)"
  eval "pw=\${$var:?$var is not set — run init.sh}"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE "$svc" LOGIN PASSWORD '$pw';
CREATE DATABASE "$svc" OWNER "$svc";
REVOKE ALL ON DATABASE "$svc" FROM PUBLIC;
SQL
done
