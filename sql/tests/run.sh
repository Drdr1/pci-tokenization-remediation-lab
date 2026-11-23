#!/usr/bin/env bash
# Runs the SQL tests against a SQL Server container.
#   CONTAINER=<name>  SA_PASSWORD=<password>  sql/tests/run.sh
# The repo is copied to /tmp/work inside the container.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${CONTAINER:?set CONTAINER}" "${SA_PASSWORD:?set SA_PASSWORD}"
python3 sql/tests/make_seed.py > /tmp/seed.sql
docker exec "$CONTAINER" rm -rf /tmp/work && docker exec "$CONTAINER" mkdir -p /tmp/work
docker cp sql "$CONTAINER":/tmp/work/sql
docker cp /tmp/seed.sql "$CONTAINER":/tmp/work/seed.sql
SQLCMD="/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P $SA_PASSWORD -b"
docker exec "$CONTAINER" $SQLCMD -Q "IF DB_ID('pci_test') IS NOT NULL BEGIN ALTER DATABASE pci_test SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE pci_test; END; CREATE DATABASE pci_test COLLATE SQL_Latin1_General_CP1_CI_AS;"
for f in sql/tests/schema.sql sql/00_objects.sql seed.sql sql/tests/tests.sql; do
  echo "== $f"
  docker exec "$CONTAINER" $SQLCMD -d pci_test -i "/tmp/work/$f"
done
echo "SQL tests passed"
