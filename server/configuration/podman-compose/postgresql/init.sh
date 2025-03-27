#!/bin/bash

set -e

PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD" psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "$POSTGRESQL_DATABASE" <<-EOSQL
    GRANT EXECUTE ON FUNCTION pg_ls_waldir TO artemis;
    CREATE EXTENSION pg_stat_statements;

    GRANT pg_monitor TO artemis;
EOSQL
