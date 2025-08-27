#!/bin/bash
# Multi-Database Initialization Script for E2E RAGnostic → BSN Knowledge Pipeline
# Creates separate databases for RAGnostic and BSN Knowledge with proper schemas

set -e

echo "🚀 Initializing multiple databases for E2E pipeline testing..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    -- Create RAGnostic database
    CREATE DATABASE ragnostic_e2e;
    GRANT ALL PRIVILEGES ON DATABASE ragnostic_e2e TO $POSTGRES_USER;

    -- Create BSN Knowledge database
    CREATE DATABASE bsn_knowledge_e2e;
    GRANT ALL PRIVILEGES ON DATABASE bsn_knowledge_e2e TO $POSTGRES_USER;

    -- Create test analytics database for metrics
    CREATE DATABASE e2e_analytics;
    GRANT ALL PRIVILEGES ON DATABASE e2e_analytics TO $POSTGRES_USER;

    \l
EOSQL

echo "✅ Multi-database initialization completed successfully"
echo "   - ragnostic_e2e: RAGnostic microservices data"
echo "   - bsn_knowledge_e2e: BSN Knowledge application data"
echo "   - e2e_analytics: Test execution metrics and results"
