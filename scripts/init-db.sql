-- BSN Knowledge Base Database Initialization
-- PostgreSQL schema for metadata and configuration storage

-- Create database if not exists (this runs in docker-entrypoint-initdb.d)
-- Database already created by Docker environment variables

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS knowledge;
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set search path
SET search_path TO knowledge, public;

-- Medical terminology metadata table
CREATE TABLE IF NOT EXISTS knowledge.medical_terms_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    neo4j_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT,
    synonyms TEXT[],
    icd_10_codes TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    version INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_medical_terms_category ON knowledge.medical_terms_metadata(category);
CREATE INDEX IF NOT EXISTS idx_medical_terms_name ON knowledge.medical_terms_metadata USING gin(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_medical_terms_synonyms ON knowledge.medical_terms_metadata USING gin(synonyms);
CREATE INDEX IF NOT EXISTS idx_medical_terms_active ON knowledge.medical_terms_metadata(is_active);

-- Categories reference table
CREATE TABLE IF NOT EXISTS knowledge.medical_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    parent_category_id UUID REFERENCES knowledge.medical_categories(id),
    hierarchy_level INTEGER DEFAULT 1,
    color_code VARCHAR(7), -- Hex color for UI
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Insert standard medical categories
INSERT INTO knowledge.medical_categories (name, description, hierarchy_level) VALUES
    ('cardiovascular', 'Heart and blood vessel related conditions', 1),
    ('respiratory', 'Lung and breathing related conditions', 1),
    ('endocrine', 'Hormone and metabolic conditions', 1),
    ('neurological', 'Brain and nervous system conditions', 1),
    ('musculoskeletal', 'Bone, muscle, and joint conditions', 1),
    ('gastrointestinal', 'Digestive system conditions', 1),
    ('genitourinary', 'Kidney and reproductive system conditions', 1),
    ('dermatological', 'Skin and related conditions', 1),
    ('psychiatric', 'Mental health conditions', 1),
    ('infectious', 'Infectious diseases and conditions', 1),
    ('oncological', 'Cancer and tumor related conditions', 1),
    ('hematological', 'Blood and lymphatic system conditions', 1)
ON CONFLICT (name) DO NOTHING;

-- Relationship types for Neo4j integration
CREATE TABLE IF NOT EXISTS knowledge.relationship_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    bidirectional BOOLEAN DEFAULT FALSE,
    strength_range JSONB DEFAULT '{"min": 0.0, "max": 1.0}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Standard relationship types
INSERT INTO knowledge.relationship_types (name, description, bidirectional) VALUES
    ('COMORBID_WITH', 'Conditions that frequently occur together', TRUE),
    ('CAUSES', 'One condition leads to another', FALSE),
    ('TREATS', 'Treatment relationship', FALSE),
    ('SYMPTOM_OF', 'Symptom relationship', FALSE),
    ('RELATED_TO', 'General relationship', TRUE),
    ('CONTRAINDICATED_WITH', 'Should not be used together', TRUE),
    ('PRECEDES', 'Temporal relationship', FALSE),
    ('PART_OF', 'Hierarchical relationship', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Analytics schema for performance tracking
CREATE TABLE IF NOT EXISTS analytics.query_performance (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    query_type VARCHAR(50) NOT NULL,
    query_text TEXT,
    execution_time_ms NUMERIC(10,3),
    result_count INTEGER,
    database_type VARCHAR(20), -- 'neo4j', 'postgres', 'qdrant'
    user_id VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);

-- Index for analytics
CREATE INDEX IF NOT EXISTS idx_query_performance_timestamp ON analytics.query_performance(timestamp);
CREATE INDEX IF NOT EXISTS idx_query_performance_type ON analytics.query_performance(query_type);

-- Audit schema for change tracking
CREATE TABLE IF NOT EXISTS audit.data_changes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name VARCHAR(100) NOT NULL,
    record_id VARCHAR(255) NOT NULL,
    change_type VARCHAR(20) NOT NULL, -- 'INSERT', 'UPDATE', 'DELETE'
    old_values JSONB,
    new_values JSONB,
    changed_by VARCHAR(100),
    change_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    change_reason TEXT
);

-- Index for audit
CREATE INDEX IF NOT EXISTS idx_data_changes_timestamp ON audit.data_changes(change_timestamp);
CREATE INDEX IF NOT EXISTS idx_data_changes_table ON audit.data_changes(table_name);

-- Configuration table for application settings
CREATE TABLE IF NOT EXISTS knowledge.application_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    config_type VARCHAR(50) DEFAULT 'general',
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(100)
);

-- Default configuration values
INSERT INTO knowledge.application_config (config_key, config_value, description, config_type) VALUES
    ('neo4j_connection_pool_size', '10', 'Maximum number of Neo4j connections', 'database'),
    ('semantic_search_threshold', '0.7', 'Minimum similarity threshold for semantic search', 'search'),
    ('graph_traversal_max_depth', '5', 'Maximum depth for graph traversal queries', 'graph'),
    ('cache_ttl_seconds', '3600', 'Default cache time-to-live in seconds', 'cache'),
    ('batch_processing_size', '100', 'Default batch size for bulk operations', 'processing'),
    ('api_rate_limit_per_minute', '1000', 'API requests per minute limit', 'api'),
    ('enable_query_logging', 'true', 'Enable detailed query performance logging', 'logging')
ON CONFLICT (config_key) DO NOTHING;

-- User sessions table (for API key management)
CREATE TABLE IF NOT EXISTS knowledge.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions TEXT[] DEFAULT ARRAY['read'],
    rate_limit INTEGER DEFAULT 1000, -- requests per minute
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- Performance optimization stored procedures
CREATE OR REPLACE FUNCTION knowledge.update_medical_term_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic updated_at
DROP TRIGGER IF EXISTS medical_terms_metadata_updated_at ON knowledge.medical_terms_metadata;
CREATE TRIGGER medical_terms_metadata_updated_at
    BEFORE UPDATE ON knowledge.medical_terms_metadata
    FOR EACH ROW
    EXECUTE FUNCTION knowledge.update_medical_term_updated_at();

-- Function for text search
CREATE OR REPLACE FUNCTION knowledge.search_medical_terms(
    search_text TEXT,
    category_filter TEXT DEFAULT NULL,
    limit_count INTEGER DEFAULT 50
)
RETURNS TABLE(
    id UUID,
    neo4j_id VARCHAR,
    name VARCHAR,
    category VARCHAR,
    description TEXT,
    similarity REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mt.id,
        mt.neo4j_id,
        mt.name,
        mt.category,
        mt.description,
        similarity(mt.name, search_text) as similarity
    FROM knowledge.medical_terms_metadata mt
    WHERE 
        (category_filter IS NULL OR mt.category = category_filter)
        AND mt.is_active = TRUE
        AND (
            mt.name ILIKE '%' || search_text || '%'
            OR search_text = ANY(mt.synonyms)
            OR similarity(mt.name, search_text) > 0.3
        )
    ORDER BY similarity DESC, mt.name
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- Performance monitoring view
CREATE OR REPLACE VIEW analytics.performance_summary AS
SELECT 
    query_type,
    database_type,
    COUNT(*) as total_queries,
    AVG(execution_time_ms) as avg_execution_time,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) as p95_execution_time,
    COUNT(*) FILTER (WHERE success = FALSE) as error_count,
    DATE_TRUNC('hour', timestamp) as hour_bucket
FROM analytics.query_performance
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY query_type, database_type, DATE_TRUNC('hour', timestamp)
ORDER BY hour_bucket DESC, avg_execution_time DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA knowledge TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA knowledge TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO bsn_knowledge;

-- Final setup message
DO $$
BEGIN
    RAISE NOTICE 'BSN Knowledge Base database initialization completed successfully';
    RAISE NOTICE 'Schemas created: knowledge, analytics, audit';
    RAISE NOTICE 'Core tables: medical_terms_metadata, medical_categories, relationship_types';
    RAISE NOTICE 'Performance monitoring and audit logging enabled';
END $$;