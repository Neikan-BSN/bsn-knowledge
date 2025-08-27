-- RAGnostic E2E Database Schema
-- Optimized for comprehensive pipeline testing with medical content focus

\c ragnostic_e2e;

-- Create extensions for advanced functionality
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Job Management Tables
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    source_url TEXT,
    source_type VARCHAR(50),
    config JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    progress JSONB DEFAULT '{"completed": 0, "total": 0}',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    assigned_worker VARCHAR(100),
    estimated_duration_seconds INTEGER,
    actual_duration_seconds INTEGER
);

-- Medical Document Processing Tables
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES jobs(id) ON DELETE CASCADE,
    original_filename VARCHAR(500),
    file_type VARCHAR(50) NOT NULL,
    file_size_bytes BIGINT,
    content_hash VARCHAR(64),
    medical_content_type VARCHAR(100), -- 'nursing_textbook', 'clinical_guidelines', 'nclex_prep', etc.
    processing_status VARCHAR(20) DEFAULT 'pending',
    extracted_text TEXT,
    metadata JSONB DEFAULT '{}',
    medical_metadata JSONB DEFAULT '{}', -- Medical-specific metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

-- Document Chunks for Vector Processing
CREATE TABLE document_chunks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    chunk_type VARCHAR(50) DEFAULT 'text', -- 'text', 'table', 'image_description', 'medical_term'
    word_count INTEGER,
    character_count INTEGER,
    medical_terms TEXT[], -- Extracted medical terminology
    confidence_score DECIMAL(5,4) DEFAULT 1.0, -- Medical accuracy confidence
    embedding_vector VECTOR(384), -- For semantic search
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Medical Terminology Extraction
CREATE TABLE medical_terms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    term VARCHAR(200) NOT NULL,
    umls_cui VARCHAR(20), -- UMLS Concept Unique Identifier
    semantic_type VARCHAR(100),
    definition TEXT,
    synonyms TEXT[],
    category VARCHAR(100), -- 'anatomy', 'pharmacology', 'pathology', etc.
    confidence_score DECIMAL(5,4) DEFAULT 1.0,
    source_documents UUID[], -- Array of document IDs where term appears
    frequency_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_term_cui UNIQUE (term, umls_cui)
);

-- Repository and Source Management
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url TEXT NOT NULL UNIQUE,
    repo_type VARCHAR(50) DEFAULT 'git', -- 'git', 'onedrive', 'local_folder'
    name VARCHAR(200) NOT NULL,
    description TEXT,
    medical_focus VARCHAR(100), -- 'nursing', 'medical', 'pharmacy', etc.
    processing_config JSONB DEFAULT '{}',
    last_processed_at TIMESTAMP WITH TIME ZONE,
    total_documents INTEGER DEFAULT 0,
    processing_status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Configuration Management
CREATE TABLE processor_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    processor_type VARCHAR(100) NOT NULL,
    config_name VARCHAR(200) NOT NULL,
    config_data JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    medical_specialty VARCHAR(100), -- Configuration optimized for specific medical areas
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_processor_config UNIQUE (processor_type, config_name)
);

-- Service Health and Monitoring
CREATE TABLE service_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(100) NOT NULL,
    health_status VARCHAR(20) NOT NULL, -- 'healthy', 'degraded', 'unhealthy'
    response_time_ms INTEGER,
    cpu_usage_percent DECIMAL(5,2),
    memory_usage_percent DECIMAL(5,2),
    active_connections INTEGER,
    error_rate_percent DECIMAL(5,4),
    last_error TEXT,
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- E2E Test Metrics
CREATE TABLE test_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    test_run_id VARCHAR(100) NOT NULL,
    test_case_id VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(12,6),
    metric_unit VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Medical Accuracy Tracking
CREATE TABLE medical_accuracy_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id),
    medical_term_id UUID REFERENCES medical_terms(id),
    accuracy_score DECIMAL(5,4) NOT NULL,
    validation_method VARCHAR(100), -- 'umls_validation', 'expert_review', 'automated_check'
    validator VARCHAR(100),
    validated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT
);

-- Create indexes for performance optimization
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_job_type ON jobs(job_type);
CREATE INDEX idx_jobs_created_at ON jobs(created_at);
CREATE INDEX idx_jobs_priority_status ON jobs(priority, status);

CREATE INDEX idx_documents_job_id ON documents(job_id);
CREATE INDEX idx_documents_medical_content_type ON documents(medical_content_type);
CREATE INDEX idx_documents_processing_status ON documents(processing_status);
CREATE INDEX idx_documents_content_hash ON documents(content_hash);

CREATE INDEX idx_document_chunks_document_id ON document_chunks(document_id);
CREATE INDEX idx_document_chunks_medical_terms ON document_chunks USING GIN(medical_terms);
CREATE INDEX idx_document_chunks_content_search ON document_chunks USING GIN(content gin_trgm_ops);

CREATE INDEX idx_medical_terms_term ON medical_terms(term);
CREATE INDEX idx_medical_terms_umls_cui ON medical_terms(umls_cui);
CREATE INDEX idx_medical_terms_category ON medical_terms(category);
CREATE INDEX idx_medical_terms_frequency ON medical_terms(frequency_count DESC);

CREATE INDEX idx_repositories_medical_focus ON repositories(medical_focus);
CREATE INDEX idx_repositories_processing_status ON repositories(processing_status);

CREATE INDEX idx_service_health_service_name ON service_health(service_name);
CREATE INDEX idx_service_health_timestamp ON service_health(timestamp);
CREATE INDEX idx_service_health_status ON service_health(health_status);

CREATE INDEX idx_test_metrics_test_run ON test_metrics(test_run_id);
CREATE INDEX idx_test_metrics_timestamp ON test_metrics(timestamp);

CREATE INDEX idx_medical_accuracy_score ON medical_accuracy_logs(accuracy_score);
CREATE INDEX idx_medical_accuracy_timestamp ON medical_accuracy_logs(validated_at);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

CREATE TRIGGER update_jobs_updated_at BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_medical_terms_updated_at BEFORE UPDATE ON medical_terms
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_repositories_updated_at BEFORE UPDATE ON repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_processor_configs_updated_at BEFORE UPDATE ON processor_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default processor configurations for E2E testing
INSERT INTO processor_configs (processor_type, config_name, config_data, medical_specialty) VALUES
('nursing-content', 'e2e_nursing_comprehensive', '{
    "chunking_strategy": "clinical",
    "chunk_size": 1000,
    "overlap_size": 200,
    "preserve_medical_terms": true,
    "detect_drug_names": true,
    "extract_vital_signs": true,
    "extract_tables": true,
    "enable_medical_nlp": true,
    "medical_accuracy_threshold": 0.98,
    "max_concurrent_sources": 8
}', 'nursing'),

('document-processor', 'e2e_medical_documents', '{
    "supported_formats": ["pdf", "docx", "txt", "html"],
    "ocr_enabled": true,
    "table_extraction": true,
    "image_description": true,
    "medical_term_highlighting": true,
    "quality_threshold": 0.95
}', 'general'),

('vector-storage', 'e2e_medical_embeddings', '{
    "embedding_model": "all-MiniLM-L6-v2",
    "vector_dimension": 384,
    "similarity_threshold": 0.7,
    "batch_size": 100,
    "collection_name": "medical_content_e2e"
}', 'medical');

-- Insert test repository configurations
INSERT INTO repositories (url, name, description, medical_focus, processing_config) VALUES
('https://github.com/nursing-education/comprehensive-textbooks', 'Nursing Education Comprehensive', 'Complete nursing education materials for E2E testing', 'nursing', '{
    "include_patterns": ["*.pdf", "*.docx", "*.md"],
    "exclude_patterns": [".*", "node_modules/*", "*.log"],
    "max_file_size_mb": 200,
    "enable_ocr": true,
    "medical_validation": true
}'),

('https://github.com/medical-terminology/umls-integration', 'UMLS Integration Test Content', 'Medical terminology test content for UMLS validation', 'medical_terminology', '{
    "focus_on_terminology": true,
    "umls_validation": true,
    "concept_mapping": true,
    "accuracy_threshold": 0.98
}'),

('onedrive://nursing-content-e2e', 'OneDrive Nursing Content E2E', 'OneDrive integration test content', 'nursing', '{
    "sync_frequency": "hourly",
    "safety_protocols": true,
    "backup_before_processing": true,
    "paranoid_mode": true
}');

-- Create views for common E2E test queries
CREATE VIEW v_active_jobs AS
SELECT
    j.*,
    COUNT(d.id) as document_count,
    AVG(mal.accuracy_score) as avg_medical_accuracy
FROM jobs j
LEFT JOIN documents d ON j.id = d.job_id
LEFT JOIN medical_accuracy_logs mal ON d.id = mal.document_id
WHERE j.status IN ('pending', 'running', 'processing')
GROUP BY j.id;

CREATE VIEW v_medical_term_statistics AS
SELECT
    category,
    COUNT(*) as term_count,
    AVG(confidence_score) as avg_confidence,
    SUM(frequency_count) as total_occurrences
FROM medical_terms
GROUP BY category
ORDER BY term_count DESC;

CREATE VIEW v_service_health_summary AS
SELECT
    service_name,
    health_status,
    AVG(response_time_ms) as avg_response_time,
    AVG(cpu_usage_percent) as avg_cpu_usage,
    AVG(memory_usage_percent) as avg_memory_usage,
    COUNT(*) as health_check_count,
    MAX(timestamp) as last_check
FROM service_health
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY service_name, health_status
ORDER BY service_name, last_check DESC;

-- Grant permissions for E2E testing
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO e2e_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO e2e_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO e2e_user;

COMMENT ON DATABASE ragnostic_e2e IS 'RAGnostic E2E testing database with medical content focus and comprehensive performance monitoring';
