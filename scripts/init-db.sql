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

-- Insert AACN Competency Domains
INSERT INTO analytics.aacn_competencies (domain, competency_name, description, minimum_level, weight) VALUES
    ('knowledge_for_nursing_practice', 'Knowledge for Nursing Practice', 'Integrate knowledge from nursing science, liberal education, and health sciences to inform evidence-based practice', 'competent', 1.2),
    ('person_centered_care', 'Person-Centered Care', 'Provide person-centered care that is culturally responsive, developmentally appropriate, and holistic', 'proficient', 1.3),
    ('population_health', 'Population Health', 'Engage with individuals, families, communities, and populations to improve health outcomes and reduce health disparities', 'competent', 1.0),
    ('scholarship_for_nursing_discipline', 'Scholarship for the Nursing Discipline', 'Demonstrate professional identity through scholarship, service, and engagement in professional organizations', 'competent', 0.9),
    ('information_technology', 'Information and Healthcare Technologies', 'Use information and healthcare technologies ethically and effectively to communicate, manage knowledge, mitigate error, and support decision making', 'competent', 0.8),
    ('healthcare_systems', 'Healthcare Systems and Safety', 'Apply knowledge of healthcare systems, policies, and financing to optimize healthcare outcomes and patient safety', 'competent', 1.1),
    ('interprofessional_partnerships', 'Interprofessional Partnerships', 'Collaborate effectively within nursing and interprofessional teams to optimize patient/population outcomes', 'competent', 1.0),
    ('personal_professional_development', 'Personal, Professional, and Leadership Development', 'Demonstrate accountability to the public, profession, and self through continuous personal and professional development', 'competent', 0.8)
ON CONFLICT DO NOTHING;

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

-- B.4 Learning Analytics Schema

-- Student profiles for competency tracking
CREATE TABLE IF NOT EXISTS analytics.student_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) UNIQUE NOT NULL,
    program VARCHAR(50) NOT NULL DEFAULT 'BSN',
    semester INTEGER NOT NULL DEFAULT 1,
    enrollment_date DATE,
    graduation_target_date DATE,
    overall_gpa NUMERIC(3,2),
    competency_gpa NUMERIC(3,2),
    graduation_readiness_score NUMERIC(5,2) DEFAULT 0.0,
    at_risk_status BOOLEAN DEFAULT FALSE,
    intervention_level VARCHAR(20) DEFAULT 'routine', -- routine, moderate, intensive
    learning_style_preferences JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- AACN Competency domains and definitions
CREATE TABLE IF NOT EXISTS analytics.aacn_competencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(100) NOT NULL,
    competency_name VARCHAR(200) NOT NULL,
    description TEXT,
    sub_competencies TEXT[],
    learning_outcomes TEXT[],
    assessment_methods TEXT[],
    prerequisites TEXT[],
    minimum_level VARCHAR(50) DEFAULT 'competent',
    weight NUMERIC(3,2) DEFAULT 1.0,
    umls_concepts TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Student competency assessments
CREATE TABLE IF NOT EXISTS analytics.competency_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    competency_id UUID REFERENCES analytics.aacn_competencies(id),
    assessment_id VARCHAR(100),
    current_level VARCHAR(50) NOT NULL, -- novice, advanced_beginner, competent, proficient, expert
    target_level VARCHAR(50) NOT NULL,
    proficiency_score NUMERIC(5,2) NOT NULL,
    evidence_items TEXT[],
    strengths TEXT[],
    improvement_areas TEXT[],
    recommended_resources TEXT[],
    assessment_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assessor_id VARCHAR(100),
    confidence_score NUMERIC(3,2) DEFAULT 0.0,
    next_assessment_due TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Knowledge gaps tracking
CREATE TABLE IF NOT EXISTS analytics.knowledge_gaps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    competency_id UUID REFERENCES analytics.aacn_competencies(id),
    gap_topic VARCHAR(200) NOT NULL,
    domain VARCHAR(100) NOT NULL,
    gap_type VARCHAR(50) DEFAULT 'knowledge', -- knowledge, skill, attitude
    severity VARCHAR(20) NOT NULL, -- critical, major, moderate, minor
    priority VARCHAR(20) NOT NULL, -- high, medium, low
    current_score NUMERIC(5,2),
    target_score NUMERIC(5,2),
    gap_size NUMERIC(5,2),
    description TEXT,
    evidence TEXT[],
    prerequisite_gaps TEXT[],
    recommended_interventions TEXT[],
    estimated_remediation_hours INTEGER DEFAULT 0,
    priority_score NUMERIC(5,2) DEFAULT 0.0,
    identified_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    target_resolution_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'identified', -- identified, in_progress, resolved
    resolved_date TIMESTAMP WITH TIME ZONE
);

-- Learning path recommendations
CREATE TABLE IF NOT EXISTS analytics.learning_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    path_name VARCHAR(200) NOT NULL,
    target_competencies TEXT[],
    current_proficiency JSONB,
    target_proficiency JSONB,
    recommended_sequence JSONB,
    estimated_duration_hours INTEGER DEFAULT 0,
    difficulty_progression VARCHAR(50) DEFAULT 'adaptive', -- linear, adaptive, accelerated
    personalization_factors JSONB,
    success_probability NUMERIC(3,2) DEFAULT 0.0,
    alternative_paths TEXT[],
    status VARCHAR(20) DEFAULT 'active', -- active, paused, completed, cancelled
    progress_percentage NUMERIC(5,2) DEFAULT 0.0,
    created_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_date TIMESTAMP WITH TIME ZONE
);

-- Student learning activities tracking
CREATE TABLE IF NOT EXISTS analytics.learning_activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    activity_type VARCHAR(100) NOT NULL, -- study, assessment, simulation, clinical
    activity_name VARCHAR(200),
    content_id VARCHAR(100),
    competency_ids TEXT[],
    duration_minutes INTEGER,
    score NUMERIC(5,2),
    completion_status VARCHAR(20) DEFAULT 'in_progress', -- in_progress, completed, abandoned
    difficulty_rating INTEGER, -- 1-5 scale
    effectiveness_rating INTEGER, -- 1-5 scale
    engagement_score NUMERIC(5,2),
    learning_objectives_met TEXT[],
    session_id VARCHAR(100),
    platform VARCHAR(50) DEFAULT 'web',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);

-- Institutional program effectiveness
CREATE TABLE IF NOT EXISTS analytics.program_effectiveness (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id VARCHAR(100) DEFAULT 'default',
    program_id VARCHAR(100) NOT NULL,
    program_name VARCHAR(200) NOT NULL,
    reporting_period VARCHAR(50) NOT NULL, -- e.g., '2024_Q1', 'AY2023-2024'
    total_students INTEGER DEFAULT 0,
    total_graduates INTEGER DEFAULT 0,
    nclex_pass_rate NUMERIC(5,2) DEFAULT 0.0,
    employment_rate NUMERIC(5,2) DEFAULT 0.0,
    employer_satisfaction NUMERIC(3,2) DEFAULT 0.0,
    competency_achievement_rates JSONB, -- per AACN domain
    curriculum_alignment_score NUMERIC(5,2) DEFAULT 0.0,
    student_satisfaction NUMERIC(3,2) DEFAULT 0.0,
    faculty_student_ratio NUMERIC(4,2) DEFAULT 0.0,
    resource_utilization JSONB,
    improvement_recommendations TEXT[],
    accreditation_compliance JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cohort analytics tracking
CREATE TABLE IF NOT EXISTS analytics.cohort_analytics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cohort_id VARCHAR(100) NOT NULL,
    program VARCHAR(50) NOT NULL,
    semester INTEGER NOT NULL,
    academic_year VARCHAR(10) NOT NULL,
    total_students INTEGER DEFAULT 0,
    active_students INTEGER DEFAULT 0,
    average_competency_score NUMERIC(5,2) DEFAULT 0.0,
    competency_distribution JSONB,
    at_risk_students INTEGER DEFAULT 0,
    high_performers INTEGER DEFAULT 0,
    engagement_metrics JSONB,
    completion_rates JSONB,
    time_to_mastery JSONB,
    resource_effectiveness JSONB,
    comparison_to_historical JSONB,
    analysis_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Analytics query performance tracking
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

-- B.4 Learning Analytics Indexes
CREATE INDEX IF NOT EXISTS idx_student_profiles_student_id ON analytics.student_profiles(student_id);
CREATE INDEX IF NOT EXISTS idx_student_profiles_program ON analytics.student_profiles(program, semester);
CREATE INDEX IF NOT EXISTS idx_student_profiles_at_risk ON analytics.student_profiles(at_risk_status) WHERE at_risk_status = TRUE;

CREATE INDEX IF NOT EXISTS idx_competency_assessments_student ON analytics.competency_assessments(student_id);
CREATE INDEX IF NOT EXISTS idx_competency_assessments_competency ON analytics.competency_assessments(competency_id);
CREATE INDEX IF NOT EXISTS idx_competency_assessments_date ON analytics.competency_assessments(assessment_date);
CREATE INDEX IF NOT EXISTS idx_competency_assessments_level ON analytics.competency_assessments(current_level, target_level);

CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_student ON analytics.knowledge_gaps(student_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_severity ON analytics.knowledge_gaps(severity, priority);
CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_domain ON analytics.knowledge_gaps(domain);
CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_status ON analytics.knowledge_gaps(status);
CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_date ON analytics.knowledge_gaps(identified_date);

CREATE INDEX IF NOT EXISTS idx_learning_paths_student ON analytics.learning_paths(student_id);
CREATE INDEX IF NOT EXISTS idx_learning_paths_status ON analytics.learning_paths(status);
CREATE INDEX IF NOT EXISTS idx_learning_paths_created ON analytics.learning_paths(created_date);

CREATE INDEX IF NOT EXISTS idx_learning_activities_student ON analytics.learning_activities(student_id);
CREATE INDEX IF NOT EXISTS idx_learning_activities_type ON analytics.learning_activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_learning_activities_date ON analytics.learning_activities(started_at);
CREATE INDEX IF NOT EXISTS idx_learning_activities_completion ON analytics.learning_activities(completion_status);
CREATE INDEX IF NOT EXISTS idx_learning_activities_competency ON analytics.learning_activities USING gin(competency_ids);

CREATE INDEX IF NOT EXISTS idx_program_effectiveness_program ON analytics.program_effectiveness(program_id);
CREATE INDEX IF NOT EXISTS idx_program_effectiveness_period ON analytics.program_effectiveness(reporting_period);
CREATE INDEX IF NOT EXISTS idx_program_effectiveness_institution ON analytics.program_effectiveness(institution_id);

CREATE INDEX IF NOT EXISTS idx_cohort_analytics_cohort ON analytics.cohort_analytics(cohort_id);
CREATE INDEX IF NOT EXISTS idx_cohort_analytics_program ON analytics.cohort_analytics(program, semester);
CREATE INDEX IF NOT EXISTS idx_cohort_analytics_year ON analytics.cohort_analytics(academic_year);

-- Query performance indexes
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

-- B.4 Learning Analytics Views

-- Student competency summary view
CREATE OR REPLACE VIEW analytics.student_competency_summary AS
SELECT
    sp.student_id,
    sp.program,
    sp.semester,
    sp.competency_gpa,
    sp.graduation_readiness_score,
    sp.at_risk_status,
    COUNT(ca.id) as total_assessments,
    AVG(ca.proficiency_score) as avg_proficiency_score,
    COUNT(kg.id) as total_knowledge_gaps,
    COUNT(kg.id) FILTER (WHERE kg.severity = 'critical') as critical_gaps,
    COUNT(kg.id) FILTER (WHERE kg.severity = 'major') as major_gaps,
    MAX(ca.assessment_date) as last_assessment_date
FROM analytics.student_profiles sp
LEFT JOIN analytics.competency_assessments ca ON sp.student_id = ca.student_id
LEFT JOIN analytics.knowledge_gaps kg ON sp.student_id = kg.student_id AND kg.status != 'resolved'
WHERE sp.is_active = TRUE
GROUP BY sp.student_id, sp.program, sp.semester, sp.competency_gpa, sp.graduation_readiness_score, sp.at_risk_status;

-- Domain competency performance view
CREATE OR REPLACE VIEW analytics.domain_competency_performance AS
SELECT
    ac.domain,
    ac.competency_name,
    COUNT(ca.id) as total_assessments,
    AVG(ca.proficiency_score) as avg_proficiency_score,
    COUNT(ca.id) FILTER (WHERE ca.current_level = 'expert') as expert_count,
    COUNT(ca.id) FILTER (WHERE ca.current_level = 'proficient') as proficient_count,
    COUNT(ca.id) FILTER (WHERE ca.current_level = 'competent') as competent_count,
    COUNT(ca.id) FILTER (WHERE ca.current_level = 'advanced_beginner') as advanced_beginner_count,
    COUNT(ca.id) FILTER (WHERE ca.current_level = 'novice') as novice_count,
    COUNT(kg.id) as related_knowledge_gaps,
    DATE_TRUNC('month', ca.assessment_date) as assessment_month
FROM analytics.aacn_competencies ac
LEFT JOIN analytics.competency_assessments ca ON ac.id = ca.competency_id
LEFT JOIN analytics.knowledge_gaps kg ON ac.domain = kg.domain AND kg.status != 'resolved'
WHERE ac.is_active = TRUE
GROUP BY ac.domain, ac.competency_name, DATE_TRUNC('month', ca.assessment_date)
ORDER BY assessment_month DESC, avg_proficiency_score DESC;

-- Learning activity effectiveness view
CREATE OR REPLACE VIEW analytics.learning_activity_effectiveness AS
SELECT
    la.activity_type,
    COUNT(la.id) as total_activities,
    AVG(la.duration_minutes) as avg_duration,
    AVG(la.score) as avg_score,
    AVG(la.effectiveness_rating) as avg_effectiveness,
    AVG(la.engagement_score) as avg_engagement,
    COUNT(la.id) FILTER (WHERE la.completion_status = 'completed') as completed_count,
    COUNT(la.id) FILTER (WHERE la.completion_status = 'abandoned') as abandoned_count,
    DATE_TRUNC('week', la.started_at) as activity_week
FROM analytics.learning_activities la
WHERE la.started_at >= NOW() - INTERVAL '12 weeks'
GROUP BY la.activity_type, DATE_TRUNC('week', la.started_at)
ORDER BY activity_week DESC, avg_effectiveness DESC;

-- At-risk students identification view
CREATE OR REPLACE VIEW analytics.at_risk_students AS
SELECT
    sp.student_id,
    sp.program,
    sp.semester,
    sp.competency_gpa,
    sp.graduation_readiness_score,
    sp.intervention_level,
    COUNT(kg.id) FILTER (WHERE kg.severity = 'critical') as critical_gaps,
    COUNT(kg.id) FILTER (WHERE kg.severity = 'major') as major_gaps,
    AVG(ca.proficiency_score) as avg_competency_score,
    COUNT(la.id) FILTER (WHERE la.started_at >= NOW() - INTERVAL '4 weeks') as recent_activities,
    AVG(la.engagement_score) as avg_engagement,
    CASE
        WHEN COUNT(kg.id) FILTER (WHERE kg.severity = 'critical') > 2 THEN 'high'
        WHEN COUNT(kg.id) FILTER (WHERE kg.severity IN ('critical', 'major')) > 3 THEN 'medium'
        WHEN sp.competency_gpa < 2.5 THEN 'medium'
        WHEN AVG(la.engagement_score) < 50 THEN 'low'
        ELSE 'low'
    END as calculated_risk_level
FROM analytics.student_profiles sp
LEFT JOIN analytics.knowledge_gaps kg ON sp.student_id = kg.student_id AND kg.status != 'resolved'
LEFT JOIN analytics.competency_assessments ca ON sp.student_id = ca.student_id
LEFT JOIN analytics.learning_activities la ON sp.student_id = la.student_id
WHERE sp.is_active = TRUE
GROUP BY sp.student_id, sp.program, sp.semester, sp.competency_gpa, sp.graduation_readiness_score, sp.intervention_level
HAVING COUNT(kg.id) FILTER (WHERE kg.severity IN ('critical', 'major')) > 0 OR sp.competency_gpa < 3.0;

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

-- B.4 Learning Analytics Functions

-- Function to calculate student competency GPA
CREATE OR REPLACE FUNCTION analytics.calculate_student_competency_gpa(student_id_param VARCHAR(100))
RETURNS NUMERIC(3,2) AS $$
DECLARE
    gpa_result NUMERIC(3,2);
BEGIN
    SELECT
        COALESCE(AVG(
            CASE
                WHEN ca.current_level = 'expert' THEN 4.0
                WHEN ca.current_level = 'proficient' THEN 3.5
                WHEN ca.current_level = 'competent' THEN 3.0
                WHEN ca.current_level = 'advanced_beginner' THEN 2.0
                ELSE 1.0
            END * ac.weight
        ), 0.0)
    INTO gpa_result
    FROM analytics.competency_assessments ca
    JOIN analytics.aacn_competencies ac ON ca.competency_id = ac.id
    WHERE ca.student_id = student_id_param;

    RETURN ROUND(gpa_result, 2);
END;
$$ LANGUAGE plpgsql;

-- Function to identify knowledge gaps for a student
CREATE OR REPLACE FUNCTION analytics.identify_student_knowledge_gaps(
    student_id_param VARCHAR(100),
    severity_threshold VARCHAR(20) DEFAULT 'moderate'
)
RETURNS TABLE(
    gap_topic VARCHAR(200),
    domain VARCHAR(100),
    severity VARCHAR(20),
    gap_size NUMERIC(5,2),
    estimated_hours INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        kg.gap_topic,
        kg.domain,
        kg.severity,
        kg.gap_size,
        kg.estimated_remediation_hours
    FROM analytics.knowledge_gaps kg
    WHERE
        kg.student_id = student_id_param
        AND kg.status != 'resolved'
        AND (
            (severity_threshold = 'critical' AND kg.severity = 'critical')
            OR (severity_threshold = 'major' AND kg.severity IN ('critical', 'major'))
            OR (severity_threshold = 'moderate' AND kg.severity IN ('critical', 'major', 'moderate'))
            OR (severity_threshold = 'minor')
        )
    ORDER BY
        CASE kg.severity
            WHEN 'critical' THEN 4
            WHEN 'major' THEN 3
            WHEN 'moderate' THEN 2
            ELSE 1
        END DESC,
        kg.gap_size DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate graduation readiness score
CREATE OR REPLACE FUNCTION analytics.calculate_graduation_readiness(student_id_param VARCHAR(100))
RETURNS NUMERIC(5,2) AS $$
DECLARE
    competency_score NUMERIC(5,2) := 0;
    gap_penalty NUMERIC(5,2) := 0;
    engagement_score NUMERIC(5,2) := 0;
    readiness_score NUMERIC(5,2);
BEGIN
    -- Calculate competency score (0-40 points)
    SELECT COALESCE(AVG(ca.proficiency_score) * 0.4, 0)
    INTO competency_score
    FROM analytics.competency_assessments ca
    WHERE ca.student_id = student_id_param;

    -- Calculate gap penalty (subtract up to 20 points)
    SELECT COALESCE(
        (COUNT(*) FILTER (WHERE severity = 'critical') * 5 +
         COUNT(*) FILTER (WHERE severity = 'major') * 3 +
         COUNT(*) FILTER (WHERE severity = 'moderate') * 1), 0
    )
    INTO gap_penalty
    FROM analytics.knowledge_gaps
    WHERE student_id = student_id_param AND status != 'resolved';

    gap_penalty := LEAST(gap_penalty, 20); -- Cap at 20 points

    -- Calculate engagement score (0-20 points)
    SELECT COALESCE(AVG(la.engagement_score) * 0.2, 0)
    INTO engagement_score
    FROM analytics.learning_activities la
    WHERE la.student_id = student_id_param
        AND la.started_at >= NOW() - INTERVAL '8 weeks';

    -- Calculate final readiness score
    readiness_score := competency_score - gap_penalty + engagement_score + 40; -- Base 40 points
    readiness_score := GREATEST(0, LEAST(100, readiness_score)); -- Clamp to 0-100

    RETURN ROUND(readiness_score, 2);
END;
$$ LANGUAGE plpgsql;

-- Function to track student progress over time
CREATE OR REPLACE FUNCTION analytics.track_student_progress(
    student_id_param VARCHAR(100),
    weeks_back INTEGER DEFAULT 12
)
RETURNS TABLE(
    week_start DATE,
    avg_competency_score NUMERIC(5,2),
    knowledge_gaps_count INTEGER,
    learning_activities_count INTEGER,
    engagement_score NUMERIC(5,2)
) AS $$
BEGIN
    RETURN QUERY
    WITH weekly_data AS (
        SELECT
            DATE_TRUNC('week', generate_series(
                CURRENT_DATE - (weeks_back * INTERVAL '1 week'),
                CURRENT_DATE,
                '1 week'::interval
            ))::DATE as week_start
    )
    SELECT
        wd.week_start,
        COALESCE(AVG(ca.proficiency_score), 0)::NUMERIC(5,2) as avg_competency_score,
        COUNT(DISTINCT kg.id)::INTEGER as knowledge_gaps_count,
        COUNT(DISTINCT la.id)::INTEGER as learning_activities_count,
        COALESCE(AVG(la.engagement_score), 0)::NUMERIC(5,2) as engagement_score
    FROM weekly_data wd
    LEFT JOIN analytics.competency_assessments ca ON
        ca.student_id = student_id_param AND
        DATE_TRUNC('week', ca.assessment_date) = wd.week_start
    LEFT JOIN analytics.knowledge_gaps kg ON
        kg.student_id = student_id_param AND
        DATE_TRUNC('week', kg.identified_date) <= wd.week_start AND
        (kg.resolved_date IS NULL OR DATE_TRUNC('week', kg.resolved_date) > wd.week_start)
    LEFT JOIN analytics.learning_activities la ON
        la.student_id = student_id_param AND
        DATE_TRUNC('week', la.started_at) = wd.week_start
    GROUP BY wd.week_start
    ORDER BY wd.week_start;
END;
$$ LANGUAGE plpgsql;

-- Function to update student profile automatically
CREATE OR REPLACE FUNCTION analytics.update_student_profile_metrics()
RETURNS TRIGGER AS $$
BEGIN
    -- Update competency GPA and graduation readiness when assessments change
    UPDATE analytics.student_profiles
    SET
        competency_gpa = analytics.calculate_student_competency_gpa(NEW.student_id),
        graduation_readiness_score = analytics.calculate_graduation_readiness(NEW.student_id),
        updated_at = NOW(),
        at_risk_status = (
            analytics.calculate_graduation_readiness(NEW.student_id) < 60 OR
            EXISTS(
                SELECT 1 FROM analytics.knowledge_gaps kg
                WHERE kg.student_id = NEW.student_id
                    AND kg.severity = 'critical'
                    AND kg.status != 'resolved'
            )
        )
    WHERE student_id = NEW.student_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers to maintain student profile metrics
DROP TRIGGER IF EXISTS update_profile_on_assessment ON analytics.competency_assessments;
CREATE TRIGGER update_profile_on_assessment
    AFTER INSERT OR UPDATE ON analytics.competency_assessments
    FOR EACH ROW
    EXECUTE FUNCTION analytics.update_student_profile_metrics();

DROP TRIGGER IF EXISTS update_profile_on_gap_change ON analytics.knowledge_gaps;
CREATE TRIGGER update_profile_on_gap_change
    AFTER INSERT OR UPDATE ON analytics.knowledge_gaps
    FOR EACH ROW
    EXECUTE FUNCTION analytics.update_student_profile_metrics();

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA knowledge TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA knowledge TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO bsn_knowledge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO bsn_knowledge;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA analytics TO bsn_knowledge;

-- Final setup message
DO $$
BEGIN
    RAISE NOTICE 'BSN Knowledge Base database initialization completed successfully';
    RAISE NOTICE 'Schemas created: knowledge, analytics, audit';
    RAISE NOTICE 'Core tables: medical_terms_metadata, medical_categories, relationship_types';
    RAISE NOTICE 'B.4 Learning Analytics tables: student_profiles, competency_assessments, knowledge_gaps, learning_paths';
    RAISE NOTICE 'Analytics views: student_competency_summary, domain_competency_performance, at_risk_students';
    RAISE NOTICE 'Learning analytics functions: calculate_graduation_readiness, identify_knowledge_gaps';
    RAISE NOTICE 'Performance monitoring and audit logging enabled';
    RAISE NOTICE 'B.4 Learning Analytics & Reporting system ready for deployment';
END $$;
