-- BSN Knowledge E2E Test Database Initialization
-- Sets up test data and schema for comprehensive pipeline validation

-- Create test schema extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Test user profiles for E2E testing
CREATE TABLE IF NOT EXISTS test_users (
    id SERIAL PRIMARY KEY,
    student_id VARCHAR(100) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) DEFAULT 'student',
    competency_level VARCHAR(50) DEFAULT 'beginner',
    preferred_topics TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Test content for pipeline validation
CREATE TABLE IF NOT EXISTS test_content (
    id SERIAL PRIMARY KEY,
    content_id UUID DEFAULT uuid_generate_v4(),
    topic VARCHAR(100) NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    content_text TEXT NOT NULL,
    umls_concepts JSONB,
    difficulty_level VARCHAR(50),
    nclex_categories TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Test learning activities tracking
CREATE TABLE IF NOT EXISTS test_activities (
    id SERIAL PRIMARY KEY,
    activity_id UUID DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    content_id UUID REFERENCES test_content(content_id),
    activity_type VARCHAR(100) NOT NULL,
    time_spent_minutes INTEGER,
    completion_status VARCHAR(50),
    performance_score DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Test assessments and results
CREATE TABLE IF NOT EXISTS test_assessments (
    id SERIAL PRIMARY KEY,
    assessment_id UUID DEFAULT uuid_generate_v4(),
    student_id VARCHAR(100) NOT NULL,
    assessment_type VARCHAR(100) NOT NULL,
    questions JSONB NOT NULL,
    responses JSONB,
    score DECIMAL(5,2),
    max_score DECIMAL(5,2),
    completion_time_seconds INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users for E2E scenarios
INSERT INTO test_users (student_id, username, email, role, competency_level, preferred_topics) VALUES
('student_001', 'test_student_001', 'student001@test.edu', 'student', 'intermediate', '{"cardiovascular","pharmacology"}'),
('student_002', 'test_student_002', 'student002@test.edu', 'student', 'beginner', '{"respiratory","infection_control"}'),
('instructor_001', 'test_instructor_001', 'instructor001@test.edu', 'instructor', 'advanced', '{"clinical_reasoning","patient_safety"}'),
('admin_001', 'test_admin_001', 'admin001@test.edu', 'admin', 'expert', '{"curriculum_development","assessment_analytics"}');

-- Insert test content for pipeline validation
INSERT INTO test_content (topic, content_type, content_text, umls_concepts, difficulty_level, nclex_categories) VALUES
('cardiovascular_assessment', 'educational_content',
 'Cardiovascular assessment is a critical nursing skill involving systematic evaluation of heart function, circulation, and related symptoms. Key components include vital signs, heart sounds, peripheral pulses, and signs of perfusion.',
 '{"concepts": [{"cui": "C0007226", "name": "Cardiovascular System"}, {"cui": "C0018787", "name": "Heart"}, {"cui": "C0232337", "name": "Cardiovascular Assessment"}]}',
 'intermediate',
 '{"Health Promotion and Maintenance", "Physiological Integrity"}'),
('medication_administration', 'educational_content',
 'Safe medication administration follows the six rights: right patient, right drug, right dose, right route, right time, and right documentation. Nurses must verify orders, check for allergies, and monitor for adverse reactions.',
 '{"concepts": [{"cui": "C0013227", "name": "Drug Administration"}, {"cui": "C0150270", "name": "Medication Safety"}, {"cui": "C0013230", "name": "Drug Therapy"}]}',
 'beginner',
 '{"Safe and Effective Care Environment"}'),
('infection_control', 'educational_content',
 'Infection prevention and control measures are essential for patient safety. Standard precautions include hand hygiene, personal protective equipment, safe injection practices, and environmental cleaning.',
 '{"concepts": [{"cui": "C0085557", "name": "Infection Control"}, {"cui": "C1292711", "name": "Hand Hygiene"}, {"cui": "C0009482", "name": "Communicable Disease Control"}]}',
 'intermediate',
 '{"Safe and Effective Care Environment"}');

-- Insert sample test activities
INSERT INTO test_activities (student_id, content_id, activity_type, time_spent_minutes, completion_status, performance_score) VALUES
('student_001', (SELECT content_id FROM test_content WHERE topic = 'cardiovascular_assessment' LIMIT 1), 'content_review', 45, 'completed', 87.5),
('student_001', (SELECT content_id FROM test_content WHERE topic = 'medication_administration' LIMIT 1), 'quiz', 25, 'completed', 92.0),
('student_002', (SELECT content_id FROM test_content WHERE topic = 'infection_control' LIMIT 1), 'content_review', 30, 'in_progress', NULL);

-- Insert sample assessments
INSERT INTO test_assessments (student_id, assessment_type, questions, responses, score, max_score, completion_time_seconds) VALUES
('student_001', 'nclex_practice',
 '{"questions": [{"id": "q1", "question": "Which assessment finding indicates digoxin toxicity?", "options": ["A. Heart rate 88 bpm", "B. Nausea and visual disturbances", "C. Blood pressure 130/80", "D. Respiratory rate 18"], "correct": "B"}]}',
 '{"responses": [{"question_id": "q1", "selected": "B", "correct": true, "time_seconds": 45}]}',
 100.0, 100.0, 45);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_test_users_student_id ON test_users(student_id);
CREATE INDEX IF NOT EXISTS idx_test_content_topic ON test_content(topic);
CREATE INDEX IF NOT EXISTS idx_test_activities_student_id ON test_activities(student_id);
CREATE INDEX IF NOT EXISTS idx_test_activities_content_id ON test_activities(content_id);
CREATE INDEX IF NOT EXISTS idx_test_assessments_student_id ON test_assessments(student_id);
CREATE INDEX IF NOT EXISTS idx_test_content_umls_concepts ON test_content USING GIN(umls_concepts);

-- Create views for test data analysis
CREATE OR REPLACE VIEW test_student_performance AS
SELECT
    u.student_id,
    u.username,
    u.competency_level,
    COUNT(a.id) as total_activities,
    AVG(a.performance_score) as avg_performance_score,
    SUM(a.time_spent_minutes) as total_time_minutes
FROM test_users u
LEFT JOIN test_activities a ON u.student_id = a.student_id
WHERE u.role = 'student'
GROUP BY u.student_id, u.username, u.competency_level;

CREATE OR REPLACE VIEW test_content_usage AS
SELECT
    c.topic,
    c.content_type,
    c.difficulty_level,
    COUNT(a.id) as usage_count,
    AVG(a.performance_score) as avg_score,
    AVG(a.time_spent_minutes) as avg_time_minutes
FROM test_content c
LEFT JOIN test_activities a ON c.content_id = a.content_id
GROUP BY c.topic, c.content_type, c.difficulty_level;

-- Performance monitoring functions
CREATE OR REPLACE FUNCTION get_test_database_stats()
RETURNS TABLE(
    table_name TEXT,
    row_count BIGINT,
    table_size TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        schemaname||'.'||tablename as table_name,
        n_tup_ins - n_tup_del as row_count,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as table_size
    FROM pg_stat_user_tables
    WHERE schemaname = 'public' AND tablename LIKE 'test_%'
    ORDER BY n_tup_ins - n_tup_del DESC;
END;
$$ LANGUAGE plpgsql;

-- Test data validation function
CREATE OR REPLACE FUNCTION validate_test_data()
RETURNS TABLE(
    validation_check TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- Check test users exist
    RETURN QUERY
    SELECT
        'test_users_count'::TEXT,
        CASE WHEN COUNT(*) >= 4 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Found ' || COUNT(*)::TEXT || ' test users'::TEXT
    FROM test_users;

    -- Check test content exists
    RETURN QUERY
    SELECT
        'test_content_count'::TEXT,
        CASE WHEN COUNT(*) >= 3 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Found ' || COUNT(*)::TEXT || ' test content items'::TEXT
    FROM test_content;

    -- Check UMLS concepts are valid JSON
    RETURN QUERY
    SELECT
        'umls_concepts_valid'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Found ' || COUNT(*)::TEXT || ' invalid UMLS concept records'::TEXT
    FROM test_content
    WHERE umls_concepts IS NULL OR NOT (umls_concepts ? 'concepts');

    -- Check foreign key relationships
    RETURN QUERY
    SELECT
        'activity_content_relationships'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Found ' || COUNT(*)::TEXT || ' orphaned activity records'::TEXT
    FROM test_activities a
    LEFT JOIN test_content c ON a.content_id = c.content_id
    WHERE c.content_id IS NULL AND a.content_id IS NOT NULL;
END;
$$ LANGUAGE plpgsql;

-- Initialize test database statistics
ANALYZE;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'BSN Knowledge E2E test database initialized successfully';
    RAISE NOTICE 'Test users: %', (SELECT COUNT(*) FROM test_users);
    RAISE NOTICE 'Test content: %', (SELECT COUNT(*) FROM test_content);
    RAISE NOTICE 'Test activities: %', (SELECT COUNT(*) FROM test_activities);
END
$$;
