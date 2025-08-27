-- BSN Knowledge E2E Database Schema
-- Educational platform optimized for nursing education and NCLEX preparation

\c bsn_knowledge_e2e;

-- Create extensions for advanced functionality
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- User Management and Authentication
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'student', -- 'student', 'instructor', 'admin'
    nursing_program VARCHAR(100), -- 'adn', 'bsn', 'msn', 'dnp'
    graduation_year INTEGER,
    nclex_taken BOOLEAN DEFAULT false,
    nclex_pass_status VARCHAR(20), -- 'passed', 'failed', 'pending', 'not_taken'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Student Learning Profiles
CREATE TABLE student_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    learning_style VARCHAR(50), -- 'visual', 'auditory', 'kinesthetic', 'mixed'
    competency_level VARCHAR(50) DEFAULT 'beginner', -- 'beginner', 'intermediate', 'advanced'
    strengths TEXT[],
    weaknesses TEXT[],
    learning_goals TEXT[],
    current_focus_areas TEXT[], -- NCLEX categories
    study_hours_weekly INTEGER DEFAULT 0,
    preferred_difficulty VARCHAR(20) DEFAULT 'medium', -- 'easy', 'medium', 'hard', 'adaptive'
    performance_metrics JSONB DEFAULT '{}',
    adaptation_settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Educational Content Management
CREATE TABLE educational_content (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    content_type VARCHAR(100) NOT NULL, -- 'study_guide', 'quiz', 'nclex_question', 'simulation'
    subject_area VARCHAR(100) NOT NULL, -- 'medical_surgical', 'pediatrics', 'maternity', etc.
    nclex_category VARCHAR(100), -- NCLEX-RN test plan categories
    difficulty_level INTEGER DEFAULT 3, -- 1-5 scale
    learning_objectives TEXT[],
    content_body TEXT,
    multimedia_urls TEXT[],
    keywords TEXT[],
    medical_concepts TEXT[],
    umls_concepts TEXT[], -- UMLS concept mappings
    ragnostic_source_id UUID, -- Link to RAGnostic processed content
    source_metadata JSONB DEFAULT '{}',
    quality_score DECIMAL(5,4) DEFAULT 1.0,
    medical_accuracy DECIMAL(5,4) DEFAULT 1.0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,
    is_published BOOLEAN DEFAULT false
);

-- NCLEX Question Bank
CREATE TABLE nclex_questions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    question_text TEXT NOT NULL,
    question_type VARCHAR(50) DEFAULT 'multiple_choice', -- 'multiple_choice', 'select_all', 'fill_blank', 'drag_drop'
    options JSONB, -- Question options and answers
    correct_answer JSONB NOT NULL,
    rationale TEXT NOT NULL,
    difficulty_level INTEGER DEFAULT 3,
    nclex_category VARCHAR(100) NOT NULL,
    client_needs_category VARCHAR(100), -- Primary NCLEX client needs category
    client_needs_subcategory VARCHAR(100),
    cognitive_level VARCHAR(50), -- 'knowledge', 'comprehension', 'application', 'analysis'
    nursing_process_step VARCHAR(50), -- 'assessment', 'diagnosis', 'planning', 'implementation', 'evaluation'
    medical_concepts TEXT[],
    umls_mappings TEXT[],
    ragnostic_content_id UUID, -- Link to source RAGnostic content
    statistics JSONB DEFAULT '{"attempts": 0, "correct": 0, "average_time": 0}',
    tags TEXT[],
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Assessment and Quiz Management
CREATE TABLE assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(300) NOT NULL,
    description TEXT,
    assessment_type VARCHAR(50) DEFAULT 'practice', -- 'practice', 'proctored', 'adaptive', 'comprehensive'
    subject_areas TEXT[],
    question_count INTEGER NOT NULL,
    time_limit_minutes INTEGER,
    passing_score INTEGER DEFAULT 75,
    difficulty_range INTEGER[] DEFAULT '{1,5}',
    nclex_categories TEXT[],
    adaptive_settings JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_published BOOLEAN DEFAULT false
);

-- Assessment Question Mappings
CREATE TABLE assessment_questions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    question_id UUID REFERENCES nclex_questions(id) ON DELETE CASCADE,
    question_order INTEGER NOT NULL,
    points_possible INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(assessment_id, question_id)
);

-- User Assessment Attempts
CREATE TABLE assessment_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    attempt_number INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'in_progress', -- 'in_progress', 'completed', 'abandoned', 'timed_out'
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    time_taken_seconds INTEGER,
    score INTEGER,
    percentage_score DECIMAL(5,2),
    passed BOOLEAN,
    answers JSONB DEFAULT '{}', -- Question ID -> answer mapping
    detailed_results JSONB DEFAULT '{}',
    analytics_data JSONB DEFAULT '{}',
    adaptive_path JSONB DEFAULT '{}' -- For adaptive assessments
);

-- Individual Question Responses
CREATE TABLE question_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attempt_id UUID REFERENCES assessment_attempts(id) ON DELETE CASCADE,
    question_id UUID REFERENCES nclex_questions(id) ON DELETE CASCADE,
    user_answer JSONB NOT NULL,
    is_correct BOOLEAN NOT NULL,
    points_earned INTEGER DEFAULT 0,
    time_spent_seconds INTEGER,
    confidence_level INTEGER, -- 1-5 scale, user self-reported
    difficulty_perception INTEGER, -- 1-5 scale, user perception
    response_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rationale_viewed BOOLEAN DEFAULT false,
    marked_for_review BOOLEAN DEFAULT false
);

-- Learning Analytics and Progress Tracking
CREATE TABLE learning_progress (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    subject_area VARCHAR(100) NOT NULL,
    nclex_category VARCHAR(100),
    competency_score DECIMAL(5,4) DEFAULT 0.0,
    mastery_level VARCHAR(50) DEFAULT 'novice', -- 'novice', 'beginner', 'competent', 'proficient', 'expert'
    questions_attempted INTEGER DEFAULT 0,
    questions_correct INTEGER DEFAULT 0,
    avg_response_time DECIMAL(8,2),
    improvement_rate DECIMAL(5,4) DEFAULT 0.0,
    knowledge_gaps TEXT[],
    strength_areas TEXT[],
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, subject_area, nclex_category)
);

-- Adaptive Learning Engine Data
CREATE TABLE adaptive_learning_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_type VARCHAR(50) DEFAULT 'study', -- 'study', 'review', 'remediation', 'challenge'
    target_competencies TEXT[],
    difficulty_adjustments JSONB DEFAULT '{}',
    content_recommendations JSONB DEFAULT '{}',
    learning_path JSONB DEFAULT '{}',
    session_duration_seconds INTEGER,
    effectiveness_score DECIMAL(5,4),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Content Generation and RAGnostic Integration
CREATE TABLE content_generation_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    request_type VARCHAR(100) NOT NULL, -- 'nclex_questions', 'study_guide', 'quiz', 'flashcards'
    subject_area VARCHAR(100) NOT NULL,
    difficulty_level INTEGER DEFAULT 3,
    quantity_requested INTEGER DEFAULT 10,
    specific_topics TEXT[],
    ragnostic_job_id UUID, -- Reference to RAGnostic processing job
    generation_parameters JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
    generated_content_ids UUID[],
    quality_metrics JSONB DEFAULT '{}',
    error_message TEXT,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Clinical Decision Support Integration
CREATE TABLE clinical_scenarios (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(300) NOT NULL,
    scenario_text TEXT NOT NULL,
    patient_context JSONB NOT NULL, -- Demographics, medical history, current condition
    clinical_data JSONB, -- Vital signs, lab results, medications
    nursing_priorities TEXT[],
    learning_objectives TEXT[],
    difficulty_level INTEGER DEFAULT 3,
    nclex_categories TEXT[],
    cognitive_skills TEXT[], -- Clinical reasoning skills being assessed
    evidence_base TEXT[], -- Evidence-based practice references
    ragnostic_source_content UUID, -- Link to RAGnostic processed clinical content
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_published BOOLEAN DEFAULT false
);

-- Performance Analytics and Reporting
CREATE TABLE analytics_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(100), -- 'learning', 'assessment', 'content_interaction', 'system'
    event_data JSONB DEFAULT '{}',
    session_id VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- E2E Test Integration Tables
CREATE TABLE e2e_test_scenarios (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scenario_name VARCHAR(200) NOT NULL,
    test_category VARCHAR(100) NOT NULL, -- 'end_to_end', 'integration', 'performance', 'security', 'resilience'
    ragnostic_integration BOOLEAN DEFAULT true,
    test_parameters JSONB DEFAULT '{}',
    expected_outcomes JSONB DEFAULT '{}',
    performance_targets JSONB DEFAULT '{}',
    medical_accuracy_requirements JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE e2e_test_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    test_run_id VARCHAR(100) NOT NULL,
    scenario_id UUID REFERENCES e2e_test_scenarios(id),
    test_status VARCHAR(20) NOT NULL, -- 'passed', 'failed', 'error', 'timeout'
    execution_time_seconds DECIMAL(8,3),
    performance_metrics JSONB DEFAULT '{}',
    medical_accuracy_score DECIMAL(5,4),
    error_details JSONB,
    ragnostic_interaction_logs JSONB DEFAULT '{}',
    bsn_response_data JSONB DEFAULT '{}',
    assertions_passed INTEGER DEFAULT 0,
    assertions_total INTEGER DEFAULT 0,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create comprehensive indexes for performance optimization
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);

CREATE INDEX idx_student_profiles_user_id ON student_profiles(user_id);
CREATE INDEX idx_student_profiles_competency ON student_profiles(competency_level);

CREATE INDEX idx_educational_content_type ON educational_content(content_type);
CREATE INDEX idx_educational_content_subject ON educational_content(subject_area);
CREATE INDEX idx_educational_content_nclex_category ON educational_content(nclex_category);
CREATE INDEX idx_educational_content_published ON educational_content(is_published);
CREATE INDEX idx_educational_content_ragnostic ON educational_content(ragnostic_source_id);
CREATE INDEX idx_educational_content_search ON educational_content USING GIN(to_tsvector('english', title || ' ' || coalesce(content_body, '')));

CREATE INDEX idx_nclex_questions_category ON nclex_questions(nclex_category);
CREATE INDEX idx_nclex_questions_difficulty ON nclex_questions(difficulty_level);
CREATE INDEX idx_nclex_questions_active ON nclex_questions(is_active);
CREATE INDEX idx_nclex_questions_client_needs ON nclex_questions(client_needs_category);
CREATE INDEX idx_nclex_questions_ragnostic ON nclex_questions(ragnostic_content_id);
CREATE INDEX idx_nclex_questions_search ON nclex_questions USING GIN(to_tsvector('english', question_text));

CREATE INDEX idx_assessments_type ON assessments(assessment_type);
CREATE INDEX idx_assessments_published ON assessments(is_published);

CREATE INDEX idx_assessment_attempts_user ON assessment_attempts(user_id);
CREATE INDEX idx_assessment_attempts_assessment ON assessment_attempts(assessment_id);
CREATE INDEX idx_assessment_attempts_status ON assessment_attempts(status);
CREATE INDEX idx_assessment_attempts_completed ON assessment_attempts(completed_at);

CREATE INDEX idx_question_responses_attempt ON question_responses(attempt_id);
CREATE INDEX idx_question_responses_question ON question_responses(question_id);
CREATE INDEX idx_question_responses_correct ON question_responses(is_correct);

CREATE INDEX idx_learning_progress_user ON learning_progress(user_id);
CREATE INDEX idx_learning_progress_subject ON learning_progress(subject_area);
CREATE INDEX idx_learning_progress_mastery ON learning_progress(mastery_level);
CREATE INDEX idx_learning_progress_activity ON learning_progress(last_activity);

CREATE INDEX idx_content_generation_user ON content_generation_requests(user_id);
CREATE INDEX idx_content_generation_status ON content_generation_requests(status);
CREATE INDEX idx_content_generation_ragnostic ON content_generation_requests(ragnostic_job_id);

CREATE INDEX idx_clinical_scenarios_published ON clinical_scenarios(is_published);
CREATE INDEX idx_clinical_scenarios_difficulty ON clinical_scenarios(difficulty_level);
CREATE INDEX idx_clinical_scenarios_ragnostic ON clinical_scenarios(ragnostic_source_content);

CREATE INDEX idx_analytics_events_user ON analytics_events(user_id);
CREATE INDEX idx_analytics_events_type ON analytics_events(event_type);
CREATE INDEX idx_analytics_events_timestamp ON analytics_events(timestamp);

CREATE INDEX idx_e2e_test_results_run ON e2e_test_results(test_run_id);
CREATE INDEX idx_e2e_test_results_scenario ON e2e_test_results(scenario_id);
CREATE INDEX idx_e2e_test_results_status ON e2e_test_results(test_status);
CREATE INDEX idx_e2e_test_results_accuracy ON e2e_test_results(medical_accuracy_score);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_student_profiles_updated_at BEFORE UPDATE ON student_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_educational_content_updated_at BEFORE UPDATE ON educational_content
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_nclex_questions_updated_at BEFORE UPDATE ON nclex_questions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_assessments_updated_at BEFORE UPDATE ON assessments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_learning_progress_updated_at BEFORE UPDATE ON learning_progress
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_clinical_scenarios_updated_at BEFORE UPDATE ON clinical_scenarios
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create views for common E2E test queries
CREATE VIEW v_user_performance_summary AS
SELECT
    u.id as user_id,
    u.username,
    u.role,
    u.nursing_program,
    COUNT(DISTINCT aa.id) as total_assessments,
    AVG(aa.percentage_score) as avg_score,
    COUNT(DISTINCT lp.subject_area) as subjects_studied,
    MAX(aa.completed_at) as last_assessment,
    ARRAY_AGG(DISTINCT lp.strength_areas) as combined_strengths
FROM users u
LEFT JOIN assessment_attempts aa ON u.id = aa.user_id AND aa.status = 'completed'
LEFT JOIN learning_progress lp ON u.id = lp.user_id
GROUP BY u.id, u.username, u.role, u.nursing_program;

CREATE VIEW v_content_effectiveness AS
SELECT
    ec.id as content_id,
    ec.title,
    ec.content_type,
    ec.subject_area,
    ec.nclex_category,
    COUNT(DISTINCT qr.id) as times_used,
    AVG(CASE WHEN qr.is_correct THEN 1.0 ELSE 0.0 END) as success_rate,
    AVG(qr.time_spent_seconds) as avg_time_spent,
    ec.medical_accuracy,
    ec.ragnostic_source_id IS NOT NULL as from_ragnostic
FROM educational_content ec
LEFT JOIN nclex_questions nq ON ec.id = nq.ragnostic_content_id
LEFT JOIN question_responses qr ON nq.id = qr.question_id
WHERE ec.is_published = true
GROUP BY ec.id, ec.title, ec.content_type, ec.subject_area, ec.nclex_category, ec.medical_accuracy, ec.ragnostic_source_id;

CREATE VIEW v_e2e_pipeline_metrics AS
SELECT
    test_run_id,
    COUNT(*) as total_tests,
    COUNT(CASE WHEN test_status = 'passed' THEN 1 END) as passed_tests,
    COUNT(CASE WHEN test_status = 'failed' THEN 1 END) as failed_tests,
    AVG(execution_time_seconds) as avg_execution_time,
    AVG(medical_accuracy_score) as avg_medical_accuracy,
    MIN(executed_at) as test_run_start,
    MAX(executed_at) as test_run_end
FROM e2e_test_results
GROUP BY test_run_id
ORDER BY test_run_start DESC;

-- Insert E2E test scenario definitions
INSERT INTO e2e_test_scenarios (scenario_name, test_category, ragnostic_integration, test_parameters, expected_outcomes, performance_targets, medical_accuracy_requirements) VALUES
('UMLS Medical Term Enrichment to NCLEX Generation', 'end_to_end', true,
 '{"medical_terms": ["hypertension", "diabetes", "pneumonia"], "question_count": 10, "difficulty": 3}',
 '{"nclex_questions_generated": 10, "medical_accuracy": ">= 0.98", "generation_time": "<= 30s"}',
 '{"pipeline_time": 30, "response_time": 2000, "throughput": 100}',
 '{"umls_accuracy": 0.98, "medical_validation": true, "terminology_precision": 0.95}'),

('Batch Processing with Real-Time API Integration', 'end_to_end', true,
 '{"batch_size": 50, "concurrent_api_requests": 20, "duration_minutes": 10}',
 '{"batch_completion": "100%", "api_response_rate": ">= 99%", "no_data_loss": true}',
 '{"batch_processing_time": 600, "api_response_time": 500, "concurrent_load": 100}',
 '{"content_accuracy": 0.98, "data_integrity": 1.0}'),

('Multi-Service Transaction Integrity', 'end_to_end', true,
 '{"transaction_types": ["user_registration", "content_generation", "assessment_attempt"], "concurrent_transactions": 50}',
 '{"acid_compliance": true, "data_consistency": true, "rollback_success": true}',
 '{"transaction_time": 2000, "rollback_time": 1000, "consistency_check": 100}',
 '{"data_accuracy": 1.0, "integrity_validation": true}');

-- Insert test users for E2E scenarios
INSERT INTO users (email, username, first_name, last_name, role, nursing_program) VALUES
('e2e.student@test.bsn', 'e2e_student_1', 'Test', 'Student', 'student', 'bsn'),
('e2e.instructor@test.bsn', 'e2e_instructor_1', 'Test', 'Instructor', 'instructor', 'msn'),
('e2e.admin@test.bsn', 'e2e_admin_1', 'Test', 'Admin', 'admin', 'dnp');

-- Insert sample educational content for testing
INSERT INTO educational_content (title, content_type, subject_area, nclex_category, difficulty_level, learning_objectives, content_body, medical_concepts, is_published, created_by) VALUES
('Hypertension Management for NCLEX', 'study_guide', 'medical_surgical', 'physiological_integrity', 3,
 ARRAY['Understand hypertension pathophysiology', 'Identify nursing interventions', 'Recognize medication effects'],
 'Comprehensive guide to hypertension management including pathophysiology, assessment, nursing interventions, and medication management.',
 ARRAY['hypertension', 'blood_pressure', 'antihypertensives', 'cardiovascular_system'],
 true, (SELECT id FROM users WHERE username = 'e2e_instructor_1')),

('Diabetes Care Planning', 'study_guide', 'medical_surgical', 'physiological_integrity', 4,
 ARRAY['Develop diabetes care plans', 'Monitor blood glucose', 'Educate patients on self-care'],
 'Detailed study guide covering Type 1 and Type 2 diabetes management, complications, and patient education.',
 ARRAY['diabetes_mellitus', 'insulin', 'blood_glucose', 'diabetic_complications'],
 true, (SELECT id FROM users WHERE username = 'e2e_instructor_1'));

-- Insert sample NCLEX questions for testing
INSERT INTO nclex_questions (question_text, question_type, options, correct_answer, rationale, difficulty_level, nclex_category, client_needs_category, cognitive_level, nursing_process_step, medical_concepts, is_active, created_by) VALUES
('A patient with hypertension is prescribed lisinopril. What is the most important nursing assessment before administering this medication?',
 'multiple_choice',
 '{"options": ["A. Heart rate", "B. Blood pressure", "C. Respiratory rate", "D. Temperature"]}',
 '{"correct": "B", "explanation": "Blood pressure must be assessed before administering antihypertensive medications"}',
 'Lisinopril is an ACE inhibitor that lowers blood pressure. Assessing baseline blood pressure is essential to determine if the medication is safe to administer and to monitor effectiveness.',
 3, 'physiological_integrity', 'pharmacological_therapies', 'application', 'assessment',
 ARRAY['hypertension', 'lisinopril', 'ace_inhibitor', 'blood_pressure'],
 true, (SELECT id FROM users WHERE username = 'e2e_instructor_1'));

-- Grant permissions for E2E testing
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO e2e_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO e2e_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO e2e_user;

COMMENT ON DATABASE bsn_knowledge_e2e IS 'BSN Knowledge E2E testing database optimized for nursing education, NCLEX preparation, and RAGnostic integration testing';
