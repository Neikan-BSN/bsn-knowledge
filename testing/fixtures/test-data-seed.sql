-- E2E Test Data Seeding Script
-- Comprehensive test data for RAGnostic → BSN Knowledge pipeline validation

-- Seed RAGnostic test data
\c ragnostic_e2e;

-- Insert comprehensive test jobs for E2E pipeline validation
INSERT INTO jobs (job_type, status, priority, source_url, source_type, config, metadata, progress) VALUES
('nursing_content_processing', 'completed', 1, 'https://github.com/nursing-education/comprehensive-textbooks', 'git',
 '{"chunking_strategy": "clinical", "medical_validation": true, "umls_integration": true}',
 '{"medical_content_type": "nursing_textbook", "target_audience": "bsn_students", "subject_areas": ["medical_surgical", "pediatrics"]}',
 '{"completed": 150, "total": 150, "medical_terms_extracted": 2847, "accuracy_validated": true}'),

('umls_terminology_enrichment', 'completed', 1, 'batch://medical-terminology-update', 'batch',
 '{"batch_size": 100, "accuracy_threshold": 0.98, "auto_validation": true}',
 '{"umls_concepts_processed": 5000, "new_mappings_created": 1247, "validation_completed": true}',
 '{"completed": 5000, "total": 5000, "validation_accuracy": 0.992}'),

('repository_chunking_analysis', 'running', 2, 'https://github.com/medical-content/nclex-prep-materials', 'git',
 '{"preserve_medical_context": true, "chunk_overlap": 200, "semantic_chunking": true}',
 '{"estimated_documents": 200, "processing_stage": "chunk_analysis", "medical_nlp_enabled": true}',
 '{"completed": 75, "total": 200, "chunks_created": 3420, "medical_terms_identified": 1205}'),

('onedrive_sync_paranoid', 'pending', 3, 'onedrive://nursing-content-library', 'onedrive',
 '{"safety_protocols": true, "backup_before_processing": true, "paranoid_mode": true}',
 '{"sync_type": "incremental", "estimated_files": 500, "medical_content_focus": "clinical_guidelines"}',
 '{"completed": 0, "total": 0, "queued_for_processing": true}');

-- Insert medical terminology test data with UMLS mappings
INSERT INTO medical_terms (term, umls_cui, semantic_type, definition, synonyms, category, confidence_score, source_documents, frequency_count) VALUES
('Hypertension', 'C0020538', 'Disease or Syndrome', 'Persistently high systemic arterial BLOOD PRESSURE',
 ARRAY['High Blood Pressure', 'HTN', 'Arterial Hypertension'], 'cardiovascular', 0.995,
 ARRAY['550e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440002']::UUID[], 487),

('Diabetes Mellitus', 'C0011849', 'Disease or Syndrome', 'A heterogeneous group of disorders characterized by HYPERGLYCEMIA',
 ARRAY['Diabetes', 'DM', 'Sugar Diabetes'], 'endocrine', 0.998,
 ARRAY['550e8400-e29b-41d4-a716-446655440003', '550e8400-e29b-41d4-a716-446655440004']::UUID[], 623),

('Pneumonia', 'C0032285', 'Disease or Syndrome', 'Infection of the lung often accompanied by inflammation',
 ARRAY['Lung Infection', 'Pneumonic Process'], 'respiratory', 0.992,
 ARRAY['550e8400-e29b-41d4-a716-446655440005']::UUID[], 342),

('Myocardial Infarction', 'C0027051', 'Disease or Syndrome', 'NECROSIS of the MYOCARDIUM caused by an obstruction of the blood supply',
 ARRAY['Heart Attack', 'MI', 'Acute MI', 'STEMI', 'NSTEMI'], 'cardiovascular', 0.999,
 ARRAY['550e8400-e29b-41d4-a716-446655440006', '550e8400-e29b-41d4-a716-446655440007']::UUID[], 289),

('Chronic Kidney Disease', 'C1561643', 'Disease or Syndrome', 'Kidney damage or decreased kidney function for 3 or more months',
 ARRAY['CKD', 'Chronic Renal Disease', 'Chronic Renal Failure'], 'renal', 0.994,
 ARRAY['550e8400-e29b-41d4-a716-446655440008']::UUID[], 156),

('Congestive Heart Failure', 'C0018802', 'Disease or Syndrome', 'A heterogeneous condition in which the heart is unable to pump blood',
 ARRAY['CHF', 'Heart Failure', 'Cardiac Failure', 'Left Heart Failure'], 'cardiovascular', 0.997,
 ARRAY['550e8400-e29b-41d4-a716-446655440009', '550e8400-e29b-41d4-a716-446655440010']::UUID[], 378);

-- Insert document processing test data
INSERT INTO documents (job_id, original_filename, file_type, file_size_bytes, content_hash, medical_content_type, processing_status, extracted_text, metadata, medical_metadata) VALUES
((SELECT id FROM jobs WHERE job_type = 'nursing_content_processing' LIMIT 1),
 'medical_surgical_nursing_chapter_12.pdf', 'pdf', 2485760, 'sha256:a1b2c3d4e5f6', 'nursing_textbook', 'completed',
 'Chapter 12: Cardiovascular Disorders - This chapter covers the pathophysiology, assessment, and nursing management of cardiovascular conditions including hypertension, myocardial infraction, and heart failure...',
 '{"pages": 45, "images": 12, "tables": 8, "ocr_confidence": 0.97}',
 '{"medical_accuracy": 0.98, "terminology_validated": true, "umls_concepts": 67, "nursing_focus": true}'),

((SELECT id FROM jobs WHERE job_type = 'nursing_content_processing' LIMIT 1),
 'pediatric_nursing_assessment_guide.docx', 'docx', 1234567, 'sha256:b2c3d4e5f6g7', 'clinical_guidelines', 'completed',
 'Pediatric Assessment Guidelines: Age-appropriate assessment techniques for infants, toddlers, school-age children, and adolescents. Includes growth and development considerations, vital sign parameters, and communication strategies...',
 '{"word_count": 8943, "sections": 15, "references": 45}',
 '{"medical_accuracy": 0.99, "age_groups_covered": ["infant", "toddler", "school_age", "adolescent"], "assessment_focus": true}');

-- Insert medical accuracy validation logs
INSERT INTO medical_accuracy_logs (document_id, medical_term_id, accuracy_score, validation_method, validator, notes) VALUES
((SELECT id FROM documents WHERE original_filename = 'medical_surgical_nursing_chapter_12.pdf'),
 (SELECT id FROM medical_terms WHERE term = 'Hypertension'),
 0.998, 'umls_validation', 'automated_system', 'UMLS CUI C0020538 confirmed with high confidence'),

((SELECT id FROM documents WHERE original_filename = 'medical_surgical_nursing_chapter_12.pdf'),
 (SELECT id FROM medical_terms WHERE term = 'Myocardial Infarction'),
 0.999, 'umls_validation', 'automated_system', 'UMLS CUI C0027051 validated with expert-level accuracy'),

((SELECT id FROM documents WHERE original_filename = 'pediatric_nursing_assessment_guide.docx'),
 (SELECT id FROM medical_terms WHERE term = 'Chronic Kidney Disease'),
 0.994, 'expert_review', 'clinical_expert_reviewer', 'Terminology usage appropriate for pediatric context');

-- Insert service health monitoring data
INSERT INTO service_health (service_name, health_status, response_time_ms, cpu_usage_percent, memory_usage_percent, active_connections, error_rate_percent, metadata) VALUES
('ragnostic-orchestrator', 'healthy', 45, 12.5, 34.2, 23, 0.01, '{"version": "1.0.0", "uptime_hours": 72}'),
('ragnostic-storage', 'healthy', 38, 8.3, 28.7, 15, 0.005, '{"vector_collections": 3, "documents_stored": 1247}'),
('ragnostic-nursing-processor', 'healthy', 122, 35.7, 56.8, 8, 0.02, '{"processed_documents": 150, "accuracy_avg": 0.984}'),
('ragnostic-config', 'healthy', 25, 5.2, 18.3, 12, 0.0, '{"configurations_active": 15, "last_update": "2025-08-27T05:00:00Z"}'),
('ragnostic-gateway', 'healthy', 67, 18.9, 42.1, 45, 0.015, '{"requests_processed": 15420, "rate_limit_hits": 23}');

-- Switch to BSN Knowledge database for test data
\c bsn_knowledge_e2e;

-- Insert additional test users with varied profiles
INSERT INTO users (email, username, first_name, last_name, role, nursing_program, graduation_year, nclex_taken, nclex_pass_status) VALUES
('student.advanced@test.bsn', 'advanced_student', 'Sarah', 'Johnson', 'student', 'bsn', 2025, false, 'not_taken'),
('student.struggling@test.bsn', 'struggling_student', 'Mike', 'Davis', 'student', 'adn', 2024, true, 'failed'),
('instructor.expert@test.bsn', 'expert_instructor', 'Dr. Lisa', 'Chen', 'instructor', 'dnp', 2018, true, 'passed'),
('student.repeater@test.bsn', 'nclex_repeater', 'Amanda', 'Williams', 'student', 'bsn', 2023, true, 'failed'),
('new.student@test.bsn', 'new_student', 'Jessica', 'Brown', 'student', 'bsn', 2026, false, 'not_taken');

-- Insert student profiles with diverse learning characteristics
INSERT INTO student_profiles (user_id, learning_style, competency_level, strengths, weaknesses, learning_goals, current_focus_areas, study_hours_weekly, preferred_difficulty, performance_metrics, adaptation_settings) VALUES
((SELECT id FROM users WHERE username = 'advanced_student'), 'visual', 'advanced',
 ARRAY['Critical thinking', 'Pharmacology', 'Patient education'],
 ARRAY['Time management', 'Test anxiety'],
 ARRAY['Pass NCLEX on first attempt', 'Develop leadership skills'],
 ARRAY['Management of Care', 'Pharmacological Therapies'],
 25, 'hard',
 '{"avg_score": 0.89, "improvement_rate": 0.15, "consistency": 0.92}',
 '{"adaptive_difficulty": true, "focus_weak_areas": true, "review_frequency": "daily"}'),

((SELECT id FROM users WHERE username = 'struggling_student'), 'kinesthetic', 'beginner',
 ARRAY['Hands-on learning', 'Patient communication'],
 ARRAY['Pharmacology', 'Pathophysiology', 'Math calculations'],
 ARRAY['Retake NCLEX successfully', 'Improve medication knowledge'],
 ARRAY['Pharmacological Therapies', 'Reduction of Risk Potential'],
 15, 'easy',
 '{"avg_score": 0.62, "improvement_rate": 0.08, "consistency": 0.45}',
 '{"remediation_focus": true, "extended_explanations": true, "frequent_breaks": true}'),

((SELECT id FROM users WHERE username = 'new_student'), 'mixed', 'beginner',
 ARRAY['Enthusiasm', 'Quick learner'],
 ARRAY['Limited clinical experience', 'Overwhelmed by content volume'],
 ARRAY['Build strong foundation', 'Develop clinical reasoning'],
 ARRAY['Safe and Effective Care Environment', 'Health Promotion'],
 20, 'medium',
 '{"avg_score": 0.74, "improvement_rate": 0.22, "consistency": 0.68}',
 '{"progressive_difficulty": true, "comprehensive_feedback": true}');

-- Insert comprehensive NCLEX questions covering multiple categories
INSERT INTO nclex_questions (question_text, question_type, options, correct_answer, rationale, difficulty_level, nclex_category, client_needs_category, client_needs_subcategory, cognitive_level, nursing_process_step, medical_concepts, umls_mappings, tags, created_by) VALUES
('A nurse is caring for a client with diabetes mellitus who is experiencing hypoglycemia. Which intervention should the nurse implement first?',
 'multiple_choice',
 '{"options": ["A. Administer glucagon intramuscularly", "B. Give 15g of fast-acting carbohydrates", "C. Check blood glucose level", "D. Call the healthcare provider"]}',
 '{"correct": "B", "explanation": "15g of fast-acting carbohydrates should be given first for conscious hypoglycemic episodes"}',
 'For a conscious client experiencing hypoglycemia, the priority is to quickly raise blood glucose levels with 15g of fast-acting carbohydrates (15-15 rule). This provides rapid glucose absorption and symptom relief.',
 3, 'physiological_integrity', 'physiological_adaptation', 'medical_emergencies', 'application', 'implementation',
 ARRAY['diabetes_mellitus', 'hypoglycemia', 'glucose_management', 'emergency_care'],
 ARRAY['C0011849', 'C0020615'], -- Diabetes Mellitus, Hypoglycemia
 ARRAY['diabetes', 'hypoglycemia', 'emergency', 'glucose'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('A client with congestive heart failure is prescribed furosemide (Lasix). Which assessment finding would indicate the medication is effective?',
 'multiple_choice',
 '{"options": ["A. Decreased heart rate", "B. Increased urine output", "C. Decreased blood pressure", "D. Increased appetite"]}',
 '{"correct": "B", "explanation": "Furosemide is a diuretic that increases urine output, reducing fluid overload in CHF"}',
 'Furosemide is a loop diuretic that works by inhibiting sodium and chloride reabsorption in the kidney, leading to increased urine output and reduced fluid retention, which is the primary therapeutic goal in CHF management.',
 3, 'physiological_integrity', 'pharmacological_therapies', 'expected_effects', 'analysis', 'evaluation',
 ARRAY['congestive_heart_failure', 'furosemide', 'diuretic', 'fluid_balance'],
 ARRAY['C0018802', 'C0016860'], -- CHF, Furosemide
 ARRAY['chf', 'diuretics', 'pharmacology', 'fluid_balance'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('A nurse is teaching a pregnant client about nutrition. Which statement by the client indicates understanding of folic acid supplementation?',
 'multiple_choice',
 '{"options": ["A. I should take folic acid only if I have anemia", "B. Folic acid helps prevent birth defects of the brain and spine", "C. I can stop taking folic acid after the first trimester", "D. Folic acid is only needed if I am carrying twins"]}',
 '{"correct": "B", "explanation": "Folic acid supplementation helps prevent neural tube defects"}',
 'Folic acid (folate) is crucial during pregnancy, especially in the first trimester, for preventing neural tube defects such as spina bifida and anencephaly. The recommendation is 400-600 mcg daily before conception and throughout pregnancy.',
 2, 'health_promotion', 'health_promotion_and_maintenance', 'ante_intra_postpartum', 'comprehension', 'evaluation',
 ARRAY['pregnancy', 'folic_acid', 'neural_tube_defects', 'prenatal_nutrition'],
 ARRAY['C0032961', 'C0016410'], -- Pregnancy, Folic Acid
 ARRAY['pregnancy', 'nutrition', 'prevention', 'birth_defects'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('A nurse is caring for a pediatric client with pneumonia. Which assessment finding would be most concerning?',
 'multiple_choice',
 '{"options": ["A. Temperature of 101.5°F (38.6°C)", "B. Respiratory rate of 45 breaths/minute in a 2-year-old", "C. Slight nasal congestion", "D. Decreased appetite"]}',
 '{"correct": "B", "explanation": "Respiratory rate of 45 in a 2-year-old exceeds normal range and indicates respiratory distress"}',
 'Normal respiratory rate for a 2-year-old is 20-30 breaths/minute. A rate of 45 indicates significant respiratory distress and potential respiratory failure, requiring immediate intervention in a child with pneumonia.',
 4, 'physiological_integrity', 'physiological_adaptation', 'alterations_in_body_systems', 'analysis', 'assessment',
 ARRAY['pediatric_pneumonia', 'respiratory_distress', 'vital_signs', 'pediatric_assessment'],
 ARRAY['C0032285', 'C0476273'], -- Pneumonia, Respiratory Distress
 ARRAY['pediatrics', 'pneumonia', 'respiratory', 'assessment'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('A client is scheduled for a colonoscopy. Which instruction should the nurse include in the pre-procedure teaching?',
 'multiple_choice',
 '{"options": ["A. Take all regular medications as scheduled", "B. Maintain a clear liquid diet for 24 hours before the procedure", "C. Eat a high-fiber meal the night before", "D. Stop taking the bowel preparation if nausea occurs"]}',
 '{"correct": "B", "explanation": "Clear liquid diet is required 24 hours before colonoscopy for adequate visualization"}',
 'A clear liquid diet 24 hours before colonoscopy is essential for proper bowel cleansing and optimal visualization during the procedure. This includes clear broths, gelatin, clear juices, and the prescribed bowel preparation solution.',
 2, 'physiological_integrity', 'reduction_of_risk_potential', 'diagnostic_tests', 'application', 'planning',
 ARRAY['colonoscopy', 'bowel_preparation', 'pre_procedure_care', 'patient_education'],
 ARRAY['C0009378'], -- Colonoscopy
 ARRAY['colonoscopy', 'procedure_prep', 'patient_education'],
 (SELECT id FROM users WHERE username = 'expert_instructor'));

-- Insert assessments for E2E testing
INSERT INTO assessments (title, description, assessment_type, subject_areas, question_count, time_limit_minutes, passing_score, difficulty_range, nclex_categories, created_by) VALUES
('Comprehensive NCLEX Practice Exam', 'Full-length practice exam covering all NCLEX categories with adaptive difficulty',
 'comprehensive', ARRAY['medical_surgical', 'pediatrics', 'maternity', 'psychiatric', 'community_health'],
 75, 90, 75, ARRAY[2,5],
 ARRAY['safe_effective_care', 'health_promotion', 'psychosocial_integrity', 'physiological_integrity'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('Pharmacology Focus Assessment', 'Targeted assessment focusing on medication administration and pharmacological therapies',
 'practice', ARRAY['pharmacology'],
 25, 30, 80, ARRAY[3,4],
 ARRAY['physiological_integrity'],
 (SELECT id FROM users WHERE username = 'expert_instructor')),

('Adaptive Learning Diagnostic', 'Diagnostic assessment that adapts to student performance to identify knowledge gaps',
 'adaptive', ARRAY['medical_surgical', 'fundamentals'],
 15, 20, 70, ARRAY[1,5],
 ARRAY['safe_effective_care', 'physiological_integrity'],
 (SELECT id FROM users WHERE username = 'expert_instructor'));

-- Link questions to assessments
INSERT INTO assessment_questions (assessment_id, question_id, question_order, points_possible)
SELECT
    a.id as assessment_id,
    nq.id as question_id,
    ROW_NUMBER() OVER (ORDER BY nq.created_at) as question_order,
    CASE WHEN nq.difficulty_level >= 4 THEN 2 ELSE 1 END as points_possible
FROM assessments a
CROSS JOIN nclex_questions nq
WHERE a.title = 'Comprehensive NCLEX Practice Exam'
  AND nq.is_active = true;

-- Insert assessment attempts for performance analytics
INSERT INTO assessment_attempts (assessment_id, user_id, attempt_number, status, started_at, completed_at, time_taken_seconds, score, percentage_score, passed, detailed_results, analytics_data) VALUES
((SELECT id FROM assessments WHERE title = 'Comprehensive NCLEX Practice Exam'),
 (SELECT id FROM users WHERE username = 'advanced_student'),
 1, 'completed', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '30 minutes', 5400, 67, 89.33, true,
 '{"questions_correct": 67, "questions_total": 75, "category_breakdown": {"physiological_integrity": 0.91, "safe_effective_care": 0.87}}',
 '{"avg_time_per_question": 72, "categories_strength": ["pharmacology", "medical_surgical"], "categories_weakness": ["delegation"]}'),

((SELECT id FROM assessments WHERE title = 'Pharmacology Focus Assessment'),
 (SELECT id FROM users WHERE username = 'struggling_student'),
 1, 'completed', NOW() - INTERVAL '1 day', NOW() - INTERVAL '23 hours', 1980, 15, 60.00, false,
 '{"questions_correct": 15, "questions_total": 25, "category_breakdown": {"physiological_integrity": 0.60}}',
 '{"avg_time_per_question": 79, "frequent_mistakes": ["dosage_calculations", "drug_interactions"], "needs_remediation": true}'),

((SELECT id FROM assessments WHERE title = 'Adaptive Learning Diagnostic'),
 (SELECT id FROM users WHERE username = 'new_student'),
 1, 'completed', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '2 hours', 1320, 11, 73.33, true,
 '{"questions_correct": 11, "questions_total": 15, "adaptive_path": {"started_difficulty": 2, "final_difficulty": 3}}',
 '{"learning_trajectory": "positive", "recommended_focus": ["pathophysiology", "nursing_process"], "confidence_building": true}');

-- Insert learning progress tracking
INSERT INTO learning_progress (user_id, subject_area, nclex_category, competency_score, mastery_level, questions_attempted, questions_correct, avg_response_time, improvement_rate, knowledge_gaps, strength_areas) VALUES
((SELECT id FROM users WHERE username = 'advanced_student'), 'medical_surgical', 'physiological_integrity', 0.89, 'proficient', 150, 134, 68.5, 0.15,
 ARRAY['delegation', 'prioritization'], ARRAY['pharmacology', 'pathophysiology', 'assessment']),

((SELECT id FROM users WHERE username = 'struggling_student'), 'pharmacology', 'physiological_integrity', 0.58, 'novice', 75, 44, 95.2, 0.05,
 ARRAY['dosage_calculations', 'drug_interactions', 'adverse_effects'], ARRAY['basic_pharmacokinetics']),

((SELECT id FROM users WHERE username = 'new_student'), 'fundamentals', 'safe_effective_care', 0.72, 'competent', 45, 33, 78.1, 0.22,
 ARRAY['infection_control', 'safety_protocols'], ARRAY['communication', 'basic_care', 'documentation']);

-- Insert content generation requests for RAGnostic integration testing
INSERT INTO content_generation_requests (user_id, request_type, subject_area, difficulty_level, quantity_requested, specific_topics, generation_parameters, status, quality_metrics) VALUES
((SELECT id FROM users WHERE username = 'expert_instructor'), 'nclex_questions', 'medical_surgical', 4, 25,
 ARRAY['cardiovascular disorders', 'respiratory conditions', 'endocrine disorders'],
 '{"focus_on_critical_thinking": true, "include_rationales": true, "umls_validation": true, "medical_accuracy_threshold": 0.98}',
 'completed',
 '{"medical_accuracy": 0.984, "content_relevance": 0.92, "difficulty_alignment": 0.96}'),

((SELECT id FROM users WHERE username = 'expert_instructor'), 'study_guide', 'pharmacology', 3, 1,
 ARRAY['cardiac medications', 'diabetes medications', 'pain management'],
 '{"comprehensive_coverage": true, "include_nursing_considerations": true, "patient_education_focus": true}',
 'processing',
 '{}');

-- Insert clinical scenarios for decision support testing
INSERT INTO clinical_scenarios (title, scenario_text, patient_context, clinical_data, nursing_priorities, learning_objectives, difficulty_level, nclex_categories, cognitive_skills, evidence_base, created_by, is_published) VALUES
('Acute MI Management in Emergency Department',
'A 58-year-old male presents to the ED with crushing chest pain radiating to his left arm, diaphoresis, and nausea. Pain started 2 hours ago while mowing the lawn.',
'{"age": 58, "gender": "male", "medical_history": ["hypertension", "hyperlipidemia"], "medications": ["lisinopril", "atorvastatin"], "allergies": ["penicillin"]}',
'{"vital_signs": {"bp": "180/95", "hr": "110", "rr": "24", "temp": "99.2", "spo2": "96%"}, "ecg": "ST elevation in leads II, III, aVF", "cardiac_enzymes": {"troponin": "elevated", "ck_mb": "elevated"}}',
ARRAY['Pain management', 'Cardiac monitoring', 'Medication administration', 'Patient/family education'],
ARRAY['Recognize signs of acute MI', 'Prioritize nursing interventions', 'Demonstrate knowledge of cardiac medications'],
4, ARRAY['physiological_integrity'], ARRAY['clinical_reasoning', 'prioritization', 'critical_thinking'],
ARRAY['AHA Guidelines for STEMI Management', 'Evidence-based cardiac care protocols'],
(SELECT id FROM users WHERE username = 'expert_instructor'), true),

('Pediatric Asthma Exacerbation',
'A 7-year-old child is brought to the clinic by her mother with increased wheezing, cough, and difficulty breathing that started this morning.',
'{"age": 7, "gender": "female", "medical_history": ["asthma", "seasonal_allergies"], "medications": ["albuterol_inhaler", "fluticasone"], "triggers": ["pollen", "dust", "exercise"]}',
'{"vital_signs": {"bp": "95/60", "hr": "125", "rr": "36", "temp": "98.6", "spo2": "91%"}, "assessment": {"peak_flow": "60% of personal_best", "accessory_muscle_use": true, "tripod_positioning": true}}',
ARRAY['Respiratory assessment', 'Bronchodilator administration', 'Oxygen therapy', 'Parent education'],
ARRAY['Assess pediatric respiratory distress', 'Implement age-appropriate interventions', 'Provide family-centered care'],
3, ARRAY['physiological_integrity', 'health_promotion'], ARRAY['pediatric_assessment', 'family_communication', 'emergency_care'],
ARRAY['NAEPP Guidelines for Asthma Management in Children', 'Pediatric Emergency Care Protocols'],
(SELECT id FROM users WHERE username = 'expert_instructor'), true);

-- Insert E2E test result samples
INSERT INTO e2e_test_results (test_run_id, scenario_id, test_status, execution_time_seconds, performance_metrics, medical_accuracy_score, ragnostic_interaction_logs, bsn_response_data, assertions_passed, assertions_total) VALUES
('e2e_run_20250827_052000',
 (SELECT id FROM e2e_test_scenarios WHERE scenario_name = 'UMLS Medical Term Enrichment to NCLEX Generation'),
 'passed', 28.5,
 '{"ragnostic_response_time": 1250, "bsn_processing_time": 890, "total_pipeline_time": 28500, "throughput": 95}',
 0.984,
 '{"umls_terms_processed": 15, "ragnostic_jobs_created": 3, "content_chunks_generated": 45}',
 '{"nclex_questions_generated": 10, "medical_accuracy_validated": true, "content_published": true}',
 12, 12),

('e2e_run_20250827_052000',
 (SELECT id FROM e2e_test_scenarios WHERE scenario_name = 'Batch Processing with Real-Time API Integration'),
 'passed', 580.2,
 '{"batch_completion_rate": 1.0, "api_success_rate": 0.995, "concurrent_requests_handled": 98, "data_integrity_score": 1.0}',
 0.991,
 '{"batch_jobs_completed": 50, "api_requests_processed": 2450, "errors_encountered": 12, "recovery_successful": true}',
 '{"user_sessions_maintained": true, "content_consistency": true, "no_data_loss": true}',
 8, 8),

('e2e_run_20250827_052000',
 (SELECT id FROM e2e_test_scenarios WHERE scenario_name = 'Multi-Service Transaction Integrity'),
 'passed', 1950.7,
 '{"transaction_success_rate": 0.98, "rollback_success_rate": 1.0, "data_consistency_verified": true, "acid_compliance": true}',
 1.0,
 '{"transactions_initiated": 150, "successful_commits": 147, "rollbacks_required": 3, "consistency_checks_passed": 150}',
 '{"data_integrity_maintained": true, "user_data_consistent": true, "no_orphaned_records": true}',
 15, 15);

-- Insert analytics events for monitoring and reporting
INSERT INTO analytics_events (user_id, event_type, event_category, event_data, session_id) VALUES
((SELECT id FROM users WHERE username = 'advanced_student'), 'assessment_started', 'learning',
 '{"assessment_id": "' || (SELECT id FROM assessments WHERE title = 'Comprehensive NCLEX Practice Exam') || '", "assessment_type": "comprehensive"}',
 'session_' || extract(epoch from now())),

((SELECT id FROM users WHERE username = 'struggling_student'), 'question_answered', 'learning',
 '{"question_id": "' || (SELECT id FROM nclex_questions LIMIT 1) || '", "is_correct": false, "time_spent": 125, "difficulty_level": 3}',
 'session_' || extract(epoch from now())),

((SELECT id FROM users WHERE username = 'new_student'), 'content_accessed', 'content_interaction',
 '{"content_id": "' || (SELECT id FROM educational_content LIMIT 1) || '", "content_type": "study_guide", "time_spent": 420}',
 'session_' || extract(epoch from now()));

-- Create summary statistics for E2E validation
INSERT INTO test_metrics (test_run_id, test_case_id, metric_name, metric_value, metric_unit, metadata) VALUES
('e2e_run_20250827_052000', 'E2E-001', 'pipeline_execution_time', 28.500, 'seconds', '{"target": 30.0, "status": "within_target"}'),
('e2e_run_20250827_052000', 'E2E-001', 'medical_accuracy_score', 0.984, 'percentage', '{"target": 0.98, "status": "exceeds_target"}'),
('e2e_run_20250827_052000', 'E2E-002', 'concurrent_load_handling', 98, 'requests', '{"target": 100, "status": "near_target"}'),
('e2e_run_20250827_052000', 'E2E-003', 'transaction_success_rate', 0.980, 'percentage', '{"target": 0.95, "status": "exceeds_target"}'),
('e2e_run_20250827_052000', 'PERF-001', 'avg_response_time', 890, 'milliseconds', '{"target": 2000, "status": "excellent"}'),
('e2e_run_20250827_052000', 'SEC-001', 'authentication_bypass_attempts', 0, 'count', '{"security_validation": "passed"}');

COMMENT ON SCHEMA public IS 'E2E test data seeding completed - RAGnostic and BSN Knowledge databases populated with comprehensive test scenarios, medical content, and performance baselines';
