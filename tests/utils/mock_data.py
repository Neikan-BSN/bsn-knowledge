"""
Mock data generators for BSN Knowledge API testing.

Provides comprehensive mock data for nursing education scenarios,
realistic test cases, and edge case testing.
"""

import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

from src.models.assessment_models import AACNDomain, CompetencyProficiencyLevel


class MockDataConstants:
    """Constants for mock data generation."""

    # Nursing specialties
    NURSING_SPECIALTIES = [
        "Medical-Surgical",
        "Critical Care",
        "Emergency",
        "Pediatric",
        "Obstetric",
        "Psychiatric",
        "Community Health",
        "Geriatric",
        "Oncology",
        "Cardiac",
        "Respiratory",
        "Renal",
    ]

    # Common nursing topics
    NURSING_TOPICS = [
        "Cardiovascular Assessment",
        "Respiratory Care",
        "Medication Administration",
        "Infection Prevention",
        "Patient Safety",
        "Pain Management",
        "Wound Care",
        "Vital Signs",
        "Mental Health",
        "Health Education",
        "Discharge Planning",
        "Emergency Procedures",
        "Surgical Care",
        "Chronic Disease Management",
        "Family-Centered Care",
        "Cultural Competency",
    ]

    # NCLEX categories
    NCLEX_CATEGORIES = [
        "Safe and Effective Care Environment - Management of Care",
        "Safe and Effective Care Environment - Safety and Infection Control",
        "Health Promotion and Maintenance",
        "Psychosocial Integrity",
        "Physiological Integrity - Basic Care and Comfort",
        "Physiological Integrity - Pharmacological and Parenteral Therapies",
        "Physiological Integrity - Reduction of Risk Potential",
        "Physiological Integrity - Physiological Adaptation",
    ]

    # Student levels
    STUDENT_LEVELS = ["freshman", "sophomore", "junior", "senior"]

    # Difficulty levels
    DIFFICULTY_LEVELS = ["beginner", "intermediate", "advanced", "expert"]

    # Question types
    QUESTION_TYPES = [
        "multiple_choice",
        "select_all_that_apply",
        "fill_in_the_blank",
        "drag_and_drop",
        "hot_spot",
        "chart_exhibit",
    ]


class MockNursingScenarios:
    """Generates realistic nursing education scenarios."""

    @staticmethod
    def create_cardiovascular_scenario() -> Dict[str, Any]:
        """Create a cardiovascular nursing scenario."""
        return {
            "title": "Cardiovascular Assessment and Intervention",
            "patient_demographics": {
                "age": random.randint(45, 80),
                "gender": random.choice(["Male", "Female"]),
                "diagnosis": "Congestive Heart Failure",
                "admission_reason": "Shortness of breath and peripheral edema",
            },
            "clinical_data": {
                "vital_signs": {
                    "blood_pressure": f"{random.randint(140, 180)}/{random.randint(85, 110)}",
                    "heart_rate": random.randint(90, 120),
                    "respiratory_rate": random.randint(20, 28),
                    "temperature": round(random.uniform(98.0, 100.4), 1),
                    "oxygen_saturation": random.randint(88, 95),
                },
                "lab_values": {
                    "BNP": random.randint(400, 1500),
                    "creatinine": round(random.uniform(1.2, 2.0), 1),
                    "sodium": random.randint(130, 138),
                    "potassium": round(random.uniform(3.2, 5.0), 1),
                },
                "medications": [
                    "Furosemide 40mg PO daily",
                    "Lisinopril 10mg PO daily",
                    "Metoprolol 50mg PO BID",
                    "Digoxin 0.25mg PO daily",
                ],
            },
            "learning_objectives": [
                "Perform comprehensive cardiovascular assessment",
                "Identify signs and symptoms of heart failure exacerbation",
                "Understand pharmacological interventions for heart failure",
                "Implement patient education for heart failure management",
            ],
            "assessment_questions": [
                {
                    "question": "Which assessment finding would be most concerning for this patient?",
                    "options": [
                        "A. Blood pressure 150/90 mmHg",
                        "B. Heart rate 110 bpm",
                        "C. Oxygen saturation 88%",
                        "D. Temperature 99.2°F",
                    ],
                    "correct_answer": "C",
                    "rationale": "Oxygen saturation of 88% indicates significant hypoxemia and requires immediate intervention.",
                }
            ],
            "competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
        }

    @staticmethod
    def create_medication_safety_scenario() -> Dict[str, Any]:
        """Create a medication safety scenario."""
        return {
            "title": "Medication Administration and Safety",
            "scenario_type": "medication_error_prevention",
            "context": {
                "setting": "Medical-Surgical Unit",
                "shift": "Day shift, 0800 medication pass",
                "nurse_experience": "New graduate nurse, 6 months experience",
            },
            "situation": {
                "patient_count": 6,
                "medications_due": 23,
                "interruptions": "High traffic area, frequent calls",
                "time_pressure": "Running 30 minutes behind schedule",
            },
            "critical_thinking_points": [
                "Importance of the 5 rights of medication administration",
                "Strategies to minimize interruptions during medication preparation",
                "Recognition of look-alike, sound-alike medications",
                "Double-checking high-alert medications",
            ],
            "learning_objectives": [
                "Demonstrate safe medication administration practices",
                "Identify potential sources of medication errors",
                "Implement error prevention strategies",
                "Understand legal and ethical responsibilities",
            ],
            "assessment_questions": [
                {
                    "question": "The nurse is preparing to administer medications to multiple patients. Which action best demonstrates safe practice?",
                    "options": [
                        "A. Prepare all medications at once to save time",
                        "B. Check each medication at the bedside before administration",
                        "C. Ask the patient to verify their medications",
                        "D. Skip the final check if interrupted during preparation",
                    ],
                    "correct_answer": "B",
                    "rationale": "Bedside medication verification is a critical safety check that helps prevent medication errors.",
                }
            ],
            "competencies": ["AACN_KNOWLEDGE_1", "AACN_HEALTHCARE_SYSTEMS_1"],
        }

    @staticmethod
    def create_infection_control_scenario() -> Dict[str, Any]:
        """Create an infection control scenario."""
        return {
            "title": "Infection Prevention and Control",
            "outbreak_scenario": {
                "pathogen": "Clostridioides difficile",
                "affected_units": ["Medical-Surgical", "ICU"],
                "patient_count": 8,
                "timeline": "2 weeks",
            },
            "prevention_measures": {
                "hand_hygiene": "Soap and water required (not alcohol-based)",
                "isolation_precautions": "Contact precautions for all affected patients",
                "environmental_cleaning": "Bleach-based disinfectants required",
                "staff_education": "C. diff prevention protocols review",
            },
            "learning_objectives": [
                "Understand transmission-based precautions",
                "Implement appropriate isolation procedures",
                "Recognize signs and symptoms of healthcare-associated infections",
                "Apply evidence-based infection prevention practices",
            ],
            "assessment_questions": [
                {
                    "question": "A patient with C. difficile infection requires contact precautions. Which action is most important?",
                    "options": [
                        "A. Use alcohol-based hand sanitizer after patient care",
                        "B. Wear gloves and gown when entering the room",
                        "C. Place patient in negative pressure room",
                        "D. Restrict all visitors from entering the room",
                    ],
                    "correct_answer": "B",
                    "rationale": "Contact precautions require gloves and gown to prevent transmission of pathogens through direct contact.",
                }
            ],
            "competencies": ["AACN_HEALTHCARE_SYSTEMS_1", "AACN_PERSON_CENTERED_1"],
        }


class MockAssessmentData:
    """Generates mock assessment and competency data."""

    @staticmethod
    def create_student_competency_profile(
        student_id: str, program: str = "BSN"
    ) -> Dict[str, Any]:
        """Create a comprehensive student competency profile."""
        domains = list(AACNDomain)
        proficiency_levels = list(CompetencyProficiencyLevel)

        # Generate competency scores for each domain
        domain_scores = {}
        for domain in domains:
            # Simulate realistic progression (generally improving over time)
            base_score = random.uniform(60, 90)
            domain_scores[domain.value] = round(base_score, 1)

        overall_gpa = round(
            sum(domain_scores.values()) / len(domain_scores) / 20, 2
        )  # Convert to 4.0 scale

        return {
            "student_id": student_id,
            "program": program,
            "semester": random.randint(1, 8),
            "academic_year": "2024-2025",
            "competency_gpa": overall_gpa,
            "graduation_readiness_score": round(random.uniform(65.0, 95.0), 1),
            "domain_proficiencies": domain_scores,
            "strengths_summary": [
                "Strong clinical reasoning skills",
                "Excellent patient communication",
                "Proficient in technical skills",
                "Shows leadership potential",
            ][: random.randint(2, 4)],
            "development_plan": [
                "Enhance pharmacology knowledge",
                "Improve time management in clinical settings",
                "Develop critical thinking in emergency situations",
                "Strengthen documentation skills",
            ][: random.randint(2, 4)],
            "clinical_hours_completed": random.randint(200, 800),
            "simulation_hours": random.randint(50, 150),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "next_assessment_date": (
                datetime.now(timezone.utc) + timedelta(days=random.randint(30, 90))
            ).isoformat(),
        }

    @staticmethod
    def create_competency_gaps_analysis(
        student_id: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Create competency gap analysis for a student."""
        domains = random.sample(list(AACNDomain), k=random.randint(2, 4))

        gaps_by_domain = {}

        for domain in domains:
            domain_gaps = []

            for i in range(random.randint(1, 3)):
                gap = {
                    "competency_id": f"AACN_{domain.value.upper()}_{i+1:02d}",
                    "gap_description": random.choice(
                        [
                            "Insufficient knowledge in pathophysiology concepts",
                            "Limited experience with advanced procedures",
                            "Needs improvement in critical thinking application",
                            "Requires strengthening in communication skills",
                            "Documentation standards not consistently met",
                        ]
                    ),
                    "severity": random.choice(["low", "medium", "high"]),
                    "recommended_resources": [
                        f"Chapter {random.randint(10, 25)} in primary textbook",
                        "ATI focused review modules",
                        "Simulation lab scenarios",
                        "Peer tutoring sessions",
                    ][: random.randint(1, 3)],
                    "estimated_time_to_close_hours": random.randint(5, 40),
                    "prerequisites": [f"AACN_FOUNDATION_{random.randint(1, 5):02d}"]
                    if random.random() > 0.5
                    else [],
                    "identified_date": (
                        datetime.now(timezone.utc)
                        - timedelta(days=random.randint(1, 30))
                    ).isoformat(),
                }
                domain_gaps.append(gap)

            gaps_by_domain[domain.value] = domain_gaps

        return gaps_by_domain

    @staticmethod
    def create_learning_path_recommendation(
        student_id: str, target_competencies: List[str]
    ) -> Dict[str, Any]:
        """Create a learning path recommendation."""
        activities = [
            "reading_assignment",
            "practice_quiz",
            "simulation_scenario",
            "case_study_analysis",
            "video_lecture",
            "peer_discussion",
            "clinical_practice",
            "skills_demonstration",
        ]

        recommended_sequence = []

        for i, competency in enumerate(target_competencies):
            # Create 2-4 activities per competency
            for j in range(random.randint(2, 4)):
                activity = {
                    "step": i * 4 + j + 1,
                    "competency_target": competency,
                    "activity_type": random.choice(activities),
                    "content": f"Learning activity for {competency}",
                    "estimated_duration_minutes": random.randint(30, 120),
                    "prerequisites": recommended_sequence[-1:]
                    if recommended_sequence
                    else [],
                    "resources": [
                        "Primary nursing textbook",
                        "ATI Learning modules",
                        "Simulation scenarios",
                        "Practice questions",
                    ][: random.randint(1, 3)],
                }
                recommended_sequence.append(activity)

        total_hours = (
            sum(
                activity["estimated_duration_minutes"]
                for activity in recommended_sequence
            )
            / 60
        )

        return {
            "student_id": student_id,
            "target_competencies": target_competencies,
            "recommended_sequence": recommended_sequence,
            "estimated_duration_hours": round(total_hours, 1),
            "difficulty_progression": random.choice(
                [
                    "beginner_to_intermediate",
                    "intermediate_to_advanced",
                    "comprehensive_review",
                ]
            ),
            "learning_style_adaptations": random.sample(
                ["visual", "auditory", "kinesthetic", "reading"], k=random.randint(1, 3)
            ),
            "milestones": [
                {
                    "milestone": f"Complete {competency} foundation",
                    "target_date": (
                        datetime.now(timezone.utc) + timedelta(weeks=i * 2 + 2)
                    ).isoformat(),
                }
                for i, competency in enumerate(target_competencies)
            ],
            "created_date": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }


class MockAnalyticsData:
    """Generates mock analytics and reporting data."""

    @staticmethod
    def create_student_analytics(student_id: str) -> Dict[str, Any]:
        """Create comprehensive student analytics."""
        domains = list(AACNDomain)

        # Generate realistic competency scores
        competency_scores = {}
        for domain in domains:
            # Simulate some variation in performance across domains
            base_score = random.uniform(70, 90)
            variation = random.uniform(-10, 10)
            score = max(0, min(100, base_score + variation))
            competency_scores[domain.value] = round(score, 1)

        overall_progress = round(
            sum(competency_scores.values()) / len(competency_scores), 1
        )

        return {
            "student_id": student_id,
            "overall_progress": overall_progress,
            "competency_scores": competency_scores,
            "study_time_hours": round(random.uniform(20.0, 100.0), 1),
            "quiz_completion_rate": round(random.uniform(75.0, 98.0), 1),
            "assignment_completion_rate": round(random.uniform(80.0, 100.0), 1),
            "clinical_hours_logged": random.randint(50, 300),
            "simulation_participations": random.randint(5, 25),
            "areas_for_improvement": random.sample(
                [
                    "Pathophysiology",
                    "Pharmacology",
                    "Clinical Procedures",
                    "Documentation",
                    "Patient Communication",
                    "Critical Thinking",
                ],
                k=random.randint(1, 3),
            ),
            "strengths": random.sample(
                [
                    "Patient Care",
                    "Communication",
                    "Technical Skills",
                    "Professionalism",
                    "Teamwork",
                    "Leadership",
                ],
                k=random.randint(2, 4),
            ),
            "recent_activity": [
                {
                    "date": (
                        datetime.now(timezone.utc) - timedelta(days=i)
                    ).isoformat(),
                    "activity": random.choice(
                        [
                            "Completed NCLEX practice quiz",
                            "Attended simulation session",
                            "Submitted case study analysis",
                            "Participated in clinical rotation",
                        ]
                    ),
                    "performance_score": random.randint(75, 95),
                }
                for i in range(random.randint(5, 10))
            ],
            "projected_graduation_readiness": round(random.uniform(75.0, 95.0), 1),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def create_class_analytics(class_id: str) -> Dict[str, Any]:
        """Create class-level analytics."""
        num_students = random.randint(20, 40)

        # Generate aggregate data
        individual_scores = [random.uniform(65, 95) for _ in range(num_students)]

        competency_averages = {}
        for domain in AACNDomain:
            scores = [random.uniform(60, 95) for _ in range(num_students)]
            competency_averages[domain.value] = round(sum(scores) / len(scores), 1)

        return {
            "class_id": class_id,
            "academic_term": "Fall 2024",
            "total_students": num_students,
            "active_students": num_students - random.randint(0, 3),
            "average_progress": round(
                sum(individual_scores) / len(individual_scores), 1
            ),
            "completion_rate": round(random.uniform(85.0, 98.0), 1),
            "competency_averages": competency_averages,
            "performance_distribution": {
                "excellent_90_plus": len([s for s in individual_scores if s >= 90]),
                "good_80_89": len([s for s in individual_scores if 80 <= s < 90]),
                "satisfactory_70_79": len(
                    [s for s in individual_scores if 70 <= s < 80]
                ),
                "needs_improvement_below_70": len(
                    [s for s in individual_scores if s < 70]
                ),
            },
            "risk_indicators": {
                "at_risk_students": random.randint(0, 5),
                "missed_assignments": random.randint(0, 10),
                "low_engagement": random.randint(0, 3),
            },
            "trends": {
                "improvement_areas": random.sample(
                    [
                        "Pharmacology understanding",
                        "Clinical documentation",
                        "Patient communication",
                        "Critical thinking",
                    ],
                    k=random.randint(1, 3),
                ),
                "strength_areas": random.sample(
                    [
                        "Basic nursing skills",
                        "Professional behavior",
                        "Teamwork",
                        "Patient safety",
                    ],
                    k=random.randint(2, 4),
                ),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def create_institutional_metrics() -> Dict[str, Any]:
        """Create institution-level metrics."""
        return {
            "institution_id": "BSN_UNIVERSITY_001",
            "reporting_period": {"start_date": "2024-01-01", "end_date": "2024-08-24"},
            "program_metrics": {
                "total_students": random.randint(200, 500),
                "graduation_rate": round(random.uniform(85.0, 95.0), 1),
                "nclex_pass_rate": round(random.uniform(88.0, 96.0), 1),
                "employment_rate": round(random.uniform(90.0, 98.0), 1),
            },
            "academic_performance": {
                "average_gpa": round(random.uniform(3.2, 3.8), 2),
                "competency_achievement_rate": round(random.uniform(85.0, 95.0), 1),
                "clinical_performance_average": round(random.uniform(4.0, 4.8), 1),
            },
            "technology_utilization": {
                "platform_adoption_rate": round(random.uniform(85.0, 98.0), 1),
                "average_study_hours_per_student": round(random.uniform(40.0, 80.0), 1),
                "simulation_usage_hours": random.randint(1000, 5000),
            },
            "quality_indicators": {
                "student_satisfaction": round(random.uniform(4.2, 4.9), 1),
                "faculty_satisfaction": round(random.uniform(4.0, 4.7), 1),
                "learning_outcome_achievement": round(random.uniform(88.0, 96.0), 1),
            },
        }


class MockContentData:
    """Generates mock educational content data."""

    @staticmethod
    def create_study_guide_content(
        topic: str, competencies: List[str]
    ) -> Dict[str, Any]:
        """Create comprehensive study guide content."""
        return {
            "topic": topic,
            "competencies": competencies,
            "content_sections": [
                {
                    "section_title": "Learning Objectives",
                    "content": f"Upon completion of this study guide on {topic}, the student will be able to:",
                    "subsections": [
                        f"Define key concepts related to {topic}",
                        "Identify clinical indicators and assessment findings",
                        "Explain nursing interventions and rationales",
                        "Apply evidence-based practice principles",
                    ],
                },
                {
                    "section_title": "Key Concepts",
                    "content": f"Essential knowledge for {topic}:",
                    "subsections": [
                        "Anatomy and physiology review",
                        "Pathophysiology considerations",
                        "Assessment techniques and findings",
                        "Nursing diagnosis and planning",
                    ],
                },
                {
                    "section_title": "Clinical Applications",
                    "content": "Real-world application of theoretical knowledge:",
                    "subsections": [
                        "Case study examples",
                        "Clinical scenarios and decision-making",
                        "Prioritization of nursing interventions",
                        "Patient and family education",
                    ],
                },
                {
                    "section_title": "Evidence-Based Practice",
                    "content": "Current research and best practices:",
                    "subsections": [
                        "Recent research findings",
                        "Clinical guidelines and protocols",
                        "Quality improvement initiatives",
                        "Professional standards",
                    ],
                },
            ],
            "learning_objectives": [
                f"Demonstrate competency in {topic} assessment",
                f"Apply nursing process to {topic} patient care",
                f"Integrate evidence-based practice in {topic} management",
            ],
            "assessment_methods": [
                "Knowledge check questions",
                "Case study analysis",
                "Skill demonstration",
                "Reflection exercises",
            ],
            "resources": [
                "Primary nursing textbook chapters",
                "Professional nursing journals",
                "Clinical practice guidelines",
                "Multimedia learning materials",
            ],
            "estimated_study_time_hours": random.randint(3, 12),
            "difficulty_level": random.choice(MockDataConstants.DIFFICULTY_LEVELS),
            "created_date": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def create_nclex_question_bank(topic: str, count: int = 10) -> Dict[str, Any]:
        """Create a bank of NCLEX-style questions."""
        questions = []

        for i in range(count):
            question_id = f"{topic.lower().replace(' ', '_')}_q_{i+1:03d}"

            # Generate question based on topic
            if "cardiovascular" in topic.lower():
                question_data = MockContentData._create_cardiovascular_question(
                    question_id
                )
            elif "medication" in topic.lower() or "pharmacology" in topic.lower():
                question_data = MockContentData._create_medication_question(question_id)
            elif "infection" in topic.lower():
                question_data = MockContentData._create_infection_question(question_id)
            else:
                question_data = MockContentData._create_general_nursing_question(
                    question_id, topic
                )

            questions.append(question_data)

        return {
            "topic": topic,
            "total_questions": count,
            "questions": questions,
            "metadata": {
                "difficulty_distribution": {
                    "easy": len([q for q in questions if q["difficulty"] == "easy"]),
                    "medium": len(
                        [q for q in questions if q["difficulty"] == "medium"]
                    ),
                    "hard": len([q for q in questions if q["difficulty"] == "hard"]),
                },
                "nclex_category_distribution": {},  # Would be populated in real implementation
                "created_date": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",
            },
        }

    @staticmethod
    def _create_cardiovascular_question(question_id: str) -> Dict[str, Any]:
        """Create a cardiovascular-focused question."""
        templates = [
            {
                "question": "A patient with heart failure presents with shortness of breath and peripheral edema. Which intervention should the nurse prioritize?",
                "options": [
                    "A. Administer prescribed diuretic",
                    "B. Encourage increased fluid intake",
                    "C. Position patient flat in bed",
                    "D. Apply heating pad to extremities",
                ],
                "correct": "A",
                "rationale": "Diuretics help reduce fluid overload, which is the primary cause of symptoms in heart failure.",
            }
        ]

        template = random.choice(templates)

        return {
            "id": question_id,
            "type": "multiple_choice",
            "question": template["question"],
            "options": template["options"],
            "correct_answer": template["correct"],
            "rationale": template["rationale"],
            "topic": "cardiovascular_nursing",
            "difficulty": random.choice(["medium", "hard"]),
            "nclex_category": "Physiological Integrity - Physiological Adaptation",
            "bloom_taxonomy": "Application",
            "estimated_time_seconds": 90,
        }

    @staticmethod
    def _create_medication_question(question_id: str) -> Dict[str, Any]:
        """Create a medication-focused question."""
        return {
            "id": question_id,
            "type": "multiple_choice",
            "question": "Before administering digoxin, the nurse should assess which parameter?",
            "options": [
                "A. Blood pressure",
                "B. Respiratory rate",
                "C. Heart rate",
                "D. Temperature",
            ],
            "correct_answer": "C",
            "rationale": "Digoxin affects heart rate and rhythm. Heart rate should be assessed before administration to detect bradycardia or arrhythmias.",
            "topic": "pharmacology",
            "difficulty": "medium",
            "nclex_category": "Physiological Integrity - Pharmacological and Parenteral Therapies",
            "bloom_taxonomy": "Comprehension",
            "estimated_time_seconds": 75,
        }

    @staticmethod
    def _create_infection_question(question_id: str) -> Dict[str, Any]:
        """Create an infection control question."""
        return {
            "id": question_id,
            "type": "multiple_choice",
            "question": "When caring for a patient with C. difficile infection, which precaution is most important?",
            "options": [
                "A. Airborne precautions",
                "B. Droplet precautions",
                "C. Contact precautions",
                "D. Standard precautions only",
            ],
            "correct_answer": "C",
            "rationale": "C. difficile is transmitted through contact with contaminated surfaces and requires contact precautions including gown and gloves.",
            "topic": "infection_control",
            "difficulty": "easy",
            "nclex_category": "Safe and Effective Care Environment - Safety and Infection Control",
            "bloom_taxonomy": "Knowledge",
            "estimated_time_seconds": 60,
        }

    @staticmethod
    def _create_general_nursing_question(
        question_id: str, topic: str
    ) -> Dict[str, Any]:
        """Create a general nursing question."""
        return {
            "id": question_id,
            "type": "multiple_choice",
            "question": f"When providing care related to {topic}, which nursing action demonstrates best practice?",
            "options": [
                "A. Follow established protocols and guidelines",
                "B. Use personal judgment exclusively",
                "C. Delegate all care to assistive personnel",
                "D. Avoid documenting routine care",
            ],
            "correct_answer": "A",
            "rationale": "Following established protocols ensures evidence-based, safe, and consistent patient care.",
            "topic": topic.lower().replace(" ", "_"),
            "difficulty": "easy",
            "nclex_category": "Safe and Effective Care Environment - Management of Care",
            "bloom_taxonomy": "Application",
            "estimated_time_seconds": 60,
        }
