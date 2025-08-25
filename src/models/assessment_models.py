from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AssessmentType(str, Enum):
    FORMATIVE = "formative"
    SUMMATIVE = "summative"
    DIAGNOSTIC = "diagnostic"
    SELF_ASSESSMENT = "self_assessment"


class QuestionType(str, Enum):
    MULTIPLE_CHOICE = "multiple_choice"
    TRUE_FALSE = "true_false"
    SELECT_ALL = "select_all_that_apply"
    FILL_BLANK = "fill_in_the_blank"
    MATCHING = "matching"
    ORDERING = "ordering"
    SHORT_ANSWER = "short_answer"


class AssessmentQuestion(BaseModel):
    id: str
    question_text: str
    question_type: QuestionType
    options: list[str] = []
    correct_answers: list[int] = []
    explanation: str
    topic: str
    difficulty: str
    points: int = 1
    tags: list[str] = []


class StudentAnswer(BaseModel):
    question_id: str
    selected_answers: list[int] = []
    text_answer: str | None = None
    time_spent: int = 0
    is_correct: bool = False
    points_earned: float = 0.0


class AssessmentSession(BaseModel):
    id: str
    student_id: str
    assessment_id: str
    started_at: datetime
    completed_at: datetime | None = None
    answers: list[StudentAnswer] = []
    total_score: float = 0.0
    percentage_score: float = 0.0
    time_taken: int = 0
    is_completed: bool = False


class Assessment(BaseModel):
    id: str
    title: str
    description: str
    assessment_type: AssessmentType
    topic: str
    questions: list[AssessmentQuestion]
    time_limit: int | None = None
    passing_score: float = 70.0
    max_attempts: int = 3
    randomize_questions: bool = False
    show_results_immediately: bool = True
    created_by: str
    created_date: datetime
    is_active: bool = True


class CompetencyMeasurement(BaseModel):
    competency_id: str
    assessment_id: str
    questions_mapped: list[str]
    weight: float = 1.0
    passing_threshold: float = 70.0


class AssessmentAnalytics(BaseModel):
    assessment_id: str
    total_attempts: int = 0
    average_score: float = 0.0
    pass_rate: float = 0.0
    average_time: int = 0
    difficulty_analysis: dict[str, Any] = {}
    question_analytics: dict[str, dict[str, Any]] = {}
    last_calculated: datetime


# AACN Competency Framework Models
class AACNDomain(str, Enum):
    KNOWLEDGE_FOR_NURSING_PRACTICE = "knowledge_for_nursing_practice"
    PERSON_CENTERED_CARE = "person_centered_care"
    POPULATION_HEALTH = "population_health"
    SCHOLARSHIP_FOR_NURSING_DISCIPLINE = "scholarship_for_nursing_discipline"
    INFORMATION_TECHNOLOGY = "information_technology"
    HEALTHCARE_SYSTEMS = "healthcare_systems"
    INTERPROFESSIONAL_PARTNERSHIPS = "interprofessional_partnerships"
    PERSONAL_PROFESSIONAL_DEVELOPMENT = "personal_professional_development"


class CompetencyProficiencyLevel(str, Enum):
    NOVICE = "novice"
    ADVANCED_BEGINNER = "advanced_beginner"
    COMPETENT = "competent"
    PROFICIENT = "proficient"
    EXPERT = "expert"


class AACNCompetency(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    domain: AACNDomain
    name: str
    description: str
    sub_competencies: list[str] = Field(default_factory=list)
    learning_outcomes: list[str] = Field(default_factory=list)
    assessment_methods: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    minimum_level: CompetencyProficiencyLevel = CompetencyProficiencyLevel.COMPETENT
    weight: float = 1.0
    umls_concepts: list[str] = Field(default_factory=list)  # UMLS concept mappings


class CompetencyAssessmentResult(BaseModel):
    student_id: str
    competency_id: str
    domain: AACNDomain
    assessment_id: str
    current_level: CompetencyProficiencyLevel
    target_level: CompetencyProficiencyLevel
    proficiency_score: float = Field(ge=0, le=100)
    evidence_items: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)
    improvement_areas: list[str] = Field(default_factory=list)
    recommended_resources: list[str] = Field(default_factory=list)
    assessment_date: datetime
    assessor_id: str
    confidence_score: float = Field(ge=0, le=1.0)
    next_assessment_due: datetime | None = None


class StudentCompetencyProfile(BaseModel):
    student_id: str
    program: str
    semester: int
    competency_assessments: list[CompetencyAssessmentResult] = Field(
        default_factory=list
    )
    overall_gpa: float | None = None
    competency_gpa: float | None = None
    graduation_readiness_score: float = 0.0
    at_risk_competencies: list[str] = Field(default_factory=list)
    strengths_summary: list[str] = Field(default_factory=list)
    development_plan: list[str] = Field(default_factory=list)
    last_updated: datetime


# Learning Analytics Models
class LearningObjectiveProgress(BaseModel):
    objective_id: str
    objective_text: str
    competency_id: str
    mastery_level: float = Field(ge=0, le=1.0)
    attempts: int = 0
    time_spent_minutes: int = 0
    last_activity: datetime
    resources_accessed: list[str] = Field(default_factory=list)
    performance_trend: list[float] = Field(default_factory=list)


class StudentProgressMetrics(BaseModel):
    student_id: str
    time_period: str  # e.g., "semester_1", "month_2024_01"
    total_study_time_minutes: int = 0
    assessments_completed: int = 0
    average_score: float = 0.0
    improvement_rate: float = 0.0  # percentage improvement over time period
    engagement_score: float = Field(ge=0, le=100)
    consistency_score: float = Field(ge=0, le=100)  # regularity of study habits
    difficulty_preference: str = "balanced"  # easy, balanced, challenging
    learning_velocity: float = 0.0  # objectives mastered per week
    predicted_performance: dict[str, float] = Field(default_factory=dict)
    risk_factors: list[str] = Field(default_factory=list)
    success_factors: list[str] = Field(default_factory=list)


class CohortAnalytics(BaseModel):
    cohort_id: str
    program: str
    semester: int
    total_students: int
    active_students: int
    average_competency_score: float
    competency_distribution: dict[str, int] = Field(default_factory=dict)
    at_risk_students: int
    high_performers: int
    engagement_metrics: dict[str, float] = Field(default_factory=dict)
    completion_rates: dict[str, float] = Field(default_factory=dict)
    time_to_mastery: dict[str, float] = Field(default_factory=dict)
    resource_effectiveness: dict[str, float] = Field(default_factory=dict)
    comparison_to_historical: dict[str, float] = Field(default_factory=dict)


# Institutional Reporting Models
class ProgramEffectivenessMetrics(BaseModel):
    program_id: str
    program_name: str
    accreditation_period: str
    total_graduates: int
    nclex_pass_rate: float
    employment_rate: float
    employer_satisfaction: float
    competency_achievement_rates: dict[AACNDomain, float] = Field(default_factory=dict)
    curriculum_alignment_score: float = Field(ge=0, le=100)
    student_satisfaction: float = Field(ge=0, le=5.0)
    faculty_student_ratio: float
    resource_utilization: dict[str, float] = Field(default_factory=dict)
    improvement_recommendations: list[str] = Field(default_factory=list)
    accreditation_compliance: dict[str, bool] = Field(default_factory=dict)


class InstitutionalReport(BaseModel):
    institution_id: str
    report_period: str
    report_type: str  # "accreditation", "quarterly", "annual"
    programs: list[ProgramEffectivenessMetrics] = Field(default_factory=list)
    overall_metrics: dict[str, Any] = Field(default_factory=dict)
    benchmarking_data: dict[str, float] = Field(default_factory=dict)
    trend_analysis: dict[str, list[float]] = Field(default_factory=dict)
    action_items: list[str] = Field(default_factory=list)
    generated_date: datetime
    next_report_due: datetime


# Knowledge Gap Analysis Models
class KnowledgeGap(BaseModel):
    student_id: str
    competency_id: str
    gap_type: str  # "knowledge", "skill", "attitude"
    severity: str  # "low", "medium", "high", "critical"
    description: str
    evidence: list[str] = Field(default_factory=list)
    prerequisite_gaps: list[str] = Field(default_factory=list)
    recommended_interventions: list[str] = Field(default_factory=list)
    estimated_remediation_time: int  # hours
    priority_score: float = Field(ge=0, le=100)
    identified_date: datetime
    target_resolution_date: datetime
    status: str = "identified"  # identified, in_progress, resolved


class LearningPathRecommendation(BaseModel):
    student_id: str
    path_id: str = Field(default_factory=lambda: str(uuid4()))
    target_competencies: list[str]
    current_proficiency: dict[str, float] = Field(default_factory=dict)
    target_proficiency: dict[str, float] = Field(default_factory=dict)
    recommended_sequence: list[dict[str, Any]] = Field(default_factory=list)
    estimated_duration_hours: int
    difficulty_progression: str = "adaptive"  # linear, adaptive, accelerated
    personalization_factors: dict[str, Any] = Field(default_factory=dict)
    success_probability: float = Field(ge=0, le=1.0)
    alternative_paths: list[str] = Field(default_factory=list)
    created_date: datetime
    last_updated: datetime
