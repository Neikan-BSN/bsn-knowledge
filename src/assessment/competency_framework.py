import logging
from datetime import datetime, timedelta
from enum import Enum
from statistics import mean, stdev
from typing import Any

from pydantic import BaseModel

from ..models.assessment_models import (
    AACNCompetency,
    AACNDomain,
    CompetencyAssessmentResult,
    CompetencyProficiencyLevel,
    KnowledgeGap,
    LearningPathRecommendation,
)
from ..services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)


# Legacy enum for backward compatibility
class CompetencyLevel(str, Enum):
    NOVICE = "novice"
    ADVANCED_BEGINNER = "advanced_beginner"
    COMPETENT = "competent"
    PROFICIENT = "proficient"
    EXPERT = "expert"


# Legacy Competency model for backward compatibility
class Competency(BaseModel):
    id: str
    name: str
    description: str
    category: str
    level: CompetencyLevel
    prerequisites: list[str]
    learning_objectives: list[str]
    assessment_criteria: list[str]


# Legacy CompetencyAssessment model for backward compatibility
class CompetencyAssessment(BaseModel):
    student_id: str
    competency_id: str
    current_level: CompetencyLevel
    target_level: CompetencyLevel
    strengths: list[str]
    improvement_areas: list[str]
    recommended_resources: list[str]
    assessment_date: str


class AACNCompetencyFramework:
    """
    AACN (American Association of Colleges of Nursing) Competency Framework Implementation

    This framework implements the AACN Essentials for Nursing Education with
    integration to RAGnostic's UMLS-enriched content and competency metadata.
    """

    def __init__(self, ragnostic_client: RAGnosticClient):
        self.ragnostic_client = ragnostic_client
        self.competencies: dict[str, AACNCompetency] = {}
        self.proficiency_thresholds = {
            CompetencyProficiencyLevel.NOVICE: 0.0,
            CompetencyProficiencyLevel.ADVANCED_BEGINNER: 0.4,
            CompetencyProficiencyLevel.COMPETENT: 0.6,
            CompetencyProficiencyLevel.PROFICIENT: 0.8,
            CompetencyProficiencyLevel.EXPERT: 0.9,
        }
        self._initialize_aacn_competencies()
        logger.info(
            "AACN Competency Framework initialized with %d competencies",
            len(self.competencies),
        )

    def _initialize_aacn_competencies(self):
        """Initialize the 8 AACN Essential domains with detailed competencies"""

        # Domain 1: Knowledge for Nursing Practice
        self.competencies["aacn_1_1"] = AACNCompetency(
            id="aacn_1_1",
            domain=AACNDomain.KNOWLEDGE_FOR_NURSING_PRACTICE,
            name="Pathophysiology and Pharmacology Integration",
            description="Integrate knowledge of pathophysiology and pharmacology to provide safe, evidence-based nursing care",
            sub_competencies=[
                "Analyze pathophysiological processes across the lifespan",
                "Apply pharmacokinetic and pharmacodynamic principles",
                "Identify drug interactions and adverse effects",
            ],
            learning_outcomes=[
                "Explain disease mechanisms and therapeutic interventions",
                "Calculate and administer medications safely",
                "Monitor patient responses to therapeutic interventions",
            ],
            assessment_methods=["case_studies", "simulation", "clinical_evaluation"],
            umls_concepts=[
                "C0031842",
                "C0031930",
                "C0013227",
            ],  # Pathophysiology, Pharmacology, Drugs
        )

        # Domain 2: Person-Centered Care
        self.competencies["aacn_2_1"] = AACNCompetency(
            id="aacn_2_1",
            domain=AACNDomain.PERSON_CENTERED_CARE,
            name="Holistic Assessment and Care Planning",
            description="Conduct comprehensive assessments and develop individualized care plans",
            sub_competencies=[
                "Perform systematic health assessments",
                "Develop evidence-based care plans",
                "Incorporate patient preferences and values",
            ],
            learning_outcomes=[
                "Complete comprehensive health histories",
                "Identify nursing diagnoses using standardized terminology",
                "Collaborate with patients in care planning",
            ],
            assessment_methods=["clinical_evaluation", "portfolio", "peer_review"],
            umls_concepts=[
                "C0199168",
                "C0032074",
                "C0006147",
            ],  # Assessment, Patient Care, Care Planning
        )

        # Domain 3: Population Health
        self.competencies["aacn_3_1"] = AACNCompetency(
            id="aacn_3_1",
            domain=AACNDomain.POPULATION_HEALTH,
            name="Health Promotion and Disease Prevention",
            description="Apply population health principles to promote wellness and prevent disease",
            sub_competencies=[
                "Analyze population health data and trends",
                "Design health promotion interventions",
                "Evaluate outcomes of preventive measures",
            ],
            learning_outcomes=[
                "Interpret epidemiological data",
                "Develop community health programs",
                "Advocate for health policy changes",
            ],
            assessment_methods=[
                "project_based",
                "community_assessment",
                "presentation",
            ],
            umls_concepts=[
                "C0032659",
                "C0679688",
                "C0679693",
            ],  # Population Health, Health Promotion, Disease Prevention
        )

        # Domain 4: Scholarship for Nursing Discipline
        self.competencies["aacn_4_1"] = AACNCompetency(
            id="aacn_4_1",
            domain=AACNDomain.SCHOLARSHIP_FOR_NURSING_DISCIPLINE,
            name="Evidence-Based Practice Integration",
            description="Integrate evidence-based practice principles in clinical decision making",
            sub_competencies=[
                "Critically appraise research literature",
                "Apply research findings to practice",
                "Participate in quality improvement initiatives",
            ],
            learning_outcomes=[
                "Evaluate research study designs and methodologies",
                "Synthesize evidence for practice recommendations",
                "Implement evidence-based protocols",
            ],
            assessment_methods=[
                "research_critique",
                "capstone_project",
                "quality_improvement",
            ],
            umls_concepts=[
                "C0013168",
                "C0005611",
                "C0034424",
            ],  # Evidence-Based Practice, Best Practices, Research
        )

        # Domain 5: Information Technology
        self.competencies["aacn_5_1"] = AACNCompetency(
            id="aacn_5_1",
            domain=AACNDomain.INFORMATION_TECHNOLOGY,
            name="Healthcare Informatics and Technology",
            description="Utilize healthcare technology and informatics to enhance patient care",
            sub_competencies=[
                "Navigate electronic health records effectively",
                "Apply clinical decision support systems",
                "Ensure health information privacy and security",
            ],
            learning_outcomes=[
                "Document nursing care using standardized terminologies",
                "Utilize technology for patient monitoring and assessment",
                "Protect patient health information",
            ],
            assessment_methods=["simulation", "practical_exam", "case_studies"],
            umls_concepts=[
                "C0025080",
                "C0013850",
                "C0018684",
            ],  # Medical Informatics, Electronic Records, Healthcare Technology
        )

        # Domain 6: Healthcare Systems
        self.competencies["aacn_6_1"] = AACNCompetency(
            id="aacn_6_1",
            domain=AACNDomain.HEALTHCARE_SYSTEMS,
            name="Quality and Safety in Healthcare Delivery",
            description="Promote quality and safety within healthcare systems",
            sub_competencies=[
                "Implement quality and safety standards",
                "Participate in system-level improvement",
                "Advocate for safe patient care environments",
            ],
            learning_outcomes=[
                "Apply quality improvement methodologies",
                "Identify and mitigate safety risks",
                "Collaborate in interprofessional quality initiatives",
            ],
            assessment_methods=[
                "quality_project",
                "safety_analysis",
                "systems_thinking",
            ],
            umls_concepts=[
                "C0034379",
                "C0036043",
                "C0018696",
            ],  # Quality of Care, Safety, Healthcare Systems
        )

        # Domain 7: Interprofessional Partnerships
        self.competencies["aacn_7_1"] = AACNCompetency(
            id="aacn_7_1",
            domain=AACNDomain.INTERPROFESSIONAL_PARTNERSHIPS,
            name="Collaborative Practice and Communication",
            description="Engage in effective interprofessional collaboration and communication",
            sub_competencies=[
                "Communicate effectively with healthcare teams",
                "Understand roles and responsibilities of team members",
                "Participate in shared decision-making",
            ],
            learning_outcomes=[
                "Demonstrate professional communication skills",
                "Collaborate effectively in team-based care",
                "Resolve conflicts constructively",
            ],
            assessment_methods=[
                "team_simulation",
                "communication_assessment",
                "peer_evaluation",
            ],
            umls_concepts=[
                "C0282116",
                "C0009462",
                "C0086541",
            ],  # Interprofessional Relations, Communication, Collaboration
        )

        # Domain 8: Personal and Professional Development
        self.competencies["aacn_8_1"] = AACNCompetency(
            id="aacn_8_1",
            domain=AACNDomain.PERSONAL_PROFESSIONAL_DEVELOPMENT,
            name="Professional Identity and Lifelong Learning",
            description="Develop professional identity and commitment to lifelong learning",
            sub_competencies=[
                "Demonstrate professional nursing values",
                "Engage in continuous professional development",
                "Maintain professional competence",
            ],
            learning_outcomes=[
                "Articulate nursing's unique contribution to healthcare",
                "Create and implement personal learning plans",
                "Maintain professional certifications and competencies",
            ],
            assessment_methods=[
                "portfolio",
                "reflection",
                "professional_development_plan",
            ],
            umls_concepts=[
                "C0028678",
                "C0033609",
                "C0013634",
            ],  # Nursing, Professional Development, Education Continuing
        )

    async def assess_competency(
        self,
        student_id: str,
        competency_id: str,
        performance_data: dict[str, Any],
        assessment_id: str,
        assessor_id: str = "system",
    ) -> CompetencyAssessmentResult:
        """
        Comprehensive competency assessment using RAGnostic-enhanced analysis

        Args:
            student_id: Unique identifier for the student
            competency_id: AACN competency identifier
            performance_data: Assessment results, quiz scores, clinical evaluations, etc.
            assessment_id: Identifier for this assessment instance
            assessor_id: Who conducted the assessment

        Returns:
            CompetencyAssessmentResult with detailed analysis and recommendations
        """
        try:
            competency = self.competencies.get(competency_id)
            if not competency:
                raise ValueError(f"Competency {competency_id} not found")

            logger.info(
                f"Assessing competency {competency_id} for student {student_id}"
            )

            # Calculate proficiency score from performance data
            proficiency_score = await self._calculate_proficiency_score(
                performance_data, competency
            )

            # Determine proficiency level
            current_level = self._determine_proficiency_level(proficiency_score)

            # Get evidence items from performance data
            evidence_items = self._extract_evidence_items(performance_data)

            # Analyze strengths and improvement areas using RAGnostic
            analysis = await self._analyze_performance_patterns(
                competency, performance_data, proficiency_score
            )

            # Get personalized recommendations
            recommendations = await self._get_competency_recommendations(
                student_id, competency, current_level, analysis
            )

            # Calculate confidence score based on data quality and consistency
            confidence_score = self._calculate_confidence_score(
                performance_data, evidence_items
            )

            # Schedule next assessment
            next_assessment = self._calculate_next_assessment_date(
                current_level, proficiency_score
            )

            assessment_result = CompetencyAssessmentResult(
                student_id=student_id,
                competency_id=competency_id,
                domain=competency.domain,
                assessment_id=assessment_id,
                current_level=current_level,
                target_level=competency.minimum_level,
                proficiency_score=proficiency_score,
                evidence_items=evidence_items,
                strengths=analysis.get("strengths", []),
                improvement_areas=analysis.get("improvement_areas", []),
                recommended_resources=recommendations,
                assessment_date=datetime.now(),
                assessor_id=assessor_id,
                confidence_score=confidence_score,
                next_assessment_due=next_assessment,
            )

            logger.info(
                f"Competency assessment completed: {current_level} level with {proficiency_score:.1f}% proficiency"
            )
            return assessment_result

        except Exception as e:
            logger.error(
                f"Error assessing competency {competency_id} for student {student_id}: {str(e)}"
            )
            raise

    async def _calculate_proficiency_score(
        self, performance_data: dict[str, Any], competency: AACNCompetency
    ) -> float:
        """
        Calculate weighted proficiency score from various assessment types
        """
        scores = []
        weights = []

        # Assessment scores (quizzes, exams)
        if "assessment_scores" in performance_data:
            assessment_avg = mean(performance_data["assessment_scores"])
            scores.append(assessment_avg)
            weights.append(0.4)  # 40% weight

        # Clinical evaluation scores
        if "clinical_scores" in performance_data:
            clinical_avg = mean(performance_data["clinical_scores"])
            scores.append(clinical_avg)
            weights.append(0.3)  # 30% weight

        # Simulation performance
        if "simulation_scores" in performance_data:
            sim_avg = mean(performance_data["simulation_scores"])
            scores.append(sim_avg)
            weights.append(0.2)  # 20% weight

        # Self-assessment and reflection
        if "self_assessment" in performance_data:
            self_score = performance_data["self_assessment"]
            scores.append(self_score)
            weights.append(0.1)  # 10% weight

        if not scores:
            logger.warning("No performance data available for proficiency calculation")
            return 0.0

        # Calculate weighted average
        weighted_score = sum(
            score * weight for score, weight in zip(scores, weights, strict=False)
        )
        total_weight = sum(weights)

        return min(
            100.0, max(0.0, weighted_score / total_weight if total_weight > 0 else 0.0)
        )

    def _determine_proficiency_level(self, score: float) -> CompetencyProficiencyLevel:
        """
        Map proficiency score to AACN proficiency level
        """
        score_normalized = score / 100.0

        for level in reversed(list(CompetencyProficiencyLevel)):
            if score_normalized >= self.proficiency_thresholds[level]:
                return level

        return CompetencyProficiencyLevel.NOVICE

    def _extract_evidence_items(self, performance_data: dict[str, Any]) -> list[str]:
        """
        Extract evidence items from performance data for documentation
        """
        evidence = []

        if "assessment_scores" in performance_data:
            evidence.append(
                f"Assessment average: {mean(performance_data['assessment_scores']):.1f}%"
            )

        if "clinical_scores" in performance_data:
            evidence.append(
                f"Clinical evaluation average: {mean(performance_data['clinical_scores']):.1f}%"
            )

        if "simulation_scores" in performance_data:
            evidence.append(
                f"Simulation performance average: {mean(performance_data['simulation_scores']):.1f}%"
            )

        if "artifacts" in performance_data:
            evidence.extend(performance_data["artifacts"])

        if "observations" in performance_data:
            evidence.extend(performance_data["observations"])

        return evidence

    async def _analyze_performance_patterns(
        self,
        competency: AACNCompetency,
        performance_data: dict[str, Any],
        proficiency_score: float,
    ) -> dict[str, list[str]]:
        """
        Use RAGnostic to analyze performance patterns and identify strengths/weaknesses
        """
        try:
            # Query RAGnostic for competency-specific analysis
            query = f"""Analyze nursing student performance in {competency.domain.value} competency.
            Performance score: {proficiency_score:.1f}%.
            Sub-competencies: {", ".join(competency.sub_competencies)}.
            Provide strengths and improvement areas."""

            response = await self.ragnostic_client.search_content(
                query=query,
                filters={
                    "content_type": "competency_analysis",
                    "domain": competency.domain.value,
                    "umls_concepts": competency.umls_concepts,
                },
                limit=5,
            )

            # Extract analysis from RAGnostic response
            analysis = {"strengths": [], "improvement_areas": []}

            if response.get("items"):
                for item in response["items"]:
                    item.get("content", "")
                    metadata = item.get("metadata", {})

                    # Extract strengths and weaknesses based on proficiency score
                    if proficiency_score >= 80:
                        analysis["strengths"].append(
                            f"Strong performance in {metadata.get('skill_area', 'core competencies')}"
                        )
                    elif proficiency_score < 60:
                        analysis["improvement_areas"].append(
                            f"Needs development in {metadata.get('skill_area', 'foundational concepts')}"
                        )

            # Fallback analysis if RAGnostic doesn't provide sufficient data
            if not analysis["strengths"] and proficiency_score >= 70:
                analysis["strengths"] = [
                    f"Demonstrates {competency.domain.value} knowledge"
                ]

            if not analysis["improvement_areas"] and proficiency_score < 70:
                analysis["improvement_areas"] = [
                    f"Requires additional practice in {competency.domain.value}"
                ]

            return analysis

        except Exception as e:
            logger.warning(f"RAGnostic analysis failed, using fallback: {str(e)}")
            # Fallback analysis
            analysis = {"strengths": [], "improvement_areas": []}

            if proficiency_score >= 80:
                analysis["strengths"] = [f"Strong {competency.domain.value} competency"]
            elif proficiency_score < 60:
                analysis["improvement_areas"] = [
                    f"Needs improvement in {competency.domain.value}"
                ]

            return analysis

    async def _get_competency_recommendations(
        self,
        student_id: str,
        competency: AACNCompetency,
        current_level: CompetencyProficiencyLevel,
        analysis: dict[str, list[str]],
    ) -> list[str]:
        """
        Get personalized learning resource recommendations from RAGnostic
        """
        try:
            f"""Recommend learning resources for nursing student to improve {competency.domain.value} competency.
            Current level: {current_level}. Target level: {competency.minimum_level}.
            Learning outcomes: {", ".join(competency.learning_outcomes)}."""

            response = await self.ragnostic_client.get_content_by_metadata(
                metadata_filters={
                    "content_type": "learning_resource",
                    "competency_domain": competency.domain.value,
                    "difficulty_level": current_level.value,
                    "umls_concepts": competency.umls_concepts,
                },
                sort_by="relevance",
                limit=10,
            )

            recommendations = []

            if response.get("items"):
                for item in response["items"][:5]:  # Top 5 recommendations
                    title = item.get("metadata", {}).get("title", "Learning Resource")
                    resource_type = item.get("metadata", {}).get(
                        "resource_type", "study_material"
                    )
                    recommendations.append(f"{title} ({resource_type})")

            # Add competency-specific recommendations
            if current_level == CompetencyProficiencyLevel.NOVICE:
                recommendations.append(
                    f"Review foundational concepts in {competency.domain.value}"
                )
                recommendations.append("Complete prerequisite learning modules")

            return recommendations or [
                f"Study {competency.domain.value} learning materials"
            ]

        except Exception as e:
            logger.warning(f"Failed to get RAGnostic recommendations: {str(e)}")
            return [f"Review {competency.domain.value} study materials"]

    def _calculate_confidence_score(
        self, performance_data: dict[str, Any], evidence_items: list[str]
    ) -> float:
        """
        Calculate confidence score based on data quality and consistency
        """
        confidence_factors = []

        # Data completeness
        data_points = len([k for k in performance_data.keys() if performance_data[k]])
        confidence_factors.append(min(1.0, data_points / 4))  # Expect 4 types of data

        # Evidence quality
        evidence_score = min(1.0, len(evidence_items) / 5)  # Expect 5 evidence items
        confidence_factors.append(evidence_score)

        # Score consistency (if multiple assessments)
        if (
            "assessment_scores" in performance_data
            and len(performance_data["assessment_scores"]) > 1
        ):
            scores = performance_data["assessment_scores"]
            if len(scores) > 1:
                consistency = 1.0 - (
                    stdev(scores) / 100.0
                )  # Lower std dev = higher consistency
                confidence_factors.append(max(0.0, min(1.0, consistency)))

        return mean(confidence_factors) if confidence_factors else 0.5

    def _calculate_next_assessment_date(
        self, level: CompetencyProficiencyLevel, score: float
    ) -> datetime:
        """
        Calculate when the next competency assessment should occur
        """
        # Base intervals by proficiency level
        intervals = {
            CompetencyProficiencyLevel.NOVICE: 30,  # 1 month
            CompetencyProficiencyLevel.ADVANCED_BEGINNER: 60,  # 2 months
            CompetencyProficiencyLevel.COMPETENT: 90,  # 3 months
            CompetencyProficiencyLevel.PROFICIENT: 180,  # 6 months
            CompetencyProficiencyLevel.EXPERT: 365,  # 1 year
        }

        base_days = intervals[level]

        # Adjust based on score within level
        if score < 50:  # Struggling, assess more frequently
            base_days = int(base_days * 0.5)
        elif score > 90:  # Excelling, can extend interval
            base_days = int(base_days * 1.5)

        return datetime.now() + timedelta(days=base_days)

    async def get_competency_gaps(
        self,
        student_id: str,
        target_competencies: list[str],
        current_assessments: list[CompetencyAssessmentResult] | None = None,
    ) -> dict[str, list[KnowledgeGap]]:
        """
        Identify competency gaps and create targeted remediation plans

        Args:
            student_id: Student identifier
            target_competencies: List of competency IDs to analyze
            current_assessments: Recent competency assessment results

        Returns:
            Dictionary mapping competency domains to identified knowledge gaps
        """
        try:
            logger.info(f"Analyzing competency gaps for student {student_id}")
            gaps_by_domain: dict[str, list[KnowledgeGap]] = {}

            for competency_id in target_competencies:
                competency = self.competencies.get(competency_id)
                if not competency:
                    continue

                domain = competency.domain.value
                if domain not in gaps_by_domain:
                    gaps_by_domain[domain] = []

                # Find current assessment for this competency
                current_assessment = None
                if current_assessments:
                    current_assessment = next(
                        (
                            a
                            for a in current_assessments
                            if a.competency_id == competency_id
                        ),
                        None,
                    )

                # Identify gaps based on current performance
                if current_assessment:
                    gaps = await self._identify_competency_gaps(
                        student_id, competency, current_assessment
                    )
                    gaps_by_domain[domain].extend(gaps)
                else:
                    # No assessment data - create gap for entire competency
                    gap = KnowledgeGap(
                        student_id=student_id,
                        competency_id=competency_id,
                        gap_type="knowledge",
                        severity="medium",
                        description=f"No assessment data available for {competency.name}",
                        evidence=["Missing competency assessment"],
                        recommended_interventions=[
                            "Complete initial competency assessment"
                        ],
                        estimated_remediation_time=10,
                        priority_score=60.0,
                        identified_date=datetime.now(),
                        target_resolution_date=datetime.now() + timedelta(weeks=4),
                    )
                    gaps_by_domain[domain].append(gap)

            logger.info(f"Identified gaps across {len(gaps_by_domain)} domains")
            return gaps_by_domain

        except Exception as e:
            logger.error(f"Error analyzing competency gaps: {str(e)}")
            raise

    async def _identify_competency_gaps(
        self,
        student_id: str,
        competency: AACNCompetency,
        assessment: CompetencyAssessmentResult,
    ) -> list[KnowledgeGap]:
        """
        Identify specific gaps within a competency based on assessment results
        """
        gaps = []

        # Overall proficiency gap
        target_score = self.proficiency_thresholds[competency.minimum_level] * 100
        if assessment.proficiency_score < target_score:
            severity = self._calculate_gap_severity(
                assessment.proficiency_score, target_score
            )

            gap = KnowledgeGap(
                student_id=student_id,
                competency_id=competency.id,
                gap_type="knowledge",
                severity=severity,
                description=f"Below target proficiency in {competency.name}",
                evidence=[
                    f"Current: {assessment.proficiency_score:.1f}%, Target: {target_score:.1f}%"
                ],
                recommended_interventions=assessment.recommended_resources,
                estimated_remediation_time=self._estimate_remediation_time(
                    assessment.proficiency_score, target_score
                ),
                priority_score=self._calculate_priority_score(
                    assessment.proficiency_score, target_score, competency
                ),
                identified_date=datetime.now(),
                target_resolution_date=assessment.next_assessment_due
                or (datetime.now() + timedelta(weeks=8)),
            )
            gaps.append(gap)

        # Sub-competency gaps (based on improvement areas)
        for area in assessment.improvement_areas:
            gap = KnowledgeGap(
                student_id=student_id,
                competency_id=competency.id,
                gap_type="skill",
                severity="medium",
                description=f"Improvement needed: {area}",
                evidence=["Identified in competency assessment"],
                recommended_interventions=[f"Focus on {area} development"],
                estimated_remediation_time=20,
                priority_score=50.0,
                identified_date=datetime.now(),
                target_resolution_date=datetime.now() + timedelta(weeks=6),
            )
            gaps.append(gap)

        return gaps

    def _calculate_gap_severity(self, current_score: float, target_score: float) -> str:
        """
        Calculate severity of competency gap
        """
        gap_size = target_score - current_score

        if gap_size >= 30:
            return "critical"
        elif gap_size >= 20:
            return "high"
        elif gap_size >= 10:
            return "medium"
        else:
            return "low"

    def _estimate_remediation_time(
        self, current_score: float, target_score: float
    ) -> int:
        """
        Estimate hours needed for remediation based on gap size
        """
        gap_size = target_score - current_score
        # Estimate 1 hour per 2 percentage points of gap
        return max(5, int(gap_size / 2))

    def _calculate_priority_score(
        self, current_score: float, target_score: float, competency: AACNCompetency
    ) -> float:
        """
        Calculate priority score for addressing this gap
        """
        # Base score on gap size
        gap_size = target_score - current_score
        gap_priority = min(50.0, gap_size * 1.5)

        # Add competency weight
        competency_weight = competency.weight * 30

        # Add domain criticality (some domains are more critical for safety)
        domain_weights = {
            AACNDomain.PERSON_CENTERED_CARE: 20,
            AACNDomain.KNOWLEDGE_FOR_NURSING_PRACTICE: 15,
            AACNDomain.HEALTHCARE_SYSTEMS: 10,
            AACNDomain.POPULATION_HEALTH: 5,
        }
        domain_priority = domain_weights.get(competency.domain, 5)

        return min(100.0, gap_priority + competency_weight + domain_priority)

    async def recommend_learning_path(
        self,
        student_id: str,
        target_competencies: list[str],
        current_proficiency: dict[str, float] | None = None,
        learning_preferences: dict[str, Any] | None = None,
    ) -> LearningPathRecommendation:
        """
        Generate personalized learning path recommendations using RAGnostic insights

        Args:
            student_id: Student identifier
            target_competencies: List of competency IDs to achieve
            current_proficiency: Current proficiency scores by competency
            learning_preferences: Student learning style preferences

        Returns:
            LearningPathRecommendation with sequenced learning activities
        """
        try:
            logger.info(f"Generating learning path for student {student_id}")

            current_proficiency = current_proficiency or {}
            learning_preferences = learning_preferences or {}

            # Analyze prerequisite dependencies
            prerequisite_graph = await self._build_prerequisite_graph(
                target_competencies
            )

            # Sequence competencies based on prerequisites and current proficiency
            learning_sequence = self._optimize_learning_sequence(
                target_competencies, prerequisite_graph, current_proficiency
            )

            # Generate detailed learning activities for each competency
            detailed_sequence = []
            total_hours = 0

            for competency_id in learning_sequence:
                competency = self.competencies.get(competency_id)
                if not competency:
                    continue

                current_level = self._determine_proficiency_level(
                    current_proficiency.get(competency_id, 0.0)
                )

                activities = await self._generate_learning_activities(
                    competency, current_level, learning_preferences
                )

                competency_hours = sum(
                    activity.get("estimated_hours", 5) for activity in activities
                )
                total_hours += competency_hours

                detailed_sequence.append(
                    {
                        "competency_id": competency_id,
                        "competency_name": competency.name,
                        "domain": competency.domain.value,
                        "current_level": current_level.value,
                        "target_level": competency.minimum_level.value,
                        "activities": activities,
                        "estimated_hours": competency_hours,
                    }
                )

            # Calculate success probability based on historical data
            success_probability = self._calculate_success_probability(
                student_id, target_competencies, current_proficiency
            )

            # Generate alternative paths
            alternative_paths = await self._generate_alternative_paths(
                target_competencies, current_proficiency, learning_preferences
            )

            recommendation = LearningPathRecommendation(
                student_id=student_id,
                target_competencies=target_competencies,
                current_proficiency=current_proficiency,
                target_proficiency={
                    comp_id: self.proficiency_thresholds[
                        self.competencies[comp_id].minimum_level
                    ]
                    * 100
                    for comp_id in target_competencies
                    if comp_id in self.competencies
                },
                recommended_sequence=detailed_sequence,
                estimated_duration_hours=total_hours,
                difficulty_progression="adaptive",
                personalization_factors=learning_preferences,
                success_probability=success_probability,
                alternative_paths=alternative_paths,
                created_date=datetime.now(),
                last_updated=datetime.now(),
            )

            logger.info(
                f"Generated learning path with {len(detailed_sequence)} competencies, {total_hours} hours"
            )
            return recommendation

        except Exception as e:
            logger.error(f"Error generating learning path: {str(e)}")
            raise

    async def _build_prerequisite_graph(
        self, competency_ids: list[str]
    ) -> dict[str, list[str]]:
        """
        Build prerequisite dependency graph for competencies
        """
        graph = {}

        for comp_id in competency_ids:
            competency = self.competencies.get(comp_id)
            if competency:
                # Filter prerequisites to only include those in our target list
                relevant_prereqs = [
                    prereq
                    for prereq in competency.prerequisites
                    if prereq in competency_ids
                ]
                graph[comp_id] = relevant_prereqs

        return graph

    def _optimize_learning_sequence(
        self,
        competency_ids: list[str],
        prerequisite_graph: dict[str, list[str]],
        current_proficiency: dict[str, float],
    ) -> list[str]:
        """
        Optimize learning sequence using topological sort and proficiency analysis
        """
        # Topological sort for prerequisite dependencies
        in_degree = {comp_id: 0 for comp_id in competency_ids}

        for comp_id in competency_ids:
            for prereq in prerequisite_graph.get(comp_id, []):
                if prereq in in_degree:
                    in_degree[comp_id] += 1

        # Start with competencies that have no prerequisites or low proficiency
        queue = []
        for comp_id in competency_ids:
            if in_degree[comp_id] == 0 or current_proficiency.get(comp_id, 0) < 60:
                queue.append(comp_id)

        sequence = []

        while queue:
            # Sort by current proficiency (work on weakest areas first)
            queue.sort(key=lambda x: current_proficiency.get(x, 0))
            current = queue.pop(0)
            sequence.append(current)

            # Update in-degrees for dependent competencies
            for comp_id in competency_ids:
                if current in prerequisite_graph.get(comp_id, []):
                    in_degree[comp_id] -= 1
                    if in_degree[comp_id] == 0:
                        queue.append(comp_id)

        # Add any remaining competencies (shouldn't happen with valid graph)
        remaining = [c for c in competency_ids if c not in sequence]
        sequence.extend(remaining)

        return sequence

    async def _generate_learning_activities(
        self,
        competency: AACNCompetency,
        current_level: CompetencyProficiencyLevel,
        preferences: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Generate specific learning activities for a competency
        """
        activities = []

        # Query RAGnostic for relevant learning resources
        try:
            response = await self.ragnostic_client.get_content_by_metadata(
                metadata_filters={
                    "content_type": "learning_activity",
                    "competency_domain": competency.domain.value,
                    "difficulty_level": current_level.value,
                    "umls_concepts": competency.umls_concepts,
                },
                limit=8,
            )

            if response.get("items"):
                for item in response["items"]:
                    metadata = item.get("metadata", {})
                    activities.append(
                        {
                            "type": metadata.get("activity_type", "reading"),
                            "title": metadata.get("title", "Learning Activity"),
                            "description": item.get("content", "")[:200] + "...",
                            "estimated_hours": metadata.get("duration_hours", 2),
                            "difficulty": metadata.get(
                                "difficulty", current_level.value
                            ),
                            "resource_url": metadata.get("url", ""),
                            "assessment_method": metadata.get(
                                "assessment", "self_check"
                            ),
                        }
                    )

        except Exception as e:
            logger.warning(f"Failed to get RAGnostic activities: {str(e)}")

        # Add standard activities if RAGnostic didn't provide enough
        if len(activities) < 3:
            standard_activities = self._get_standard_activities(
                competency, current_level
            )
            activities.extend(standard_activities)

        # Limit to reasonable number and sort by estimated effectiveness
        return activities[:6]

    def _get_standard_activities(
        self, competency: AACNCompetency, level: CompetencyProficiencyLevel
    ) -> list[dict[str, Any]]:
        """
        Generate standard learning activities based on competency and level
        """
        activities = []

        # Reading assignments
        activities.append(
            {
                "type": "reading",
                "title": f"{competency.name} - Foundational Reading",
                "description": f"Core concepts in {competency.domain.value}",
                "estimated_hours": 3,
                "difficulty": level.value,
                "assessment_method": "quiz",
            }
        )

        # Case studies
        if level in [
            CompetencyProficiencyLevel.COMPETENT,
            CompetencyProficiencyLevel.PROFICIENT,
        ]:
            activities.append(
                {
                    "type": "case_study",
                    "title": f"{competency.name} - Case Analysis",
                    "description": f"Apply {competency.domain.value} principles to real scenarios",
                    "estimated_hours": 4,
                    "difficulty": level.value,
                    "assessment_method": "written_analysis",
                }
            )

        # Simulation or practical exercises
        if "simulation" in competency.assessment_methods:
            activities.append(
                {
                    "type": "simulation",
                    "title": f"{competency.name} - Skills Practice",
                    "description": f"Hands-on practice of {competency.domain.value} skills",
                    "estimated_hours": 5,
                    "difficulty": level.value,
                    "assessment_method": "performance_checklist",
                }
            )

        return activities

    def _calculate_success_probability(
        self, student_id: str, competencies: list[str], current_prof: dict[str, float]
    ) -> float:
        """
        Calculate probability of success based on current proficiency and historical patterns
        """
        if not current_prof:
            return 0.7  # Default moderate confidence

        avg_proficiency = mean(current_prof.values()) if current_prof else 0

        # Base probability on current average proficiency
        base_prob = min(0.95, max(0.3, avg_proficiency / 100.0))

        # Adjust for number of competencies (more competencies = lower probability)
        complexity_factor = max(0.7, 1.0 - (len(competencies) - 1) * 0.05)

        # Adjust for consistency (lower variation = higher probability)
        if len(current_prof.values()) > 1:
            variation = stdev(current_prof.values()) / 100.0
            consistency_factor = max(0.8, 1.0 - variation)
        else:
            consistency_factor = 0.9

        return min(0.95, base_prob * complexity_factor * consistency_factor)

    async def _generate_alternative_paths(
        self,
        competencies: list[str],
        current_prof: dict[str, float],
        preferences: dict[str, Any],
    ) -> list[str]:
        """
        Generate alternative learning path identifiers
        """
        alternatives = []

        # Different sequencing strategies
        alternatives.append("difficulty_ascending")  # Easiest first
        alternatives.append("difficulty_descending")  # Hardest first
        alternatives.append("domain_grouped")  # Group by AACN domain

        # Preference-based alternatives
        if preferences.get("learning_style") == "visual":
            alternatives.append("visual_heavy")
        elif preferences.get("learning_style") == "kinesthetic":
            alternatives.append("hands_on_focus")

        return alternatives[:3]  # Limit to 3 alternatives

    def get_all_competencies(self) -> list[AACNCompetency]:
        """
        Get all AACN competencies in the framework
        """
        return list(self.competencies.values())

    def get_competencies_by_domain(self, domain: AACNDomain) -> list[AACNCompetency]:
        """
        Get competencies for a specific AACN domain
        """
        return [c for c in self.competencies.values() if c.domain == domain]

    def get_competency_by_id(self, competency_id: str) -> AACNCompetency | None:
        """
        Get a specific competency by ID
        """
        return self.competencies.get(competency_id)


# Legacy CompetencyFramework for backward compatibility
class CompetencyFramework(AACNCompetencyFramework):
    """
    Legacy wrapper for backward compatibility
    """

    def __init__(self, ragnostic_client: RAGnosticClient | None = None):
        if ragnostic_client is None:
            # Create a minimal client for compatibility
            ragnostic_client = RAGnosticClient("http://localhost:8000")

        super().__init__(ragnostic_client)
        logger.info("Legacy CompetencyFramework initialized")
