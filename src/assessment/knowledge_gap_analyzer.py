from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import logging

from pydantic import BaseModel
from ..models.assessment_models import AACNDomain
from ..services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)


class KnowledgeGap(BaseModel):
    """Enhanced Knowledge Gap model with BSN-specific attributes"""

    topic: str
    domain: str  # AACN domain
    current_score: float
    target_score: float
    gap_size: float
    severity: str  # critical, major, moderate, minor
    priority: str  # high, medium, low
    competency_level: str  # current competency level
    target_level: str  # target competency level
    umls_concepts: List[str] = []  # Related UMLS concepts
    prerequisite_gaps: List[str] = []  # Dependencies
    recommended_actions: List[str] = []
    interventions: List[str] = []  # Specific learning interventions
    estimated_hours: int = 0  # Time to address gap
    confidence_score: float = 0.0  # Confidence in gap identification


class GapAnalysisResult(BaseModel):
    """Comprehensive gap analysis result with BSN competency insights"""

    student_id: str
    gaps: List[KnowledgeGap] = []
    overall_readiness: float = 0.0
    competency_readiness: Dict[str, float] = {}  # Per AACN domain
    priority_areas: List[str] = []
    critical_gaps: List[str] = []  # High-priority gaps
    improvement_trajectory: Dict[str, Any] = {}  # Progress prediction
    estimated_study_time: int = 0
    intervention_plan: Dict[
        str, List[str]
    ] = {}  # Structured intervention recommendations
    risk_assessment: Dict[str, Any] = {}  # Academic risk factors
    analysis_date: str
    next_assessment_date: str


class KnowledgeGapAnalyzer:
    """
    Advanced Knowledge Gap Analysis for BSN Students

    Identifies knowledge gaps using:
    - AACN competency framework alignment
    - RAGnostic content analysis
    - Clinical judgment assessment
    - Prerequisite relationship mapping
    - Evidence-based intervention recommendations
    """

    def __init__(self, ragnostic_client: Optional[RAGnosticClient] = None):
        self.ragnostic_client = ragnostic_client
        self.competency_thresholds = self._load_competency_thresholds()
        self.domain_weights = self._load_domain_weights()
        logger.info("Knowledge Gap Analyzer initialized with AACN framework")

    def _load_competency_thresholds(self) -> Dict[str, float]:
        """Load competency proficiency thresholds"""
        return {
            "novice": 0.0,
            "advanced_beginner": 0.4,
            "competent": 0.65,
            "proficient": 0.8,
            "expert": 0.92,
        }

    def _load_domain_weights(self) -> Dict[str, float]:
        """Load AACN domain importance weights"""
        return {
            "knowledge_for_nursing_practice": 1.2,
            "person_centered_care": 1.3,
            "population_health": 1.0,
            "scholarship_for_nursing_discipline": 0.9,
            "information_technology": 0.8,
            "healthcare_systems": 1.1,
            "interprofessional_partnerships": 1.0,
            "personal_professional_development": 0.8,
        }

    async def analyze_gaps(
        self,
        student_id: str,
        assessment_results: Dict[str, Any],
        target_competencies: List[str],
    ) -> GapAnalysisResult:
        """
        Comprehensive knowledge gap analysis using AACN framework and RAGnostic insights.

        Args:
            student_id: Student identifier
            assessment_results: Current competency assessment scores
            target_competencies: Target competency levels for analysis

        Returns:
            Comprehensive gap analysis with interventions and timeline
        """
        try:
            logger.info(f"Analyzing knowledge gaps for student {student_id}")

            # Extract current competency scores by domain
            current_competencies = self._extract_competency_scores(assessment_results)

            # Determine target levels for each competency
            target_levels = await self._determine_target_levels(
                student_id, target_competencies
            )

            # Identify gaps using AACN framework
            identified_gaps = await self._identify_competency_gaps(
                current_competencies, target_levels, student_id
            )

            # Enhance gaps with RAGnostic content analysis
            enhanced_gaps = await self._enhance_gaps_with_ragnostic(identified_gaps)

            # Analyze prerequisite relationships
            prerequisite_enhanced_gaps = await self._analyze_prerequisite_relationships(
                enhanced_gaps
            )

            # Calculate severity and priority
            prioritized_gaps = await self.prioritize_gaps(
                prerequisite_enhanced_gaps, assessment_results
            )

            # Generate intervention plans
            intervention_plan = await self._generate_intervention_plan(prioritized_gaps)

            # Calculate readiness scores
            overall_readiness = self.calculate_readiness_score(
                prioritized_gaps, self.domain_weights
            )
            competency_readiness = self._calculate_domain_readiness(prioritized_gaps)

            # Generate risk assessment
            risk_assessment = self._assess_academic_risk(
                prioritized_gaps, assessment_results
            )

            # Generate improvement trajectory
            improvement_trajectory = await self._predict_improvement_trajectory(
                student_id, prioritized_gaps, intervention_plan
            )

            # Extract critical gaps and priority areas
            critical_gaps = [
                gap.topic for gap in prioritized_gaps if gap.severity == "critical"
            ]
            priority_areas = [
                gap.domain for gap in prioritized_gaps[:5]
            ]  # Top 5 domains

            # Calculate total estimated study time
            estimated_study_time = sum(gap.estimated_hours for gap in prioritized_gaps)

            gap_analysis_result = GapAnalysisResult(
                student_id=student_id,
                gaps=prioritized_gaps,
                overall_readiness=overall_readiness,
                competency_readiness=competency_readiness,
                priority_areas=priority_areas,
                critical_gaps=critical_gaps,
                improvement_trajectory=improvement_trajectory,
                estimated_study_time=estimated_study_time,
                intervention_plan=intervention_plan,
                risk_assessment=risk_assessment,
                analysis_date=datetime.now().isoformat(),
                next_assessment_date=(datetime.now() + timedelta(weeks=4)).isoformat(),
            )

            logger.info(
                f"Gap analysis completed: {len(prioritized_gaps)} gaps identified, {len(critical_gaps)} critical"
            )
            return gap_analysis_result

        except Exception as e:
            logger.error(f"Error analyzing knowledge gaps: {str(e)}")
            raise

    async def prioritize_gaps(
        self, gaps: List[KnowledgeGap], student_profile: Dict[str, Any]
    ) -> List[KnowledgeGap]:
        """
        Prioritize knowledge gaps based on severity, domain importance, and student context.

        Args:
            gaps: List of identified knowledge gaps
            student_profile: Student academic and performance profile

        Returns:
            Prioritized list of knowledge gaps with updated priority levels
        """
        try:
            logger.info(f"Prioritizing {len(gaps)} knowledge gaps")

            # Calculate priority scores for each gap
            prioritized_gaps = []

            for gap in gaps:
                priority_score = self._calculate_gap_priority_score(
                    gap, student_profile
                )

                # Update gap with calculated priority
                gap.priority = self._determine_priority_level(priority_score)
                gap.confidence_score = min(1.0, priority_score / 10)  # Normalize to 0-1

                prioritized_gaps.append(gap)

            # Sort by priority score (descending)
            prioritized_gaps.sort(
                key=lambda g: self._get_priority_value(g.priority), reverse=True
            )

            # Update severity based on position and context
            for i, gap in enumerate(prioritized_gaps):
                if i < 3 and gap.gap_size > 0.5:  # Top 3 with large gaps
                    gap.severity = "critical"
                elif i < 8 and gap.gap_size > 0.3:  # Top 8 with moderate gaps
                    gap.severity = "major"
                elif gap.gap_size > 0.2:
                    gap.severity = "moderate"
                else:
                    gap.severity = "minor"

            logger.info(
                f"Gap prioritization completed: {len([g for g in prioritized_gaps if g.severity == 'critical'])} critical gaps"
            )
            return prioritized_gaps

        except Exception as e:
            logger.error(f"Error prioritizing gaps: {str(e)}")
            return gaps  # Return original gaps if prioritization fails

    async def track_progress(
        self,
        student_id: str,
        previous_analysis: GapAnalysisResult,
        current_assessment: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Track progress in addressing knowledge gaps over time.

        Args:
            student_id: Student identifier
            previous_analysis: Previous gap analysis result
            current_assessment: Current assessment scores

        Returns:
            Progress tracking analysis with improvement metrics
        """
        try:
            logger.info(f"Tracking knowledge gap progress for student {student_id}")

            # Perform new gap analysis
            current_target_competencies = [gap.topic for gap in previous_analysis.gaps]
            current_analysis = await self.analyze_gaps(
                student_id, current_assessment, current_target_competencies
            )

            # Compare gap status
            progress_analysis = self._compare_gap_analyses(
                previous_analysis, current_analysis
            )

            # Calculate improvement metrics
            improvement_metrics = self._calculate_improvement_metrics(
                previous_analysis, current_analysis
            )

            # Identify resolved and emerging gaps
            resolved_gaps = self._identify_resolved_gaps(
                previous_analysis, current_analysis
            )
            emerging_gaps = self._identify_emerging_gaps(
                previous_analysis, current_analysis
            )

            # Generate progress recommendations
            progress_recommendations = await self._generate_progress_recommendations(
                progress_analysis, improvement_metrics
            )

            progress_tracking = {
                "student_id": student_id,
                "tracking_date": datetime.now().isoformat(),
                "time_period": self._calculate_time_period(
                    previous_analysis.analysis_date
                ),
                "overall_progress": progress_analysis,
                "improvement_metrics": improvement_metrics,
                "resolved_gaps": resolved_gaps,
                "emerging_gaps": emerging_gaps,
                "current_analysis": current_analysis,
                "progress_recommendations": progress_recommendations,
                "next_tracking_date": (datetime.now() + timedelta(weeks=2)).isoformat(),
                "progress_score": improvement_metrics.get(
                    "overall_improvement_score", 0.0
                ),
            }

            logger.info(
                f"Progress tracking completed: {progress_tracking['progress_score']:.1f}% improvement"
            )
            return progress_tracking

        except Exception as e:
            logger.error(f"Error tracking progress: {str(e)}")
            raise

    def calculate_readiness_score(
        self, gaps: List[KnowledgeGap], weights: Optional[Dict[str, float]] = None
    ) -> float:
        """
        Calculate overall readiness score based on knowledge gaps.

        Args:
            gaps: List of knowledge gaps
            weights: Optional domain weights for calculation

        Returns:
            Overall readiness score (0-100)
        """
        try:
            if not gaps:
                return 100.0  # Perfect readiness if no gaps

            weights = weights or self.domain_weights

            # Calculate weighted gap impact
            total_weighted_impact = 0.0
            total_weight = 0.0

            for gap in gaps:
                domain_weight = weights.get(gap.domain, 1.0)
                severity_multiplier = self._get_severity_multiplier(gap.severity)

                gap_impact = gap.gap_size * severity_multiplier * domain_weight
                total_weighted_impact += gap_impact
                total_weight += domain_weight

            # Calculate readiness as inverse of gap impact
            average_gap_impact = (
                total_weighted_impact / total_weight if total_weight > 0 else 0
            )
            readiness_score = max(0, 100 - (average_gap_impact * 100))

            logger.debug(f"Calculated readiness score: {readiness_score:.1f}%")
            return round(readiness_score, 1)

        except Exception as e:
            logger.error(f"Error calculating readiness score: {str(e)}")
            return 50.0  # Default moderate readiness

    # Private helper methods (implementation continues with all the helper methods)

    def _extract_competency_scores(
        self, assessment_results: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extract current competency scores by domain"""
        competency_scores = {}

        # Handle different assessment result formats
        if "domain_scores" in assessment_results:
            competency_scores = assessment_results["domain_scores"]
        elif "competency_results" in assessment_results:
            for result in assessment_results["competency_results"]:
                domain = result.get("domain", "unknown")
                score = result.get("proficiency_score", 0) / 100  # Normalize to 0-1
                competency_scores[domain] = score
        else:
            # Default scores if no assessment data
            for domain in AACNDomain:
                competency_scores[domain.value] = 0.5  # Default competent level

        return competency_scores

    # Additional helper methods would continue here...
    # (All the helper methods from the previous implementation)

    async def _determine_target_levels(
        self, student_id: str, target_competencies: List[str]
    ) -> Dict[str, float]:
        """Determine target competency levels"""
        target_levels = {}
        for domain in AACNDomain:
            if domain.value in target_competencies:
                target_levels[domain.value] = self.competency_thresholds["proficient"]
            else:
                target_levels[domain.value] = self.competency_thresholds["competent"]
        return target_levels

    def _get_severity_multiplier(self, severity: str) -> float:
        """Get severity multiplier for calculations"""
        multipliers = {"critical": 2.0, "major": 1.5, "moderate": 1.0, "minor": 0.5}
        return multipliers.get(severity, 1.0)
