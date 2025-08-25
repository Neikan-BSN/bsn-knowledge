"""
B.5 Adaptive Learning Engine Implementation

Personalizes learning experiences based on student performance, leveraging:
- B.4 Learning Analytics foundation for student progress analysis
- Knowledge Gap Analysis for targeted content recommendations
- Learning Path Optimization for real-time adaptive adjustments
- RAGnostic integration for intelligent content retrieval
- AACN competency framework for adaptive difficulty scaling

Built per REVISED_PHASE3_PLAN.md B.5 specifications
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import mean, stdev
from typing import Any

from ..assessment.knowledge_gap_analyzer import GapAnalysisResult, KnowledgeGapAnalyzer
from ..assessment.learning_path_optimizer import (
    LearningPathOptimizer,
    OptimizedLearningPath,
)
from ..models.assessment_models import AACNDomain
from .analytics_service import AnalyticsService
from .learning_analytics import LearningAnalytics
from .ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)


@dataclass
class PersonalizationFactors:
    """Student personalization factors for adaptive algorithms"""

    learning_style: str
    difficulty_preference: str
    pace_preference: str  # "slow", "moderate", "fast"
    content_type_preferences: list[str] = field(default_factory=list)
    performance_patterns: dict[str, float] = field(default_factory=dict)
    engagement_patterns: dict[str, Any] = field(default_factory=dict)
    confidence_levels: dict[str, float] = field(default_factory=dict)
    time_constraints: dict[str, int] = field(default_factory=dict)


@dataclass
class AdaptiveContentRecommendation:
    """Personalized content recommendation with adaptive parameters"""

    content_id: str
    title: str
    content_type: str
    difficulty_level: str
    estimated_duration: int
    personalization_score: float
    adaptive_reason: str
    learning_objectives: list[str] = field(default_factory=list)
    prerequisite_concepts: list[str] = field(default_factory=list)
    success_probability: float = 0.0
    engagement_prediction: float = 0.0


@dataclass
class DifficultyAdjustment:
    """Dynamic difficulty adjustment parameters"""

    current_difficulty: str
    recommended_difficulty: str
    adjustment_reason: str
    confidence_score: float
    supporting_metrics: dict[str, Any] = field(default_factory=dict)
    adjustment_magnitude: float = 0.0  # -1.0 to 1.0 scale


@dataclass
class LearningPathAdaptation:
    """Real-time learning path adaptation"""

    original_path_id: str
    adapted_path_id: str
    adaptations_made: list[str] = field(default_factory=list)
    performance_triggers: list[str] = field(default_factory=list)
    estimated_improvement: float = 0.0
    adaptation_confidence: float = 0.0


class AdaptiveLearningEngine:
    """
    Advanced Adaptive Learning Engine for BSN Knowledge Application

    Personalizes learning experiences using:
    - Student performance analysis from B.4 Learning Analytics
    - Knowledge gap identification and targeting
    - Dynamic difficulty adjustment algorithms
    - Real-time learning path optimization
    - Content recommendation based on performance patterns
    - Integration with RAGnostic for intelligent content retrieval

    Key Features:
    - Performance-based personalization using B.4 analytics data
    - Dynamic difficulty adjustment based on competency progression
    - Real-time learning path modification using knowledge gap severity
    - Intelligent content sequencing with RAGnostic prerequisite graphs
    - Adaptive study plan generation with B.4's path optimization
    """

    def __init__(
        self,
        learning_analytics: LearningAnalytics,
        ragnostic_client: RAGnosticClient,
        analytics_service: AnalyticsService,
        gap_analyzer: KnowledgeGapAnalyzer,
        path_optimizer: LearningPathOptimizer,
    ):
        """
        Initialize Adaptive Learning Engine with B.4 analytics integration

        Args:
            learning_analytics: B.4 LearningAnalytics class instance
            ragnostic_client: RAGnostic integration for content retrieval
            analytics_service: Analytics service for student data
            gap_analyzer: B.4 KnowledgeGapAnalyzer for targeted personalization
            path_optimizer: B.4 LearningPathOptimizer for real-time adjustments
        """
        self.learning_analytics = learning_analytics
        self.ragnostic_client = ragnostic_client
        self.analytics_service = analytics_service
        self.gap_analyzer = gap_analyzer
        self.path_optimizer = path_optimizer

        # Adaptive algorithm parameters
        self.difficulty_adjustment_threshold = (
            0.7  # Performance threshold for adjustments
        )
        self.personalization_cache = {}  # Performance cache for recommendations
        self.adaptation_history = {}  # Track adaptation effectiveness

        # Performance thresholds for adaptive adjustments
        self.performance_thresholds = {
            "excellent": 0.9,
            "good": 0.8,
            "satisfactory": 0.7,
            "needs_improvement": 0.6,
            "struggling": 0.5,
        }

        logger.info(
            "Adaptive Learning Engine initialized with B.4 analytics integration"
        )

    async def generate_personalized_content(
        self,
        student_profile: dict[str, Any],
        target_competencies: list[str] | None = None,
        content_filters: dict[str, Any] | None = None,
    ) -> list[AdaptiveContentRecommendation]:
        """
        Generate personalized content based on student performance and preferences.

        Leverages:
        - B.4 Learning Analytics for student strengths/weaknesses analysis
        - RAGnostic for content search based on performance patterns
        - Dynamic difficulty adjustment using competency data
        - Personalized study plans with B.4 gap analysis integration

        Args:
            student_profile: Student profile with preferences and performance history
            target_competencies: Specific competencies to target (optional)
            content_filters: Additional filters for content selection

        Returns:
            List of personalized content recommendations with adaptive parameters
        """
        try:
            student_id = student_profile.get("student_id")
            logger.info(f"Generating personalized content for student {student_id}")

            # Analyze student performance using B.4 Learning Analytics
            performance_analysis = (
                await self.learning_analytics.analyze_student_progress(student_id)
            )

            # Extract personalization factors
            personalization_factors = await self._extract_personalization_factors(
                student_profile, performance_analysis
            )

            # Identify knowledge gaps using B.4 KnowledgeGapAnalyzer
            knowledge_gaps = performance_analysis.get("knowledge_gaps", [])

            # Generate content recommendations based on gaps and preferences
            content_recommendations = await self._generate_adaptive_recommendations(
                student_id, knowledge_gaps, personalization_factors, target_competencies
            )

            # Apply difficulty adjustments based on performance patterns
            adjusted_recommendations = await self._apply_difficulty_adjustments(
                content_recommendations, performance_analysis, personalization_factors
            )

            # Use RAGnostic to enhance recommendations with related content
            enhanced_recommendations = await self._enhance_with_ragnostic_content(
                adjusted_recommendations, performance_analysis
            )

            # Rank recommendations by personalization score
            final_recommendations = self._rank_by_personalization_score(
                enhanced_recommendations
            )

            # Cache recommendations for performance
            cache_key = f"personalized_content_{student_id}"
            self.personalization_cache[cache_key] = {
                "recommendations": final_recommendations,
                "generated_at": datetime.now().timestamp(),
                "ttl": 1800,  # 30 minutes
            }

            logger.info(
                f"Generated {len(final_recommendations)} personalized recommendations for {student_id}"
            )
            return final_recommendations[:10]  # Return top 10 recommendations

        except Exception as e:
            logger.error(f"Error generating personalized content: {str(e)}")
            raise

    async def optimize_learning_path(
        self,
        student_id: str,
        target_competencies: list[str],
        time_constraints: dict[str, int] | None = None,
        performance_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Optimize learning path using RAGnostic prerequisite graphs and B.4 analytics.

        Features:
        - RAGnostic prerequisite graph integration for optimal sequencing
        - B.4 analytics for competency-based path calculation
        - Real-time progress adjustment using B.4 tracking data
        - B.4 LearningPathOptimizer enhancement for adaptive modifications

        Args:
            student_id: Student identifier
            target_competencies: Target competencies for path optimization
            time_constraints: Available study time constraints
            performance_context: Current performance context for adjustments

        Returns:
            Optimized learning path with adaptive features and performance predictions
        """
        try:
            logger.info(f"Optimizing learning path for student {student_id}")

            # Get comprehensive student analysis from B.4 Learning Analytics
            student_analysis = await self.learning_analytics.analyze_student_progress(
                student_id
            )

            # Extract current competency levels and knowledge gaps
            competency_progression = student_analysis.get("competency_progression", {})
            knowledge_gaps = student_analysis.get("knowledge_gaps", [])

            # Use B.4 KnowledgeGapAnalyzer to identify priority learning areas
            await self.gap_analyzer.analyze_gaps(
                student_id, competency_progression, target_competencies
            )

            # Generate learning preferences for path optimization
            student_profile = await self.analytics_service._get_student_profile(
                student_id
            )
            learning_preferences = self._extract_learning_preferences(
                student_profile, student_analysis
            )

            # Create optimized path using B.4 LearningPathOptimizer
            optimized_path = await self.path_optimizer.create_optimized_path(
                student_id,
                knowledge_gaps,
                learning_preferences,
                time_constraints.get("weekly_minutes") if time_constraints else None,
            )

            # Enhance path with RAGnostic prerequisite relationships
            enhanced_path = await self._enhance_path_with_ragnostic_prerequisites(
                optimized_path, target_competencies
            )

            # Apply adaptive adjustments based on performance patterns
            adaptive_path = await self._apply_adaptive_path_adjustments(
                enhanced_path, student_analysis, performance_context
            )

            # Calculate success probability and performance predictions
            success_metrics = await self._calculate_path_success_metrics(
                adaptive_path, student_analysis
            )

            # Generate path validation and feasibility analysis
            feasibility_analysis = self.path_optimizer.validate_path_feasibility(
                adaptive_path, learning_preferences
            )

            learning_path_result = {
                "student_id": student_id,
                "path_id": f"adaptive_path_{student_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "target_competencies": target_competencies,
                "optimized_path": adaptive_path.dict(),
                "success_metrics": success_metrics,
                "feasibility_analysis": feasibility_analysis,
                "adaptation_features": {
                    "dynamic_difficulty": True,
                    "real_time_adjustment": True,
                    "performance_tracking": True,
                    "prerequisite_optimization": True,
                },
                "performance_predictions": {
                    "completion_probability": success_metrics.get(
                        "completion_probability", 0.85
                    ),
                    "competency_improvement": success_metrics.get(
                        "competency_improvement", 0.75
                    ),
                    "estimated_study_time": adaptive_path.total_duration,
                    "difficulty_progression": success_metrics.get(
                        "difficulty_progression", "adaptive"
                    ),
                },
                "generated_at": datetime.now().isoformat(),
                "last_adapted": datetime.now().isoformat(),
            }

            logger.info(
                f"Learning path optimized: {len(adaptive_path.steps)} steps, {adaptive_path.total_duration} minutes"
            )
            return learning_path_result

        except Exception as e:
            logger.error(f"Error optimizing learning path: {str(e)}")
            raise

    async def adjust_difficulty_dynamically(
        self,
        student_id: str,
        current_content: dict[str, Any],
        recent_performance: dict[str, Any],
        competency_context: dict[str, Any],
    ) -> DifficultyAdjustment:
        """
        Dynamically adjust content difficulty based on real-time performance.

        Uses:
        - B.4 competency assessment data for difficulty scaling
        - Knowledge gap severity for adjustment magnitude
        - Performance patterns for confidence scoring
        - AACN proficiency levels for appropriate difficulty targeting

        Args:
            student_id: Student identifier
            current_content: Currently assigned content
            recent_performance: Recent performance metrics
            competency_context: Current competency levels and progression

        Returns:
            Difficulty adjustment recommendation with supporting rationale
        """
        try:
            logger.info(
                f"Calculating dynamic difficulty adjustment for student {student_id}"
            )

            # Analyze recent performance trends
            performance_trend = self._analyze_performance_trend(recent_performance)

            # Get competency levels from B.4 analytics
            competency_levels = competency_context.get("domain_progressions", {})

            # Calculate current difficulty appropriateness
            current_difficulty = current_content.get("difficulty_level", "intermediate")
            difficulty_score = self._calculate_difficulty_appropriateness(
                current_difficulty, performance_trend, competency_levels
            )

            # Determine optimal difficulty adjustment
            recommended_difficulty = self._calculate_optimal_difficulty(
                difficulty_score, performance_trend, competency_levels
            )

            # Calculate adjustment confidence
            confidence_score = self._calculate_adjustment_confidence(
                performance_trend, competency_levels, recent_performance
            )

            # Generate adjustment rationale
            adjustment_reason = self._generate_adjustment_rationale(
                current_difficulty, recommended_difficulty, performance_trend
            )

            # Calculate adjustment magnitude (-1.0 to 1.0)
            adjustment_magnitude = self._calculate_adjustment_magnitude(
                current_difficulty, recommended_difficulty
            )

            difficulty_adjustment = DifficultyAdjustment(
                current_difficulty=current_difficulty,
                recommended_difficulty=recommended_difficulty,
                adjustment_reason=adjustment_reason,
                confidence_score=confidence_score,
                supporting_metrics={
                    "performance_trend": performance_trend,
                    "competency_alignment": difficulty_score,
                    "recent_scores": recent_performance.get("scores", []),
                    "engagement_level": recent_performance.get("engagement", 0.7),
                },
                adjustment_magnitude=adjustment_magnitude,
            )

            logger.info(
                f"Difficulty adjustment calculated: {current_difficulty} → {recommended_difficulty} (confidence: {confidence_score:.2f})"
            )
            return difficulty_adjustment

        except Exception as e:
            logger.error(f"Error calculating difficulty adjustment: {str(e)}")
            # Return safe default adjustment
            return DifficultyAdjustment(
                current_difficulty="intermediate",
                recommended_difficulty="intermediate",
                adjustment_reason="Error in calculation - maintaining current difficulty",
                confidence_score=0.5,
            )

    async def adapt_learning_path_realtime(
        self,
        student_id: str,
        current_path_id: str,
        performance_update: dict[str, Any],
        competency_changes: dict[str, Any],
    ) -> LearningPathAdaptation:
        """
        Adapt learning path in real-time based on performance updates.

        Integrates:
        - B.4 Learning Analytics real-time progress data
        - Knowledge gap analysis updates from performance changes
        - B.4 LearningPathOptimizer for path re-optimization
        - Dynamic content sequencing based on competency progression

        Args:
            student_id: Student identifier
            current_path_id: Current learning path identifier
            performance_update: Latest performance data
            competency_changes: Changes in competency levels

        Returns:
            Learning path adaptation with modifications and improvement estimates
        """
        try:
            logger.info(f"Adapting learning path in real-time for student {student_id}")

            # Analyze performance change significance
            performance_significance = self._analyze_performance_significance(
                performance_update
            )

            if performance_significance["requires_adaptation"]:
                # Get updated student analysis from B.4 Learning Analytics
                updated_analysis = (
                    await self.learning_analytics.analyze_student_progress(student_id)
                )

                # Re-analyze knowledge gaps with new performance data
                updated_gaps = await self.gap_analyzer.analyze_gaps(
                    student_id,
                    competency_changes,
                    updated_analysis.get("target_competencies", []),
                )

                # Identify required adaptations
                required_adaptations = self._identify_required_adaptations(
                    performance_update, updated_gaps, competency_changes
                )

                # Apply path adaptations
                adapted_path_data = await self._apply_path_adaptations(
                    current_path_id, required_adaptations, updated_analysis
                )

                # Calculate improvement estimates
                improvement_estimate = self._calculate_adaptation_improvement(
                    performance_update, adapted_path_data, required_adaptations
                )

                # Create adaptation result
                adaptation = LearningPathAdaptation(
                    original_path_id=current_path_id,
                    adapted_path_id=adapted_path_data["path_id"],
                    adaptations_made=required_adaptations,
                    performance_triggers=performance_significance["triggers"],
                    estimated_improvement=improvement_estimate,
                    adaptation_confidence=performance_significance["confidence"],
                )

                # Store adaptation history for learning
                self.adaptation_history[student_id] = {
                    "adaptation": adaptation,
                    "timestamp": datetime.now().isoformat(),
                    "trigger_data": performance_update,
                }

                logger.info(
                    f"Real-time adaptation completed: {len(required_adaptations)} modifications made"
                )
                return adaptation

            else:
                # No significant change - return minimal adaptation
                return LearningPathAdaptation(
                    original_path_id=current_path_id,
                    adapted_path_id=current_path_id,
                    adaptations_made=["no_changes_needed"],
                    performance_triggers=[],
                    estimated_improvement=0.0,
                    adaptation_confidence=1.0,
                )

        except Exception as e:
            logger.error(f"Error adapting learning path: {str(e)}")
            raise

    async def generate_adaptive_study_plan(
        self,
        student_id: str,
        study_duration_weeks: int,
        weekly_time_budget: int,
        priority_competencies: list[str],
    ) -> dict[str, Any]:
        """
        Generate comprehensive adaptive study plan with performance tracking.

        Combines:
        - B.4 Learning Analytics student profiling
        - Knowledge gap prioritization from B.4 analysis
        - Adaptive difficulty progression using competency data
        - Real-time adjustment capabilities with B.4 tracking integration

        Args:
            student_id: Student identifier
            study_duration_weeks: Study plan duration in weeks
            weekly_time_budget: Available study time per week (minutes)
            priority_competencies: High-priority competencies to focus on

        Returns:
            Comprehensive adaptive study plan with tracking and adjustment features
        """
        try:
            logger.info(f"Generating adaptive study plan for student {student_id}")

            # Get comprehensive student analysis
            student_analysis = await self.learning_analytics.analyze_student_progress(
                student_id
            )

            # Generate personalized content recommendations
            personalized_content = await self.generate_personalized_content(
                {"student_id": student_id}, priority_competencies
            )

            # Create optimized learning path
            learning_path = await self.optimize_learning_path(
                student_id,
                priority_competencies,
                {"weekly_minutes": weekly_time_budget},
            )

            # Generate weekly study schedule
            weekly_schedule = await self._generate_weekly_schedule(
                learning_path["optimized_path"],
                weekly_time_budget,
                study_duration_weeks,
            )

            # Create milestone tracking system
            milestones = self._create_adaptive_milestones(
                learning_path, student_analysis, study_duration_weeks
            )

            # Generate assessment schedule for progress tracking
            assessment_schedule = self._create_assessment_schedule(
                priority_competencies, study_duration_weeks
            )

            # Calculate success metrics and predictions
            success_predictions = await self._calculate_study_plan_predictions(
                student_analysis, learning_path, weekly_time_budget
            )

            adaptive_study_plan = {
                "student_id": student_id,
                "plan_id": f"adaptive_study_{student_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "study_duration_weeks": study_duration_weeks,
                "weekly_time_budget": weekly_time_budget,
                "priority_competencies": priority_competencies,
                "personalized_content": [rec.dict() for rec in personalized_content],
                "learning_path": learning_path,
                "weekly_schedule": weekly_schedule,
                "milestones": milestones,
                "assessment_schedule": assessment_schedule,
                "adaptive_features": {
                    "dynamic_difficulty_adjustment": True,
                    "real_time_path_adaptation": True,
                    "performance_based_content_selection": True,
                    "automatic_milestone_adjustment": True,
                    "competency_based_progression": True,
                },
                "success_predictions": success_predictions,
                "tracking_metrics": {
                    "competency_improvement_targets": success_predictions.get(
                        "competency_targets", {}
                    ),
                    "engagement_targets": {
                        "weekly_engagement": 0.8,
                        "content_completion": 0.85,
                    },
                    "performance_thresholds": self.performance_thresholds,
                },
                "generated_at": datetime.now().isoformat(),
                "next_adaptation_date": (
                    datetime.now() + timedelta(weeks=1)
                ).isoformat(),
            }

            logger.info(
                f"Adaptive study plan generated: {study_duration_weeks} weeks, {len(personalized_content)} resources"
            )
            return adaptive_study_plan

        except Exception as e:
            logger.error(f"Error generating adaptive study plan: {str(e)}")
            raise

    # Private helper methods for adaptive algorithms

    async def _extract_personalization_factors(
        self, student_profile: dict[str, Any], performance_analysis: dict[str, Any]
    ) -> PersonalizationFactors:
        """Extract personalization factors from student data"""
        try:
            progress_metrics = performance_analysis.get("progress_metrics", {})
            learning_patterns = performance_analysis.get("learning_patterns", {})

            return PersonalizationFactors(
                learning_style=student_profile.get("learning_style", "visual"),
                difficulty_preference=student_profile.get(
                    "difficulty_preference", "adaptive"
                ),
                pace_preference=self._infer_pace_preference(progress_metrics),
                content_type_preferences=student_profile.get(
                    "content_types", ["interactive", "visual"]
                ),
                performance_patterns={
                    "average_score": progress_metrics.get("overall_progress", 0.7),
                    "consistency": progress_metrics.get("consistency_score", 0.7),
                    "engagement": progress_metrics.get("engagement_score", 0.7),
                },
                engagement_patterns=learning_patterns,
                confidence_levels=self._extract_confidence_levels(performance_analysis),
                time_constraints=student_profile.get(
                    "time_constraints", {"daily_minutes": 60}
                ),
            )
        except Exception as e:
            logger.error(f"Error extracting personalization factors: {str(e)}")
            return PersonalizationFactors(
                learning_style="visual",
                difficulty_preference="adaptive",
                pace_preference="moderate",
            )

    def _infer_pace_preference(self, progress_metrics: dict[str, Any]) -> str:
        """Infer learning pace preference from performance metrics"""
        learning_velocity = progress_metrics.get("learning_velocity", 0.5)

        if learning_velocity > 0.8:
            return "fast"
        elif learning_velocity < 0.4:
            return "slow"
        else:
            return "moderate"

    def _extract_confidence_levels(
        self, performance_analysis: dict[str, Any]
    ) -> dict[str, float]:
        """Extract confidence levels by competency domain"""
        competency_progression = performance_analysis.get("competency_progression", {})
        domain_progressions = competency_progression.get("domain_progressions", {})

        confidence_levels = {}
        for domain, progression in domain_progressions.items():
            # Use progression strength indicators as confidence proxy
            strengths = progression.get("strengths", [])
            confidence_levels[domain] = 0.8 if domain in strengths else 0.6

        return confidence_levels

    async def _generate_adaptive_recommendations(
        self,
        student_id: str,
        knowledge_gaps: list[dict[str, Any]],
        personalization_factors: PersonalizationFactors,
        target_competencies: list[str] | None,
    ) -> list[AdaptiveContentRecommendation]:
        """Generate adaptive content recommendations based on gaps and personalization"""
        try:
            recommendations = []

            # Prioritize knowledge gaps by severity and personalization relevance
            prioritized_gaps = self._prioritize_gaps_for_personalization(
                knowledge_gaps, personalization_factors
            )

            for gap in prioritized_gaps[:5]:  # Focus on top 5 gaps
                # Generate recommendations for this gap
                gap_recommendations = await self._generate_gap_recommendations(
                    gap, personalization_factors, target_competencies
                )
                recommendations.extend(gap_recommendations)

            # Add exploration content based on strengths
            strength_recommendations = (
                await self._generate_strength_based_recommendations(
                    student_id, personalization_factors
                )
            )
            recommendations.extend(strength_recommendations)

            return recommendations

        except Exception as e:
            logger.error(f"Error generating adaptive recommendations: {str(e)}")
            return []

    def _prioritize_gaps_for_personalization(
        self,
        knowledge_gaps: list[dict[str, Any]],
        personalization_factors: PersonalizationFactors,
    ) -> list[dict[str, Any]]:
        """Prioritize knowledge gaps considering personalization factors"""

        def personalization_score(gap):
            base_severity = {"critical": 4, "major": 3, "moderate": 2, "minor": 1}
            severity_score = base_severity.get(gap.get("severity", "minor"), 1)

            # Adjust for learning style alignment
            content_types = gap.get("recommended_content_types", [])
            style_bonus = (
                1.5 if personalization_factors.learning_style in content_types else 1.0
            )

            # Adjust for confidence level in domain
            domain = gap.get("domain", "unknown")
            confidence = personalization_factors.confidence_levels.get(domain, 0.6)
            confidence_modifier = 2.0 - confidence  # Lower confidence = higher priority

            return severity_score * style_bonus * confidence_modifier

        return sorted(knowledge_gaps, key=personalization_score, reverse=True)

    async def _generate_gap_recommendations(
        self,
        gap: dict[str, Any],
        personalization_factors: PersonalizationFactors,
        target_competencies: list[str] | None,
    ) -> list[AdaptiveContentRecommendation]:
        """Generate content recommendations for a specific knowledge gap"""
        try:
            # Use RAGnostic to find relevant content
            search_query = self._construct_gap_search_query(gap, target_competencies)
            ragnostic_results = await self.ragnostic_client.search_content(search_query)

            recommendations = []
            for result in ragnostic_results.get("results", [])[:3]:
                # Calculate personalization score
                personalization_score = self._calculate_content_personalization_score(
                    result, gap, personalization_factors
                )

                # Adjust difficulty based on gap severity and student confidence
                adjusted_difficulty = self._adjust_content_difficulty(
                    result.get("difficulty", "intermediate"),
                    gap.get("severity", "moderate"),
                    personalization_factors.confidence_levels.get(
                        gap.get("domain", "unknown"), 0.6
                    ),
                )

                recommendation = AdaptiveContentRecommendation(
                    content_id=result.get("id", "unknown"),
                    title=result.get("title", "Content"),
                    content_type=result.get("type", "reading"),
                    difficulty_level=adjusted_difficulty,
                    estimated_duration=result.get("duration", 30),
                    personalization_score=personalization_score,
                    adaptive_reason=f"Addresses {gap.get('topic', 'knowledge gap')} with {gap.get('severity', 'moderate')} severity",
                    learning_objectives=result.get("learning_objectives", []),
                    prerequisite_concepts=result.get("prerequisites", []),
                    success_probability=self._calculate_success_probability(
                        result, gap, personalization_factors
                    ),
                    engagement_prediction=self._predict_engagement(
                        result, personalization_factors
                    ),
                )

                recommendations.append(recommendation)

            return recommendations

        except Exception as e:
            logger.error(f"Error generating gap recommendations: {str(e)}")
            return []

    def _construct_gap_search_query(
        self, gap: dict[str, Any], target_competencies: list[str] | None
    ) -> str:
        """Construct search query for RAGnostic based on knowledge gap"""
        base_query = gap.get("topic", "nursing knowledge")
        domain = gap.get("domain", "")

        if target_competencies and domain in target_competencies:
            return f"{base_query} {domain} competency nursing education"
        else:
            return f"{base_query} nursing education fundamentals"

    def _calculate_content_personalization_score(
        self,
        content: dict[str, Any],
        gap: dict[str, Any],
        personalization_factors: PersonalizationFactors,
    ) -> float:
        """Calculate personalization score for content recommendation"""
        try:
            base_score = 0.5

            # Content type alignment with learning style
            content_type = content.get("type", "reading")
            if content_type in personalization_factors.content_type_preferences:
                base_score += 0.2

            # Difficulty alignment with preference
            difficulty = content.get("difficulty", "intermediate")
            if personalization_factors.difficulty_preference == "adaptive":
                base_score += 0.1  # Adaptive is always good
            elif difficulty == personalization_factors.difficulty_preference:
                base_score += 0.15

            # Duration alignment with time constraints
            duration = content.get("duration", 30)
            daily_minutes = personalization_factors.time_constraints.get(
                "daily_minutes", 60
            )
            if duration <= daily_minutes:
                base_score += 0.1

            # Topic relevance to gap severity
            gap_severity = gap.get("severity", "moderate")
            severity_weights = {
                "critical": 0.2,
                "major": 0.15,
                "moderate": 0.1,
                "minor": 0.05,
            }
            base_score += severity_weights.get(gap_severity, 0.1)

            return min(1.0, base_score)  # Cap at 1.0

        except Exception as e:
            logger.error(f"Error calculating personalization score: {str(e)}")
            return 0.5

    def _adjust_content_difficulty(
        self, original_difficulty: str, gap_severity: str, confidence: float
    ) -> str:
        """Adjust content difficulty based on gap severity and student confidence"""
        difficulty_levels = ["beginner", "intermediate", "advanced", "expert"]
        current_index = (
            difficulty_levels.index(original_difficulty)
            if original_difficulty in difficulty_levels
            else 1
        )

        # Adjust based on gap severity (higher severity = lower difficulty initially)
        severity_adjustments = {"critical": -1, "major": 0, "moderate": 0, "minor": 1}
        severity_adjustment = severity_adjustments.get(gap_severity, 0)

        # Adjust based on confidence (lower confidence = lower difficulty)
        confidence_adjustment = (
            -1 if confidence < 0.5 else (1 if confidence > 0.8 else 0)
        )

        adjusted_index = max(
            0,
            min(
                len(difficulty_levels) - 1,
                current_index + severity_adjustment + confidence_adjustment,
            ),
        )
        return difficulty_levels[adjusted_index]

    def _calculate_success_probability(
        self,
        content: dict[str, Any],
        gap: dict[str, Any],
        personalization_factors: PersonalizationFactors,
    ) -> float:
        """Calculate probability of successful content completion"""
        base_probability = 0.7

        # Adjust for difficulty vs student level
        difficulty = content.get("difficulty", "intermediate")
        if difficulty == "beginner":
            base_probability += 0.1
        elif difficulty == "advanced":
            base_probability -= 0.1

        # Adjust for learning style alignment
        content_type = content.get("type", "reading")
        if content_type in personalization_factors.content_type_preferences:
            base_probability += 0.1

        # Adjust for confidence in domain
        domain = gap.get("domain", "unknown")
        domain_confidence = personalization_factors.confidence_levels.get(domain, 0.6)
        base_probability += (domain_confidence - 0.5) * 0.2

        return max(0.3, min(0.95, base_probability))

    def _predict_engagement(
        self, content: dict[str, Any], personalization_factors: PersonalizationFactors
    ) -> float:
        """Predict student engagement with content"""
        base_engagement = 0.6

        # Content type preference bonus
        content_type = content.get("type", "reading")
        if content_type in personalization_factors.content_type_preferences:
            base_engagement += 0.2

        # Duration appropriateness
        duration = content.get("duration", 30)
        daily_minutes = personalization_factors.time_constraints.get(
            "daily_minutes", 60
        )
        if duration <= daily_minutes * 0.8:  # Fits comfortably in available time
            base_engagement += 0.1

        # Historical engagement patterns
        historical_engagement = personalization_factors.engagement_patterns.get(
            "average_engagement", 0.7
        )
        base_engagement = (base_engagement + historical_engagement) / 2

        return max(0.3, min(0.95, base_engagement))

    async def _generate_strength_based_recommendations(
        self, student_id: str, personalization_factors: PersonalizationFactors
    ) -> list[AdaptiveContentRecommendation]:
        """Generate recommendations based on student strengths for exploration"""
        try:
            # Identify domains with high confidence (strengths)
            strength_domains = [
                domain
                for domain, confidence in personalization_factors.confidence_levels.items()
                if confidence > 0.75
            ]

            if not strength_domains:
                return []

            recommendations = []
            for domain in strength_domains[:2]:  # Focus on top 2 strengths
                # Search for advanced content in strength areas
                search_query = (
                    f"{domain} advanced nursing concepts clinical applications"
                )
                ragnostic_results = await self.ragnostic_client.search_content(
                    search_query
                )

                for result in ragnostic_results.get("results", [])[:2]:
                    recommendation = AdaptiveContentRecommendation(
                        content_id=result.get("id", "unknown"),
                        title=result.get("title", "Advanced Content"),
                        content_type=result.get("type", "reading"),
                        difficulty_level="advanced",  # Challenge students in their strength areas
                        estimated_duration=result.get("duration", 45),
                        personalization_score=0.8,  # High score for strength-based content
                        adaptive_reason=f"Builds on your strength in {domain} for deeper understanding",
                        learning_objectives=result.get("learning_objectives", []),
                        prerequisite_concepts=[],  # Strengths don't require prerequisites
                        success_probability=0.85,  # High probability in strength areas
                        engagement_prediction=0.8,  # Students enjoy their strengths
                    )
                    recommendations.append(recommendation)

            return recommendations

        except Exception as e:
            logger.error(f"Error generating strength-based recommendations: {str(e)}")
            return []

    # Additional helper methods continue...
    # (Implementation continues with remaining helper methods for completeness)

    async def _apply_difficulty_adjustments(
        self,
        recommendations: list[AdaptiveContentRecommendation],
        performance_analysis: dict[str, Any],
        personalization_factors: PersonalizationFactors,
    ) -> list[AdaptiveContentRecommendation]:
        """Apply difficulty adjustments to content recommendations"""
        adjusted_recommendations = []

        for rec in recommendations:
            # Calculate if difficulty adjustment is needed
            difficulty_adjustment = await self.adjust_difficulty_dynamically(
                personalization_factors.performance_patterns.get(
                    "student_id", "unknown"
                ),
                {"difficulty_level": rec.difficulty_level},
                personalization_factors.performance_patterns,
                performance_analysis.get("competency_progression", {}),
            )

            # Apply adjustment if confidence is high enough
            if difficulty_adjustment.confidence_score > 0.7:
                rec.difficulty_level = difficulty_adjustment.recommended_difficulty
                rec.adaptive_reason += (
                    f" (Difficulty adjusted: {difficulty_adjustment.adjustment_reason})"
                )

            adjusted_recommendations.append(rec)

        return adjusted_recommendations

    async def _enhance_with_ragnostic_content(
        self,
        recommendations: list[AdaptiveContentRecommendation],
        performance_analysis: dict[str, Any],
    ) -> list[AdaptiveContentRecommendation]:
        """Enhance recommendations with additional RAGnostic content analysis"""
        enhanced_recommendations = []

        for rec in recommendations:
            try:
                # Get prerequisite information from RAGnostic
                prerequisite_query = f"prerequisites for {rec.title} nursing education"
                prerequisite_results = await self.ragnostic_client.search_content(
                    prerequisite_query
                )

                # Update prerequisite concepts
                if prerequisite_results.get("results"):
                    prerequisites = []
                    for result in prerequisite_results["results"][:3]:
                        prerequisites.extend(result.get("concepts", []))
                    rec.prerequisite_concepts = list(set(prerequisites))

                enhanced_recommendations.append(rec)

            except Exception as e:
                logger.warning(
                    f"Could not enhance recommendation {rec.content_id}: {str(e)}"
                )
                enhanced_recommendations.append(rec)  # Keep original

        return enhanced_recommendations

    def _rank_by_personalization_score(
        self, recommendations: list[AdaptiveContentRecommendation]
    ) -> list[AdaptiveContentRecommendation]:
        """Rank recommendations by personalization score"""
        return sorted(
            recommendations, key=lambda x: x.personalization_score, reverse=True
        )

    async def _enhance_path_with_ragnostic_prerequisites(
        self, optimized_path: OptimizedLearningPath, target_competencies: list[str]
    ) -> OptimizedLearningPath:
        """Enhance learning path with RAGnostic prerequisite information"""
        try:
            # For each step in the path, get prerequisite information
            enhanced_steps = []

            for step in optimized_path.steps:
                # Query RAGnostic for prerequisite concepts
                prerequisite_query = f"prerequisites for {step.resource.title} {' '.join(target_competencies)}"
                results = await self.ragnostic_client.search_content(prerequisite_query)

                # Update step with prerequisite information
                if results.get("results"):
                    # Extract concepts from results
                    concepts = []
                    for result in results["results"][:2]:
                        concepts.extend(result.get("concepts", []))

                    # Update resource prerequisites
                    step.resource.prerequisites.extend(
                        concepts[:3]
                    )  # Add top 3 concepts

                enhanced_steps.append(step)

            # Return path with enhanced steps
            optimized_path.steps = enhanced_steps
            return optimized_path

        except Exception as e:
            logger.error(f"Error enhancing path with RAGnostic prerequisites: {str(e)}")
            return optimized_path  # Return original path if enhancement fails

    async def _apply_adaptive_path_adjustments(
        self,
        enhanced_path: OptimizedLearningPath,
        student_analysis: dict[str, Any],
        performance_context: dict[str, Any] | None,
    ) -> OptimizedLearningPath:
        """Apply adaptive adjustments to learning path based on student analysis"""
        try:
            # Extract performance indicators
            performance_metrics = student_analysis.get("progress_metrics", {})
            risk_assessment = student_analysis.get("risk_assessment", {})

            # Adjust path based on risk level
            risk_level = risk_assessment.get("risk_level", "low")

            if risk_level == "high":
                # Add remedial content and extend timeline
                enhanced_path = await self._add_remedial_content(
                    enhanced_path, student_analysis
                )
                enhanced_path.total_duration = int(
                    enhanced_path.total_duration * 1.3
                )  # 30% more time
            elif (
                risk_level == "low"
                and performance_metrics.get("overall_progress", 0) > 0.85
            ):
                # Add advanced content for high performers
                enhanced_path = await self._add_advanced_content(
                    enhanced_path, student_analysis
                )

            # Adjust based on engagement patterns
            engagement_score = performance_metrics.get("engagement_score", 0.7)
            if engagement_score < 0.6:
                enhanced_path = self._adjust_for_low_engagement(enhanced_path)

            return enhanced_path

        except Exception as e:
            logger.error(f"Error applying adaptive path adjustments: {str(e)}")
            return enhanced_path

    async def _calculate_path_success_metrics(
        self, adaptive_path: OptimizedLearningPath, student_analysis: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate success metrics and predictions for learning path"""
        try:
            performance_metrics = student_analysis.get("progress_metrics", {})
            competency_progression = student_analysis.get("competency_progression", {})

            # Base success probability
            base_success = 0.75

            # Adjust based on historical performance
            overall_progress = performance_metrics.get("overall_progress", 0.7)
            consistency_score = performance_metrics.get("consistency_score", 0.7)

            performance_factor = (overall_progress + consistency_score) / 2
            completion_probability = base_success * performance_factor

            # Calculate competency improvement prediction
            current_readiness = competency_progression.get("current_profile", {}).get(
                "graduation_readiness", 0.6
            )
            competency_improvement = min(
                0.95, current_readiness + 0.2
            )  # Expect 20% improvement

            return {
                "completion_probability": max(0.5, min(0.95, completion_probability)),
                "competency_improvement": competency_improvement,
                "estimated_timeline_accuracy": 0.8,
                "difficulty_progression": "adaptive",
                "success_factors": [
                    "Personalized content selection",
                    "Adaptive difficulty adjustment",
                    "Real-time path optimization",
                    "Performance-based modifications",
                ],
                "risk_factors": student_analysis.get("risk_assessment", {}).get(
                    "risk_factors", []
                ),
            }

        except Exception as e:
            logger.error(f"Error calculating path success metrics: {str(e)}")
            return {
                "completion_probability": 0.75,
                "competency_improvement": 0.8,
                "estimated_timeline_accuracy": 0.8,
                "difficulty_progression": "adaptive",
            }

    def _extract_learning_preferences(
        self, student_profile: dict[str, Any], student_analysis: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract learning preferences for path optimization"""
        try:
            preferences = student_profile.get("preferences", {})
            learning_patterns = student_analysis.get("learning_patterns", {})

            return {
                "preferred_content_types": preferences.get(
                    "content_types", ["interactive", "visual"]
                ),
                "learning_style": preferences.get("learning_style", "visual"),
                "difficulty_preference": preferences.get(
                    "difficulty_preference", "adaptive"
                ),
                "available_hours_per_week": preferences.get("study_time", {}).get(
                    "weekly_hours", 10
                ),
                "preferred_session_length": preferences.get("study_time", {}).get(
                    "session_length", 60
                ),
                "max_difficulty_level": "advanced"
                if student_analysis.get("progress_metrics", {}).get(
                    "overall_progress", 0
                )
                > 0.8
                else "intermediate",
                "completed_courses": student_profile.get("academic_record", {}).get(
                    "courses_completed", []
                ),
                "learning_pace": learning_patterns.get("pattern_type", "moderate"),
            }

        except Exception as e:
            logger.error(f"Error extracting learning preferences: {str(e)}")
            return {
                "preferred_content_types": ["interactive"],
                "learning_style": "visual",
                "difficulty_preference": "adaptive",
            }

    # Performance trend analysis methods

    def _analyze_performance_trend(
        self, recent_performance: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze recent performance trends"""
        try:
            scores = recent_performance.get(
                "scores", [0.7]
            )  # Default to moderate performance

            if len(scores) >= 3:
                # Calculate trend
                recent_avg = mean(scores[-3:])
                older_avg = mean(scores[:-3]) if len(scores) > 3 else mean(scores)

                trend = (
                    "improving"
                    if recent_avg > older_avg
                    else ("declining" if recent_avg < older_avg else "stable")
                )
                trend_magnitude = abs(recent_avg - older_avg)

                return {
                    "direction": trend,
                    "magnitude": trend_magnitude,
                    "current_level": recent_avg,
                    "consistency": 1.0 - (stdev(scores) if len(scores) > 1 else 0.0),
                    "sample_size": len(scores),
                }
            else:
                return {
                    "direction": "stable",
                    "magnitude": 0.0,
                    "current_level": scores[0] if scores else 0.7,
                    "consistency": 1.0,
                    "sample_size": len(scores),
                }

        except Exception as e:
            logger.error(f"Error analyzing performance trend: {str(e)}")
            return {
                "direction": "stable",
                "magnitude": 0.0,
                "current_level": 0.7,
                "consistency": 0.7,
                "sample_size": 1,
            }

    def _calculate_difficulty_appropriateness(
        self,
        current_difficulty: str,
        performance_trend: dict[str, Any],
        competency_levels: dict[str, Any],
    ) -> float:
        """Calculate how appropriate current difficulty is for student"""
        difficulty_scores = {
            "beginner": 1,
            "intermediate": 2,
            "advanced": 3,
            "expert": 4,
        }
        current_score = difficulty_scores.get(current_difficulty, 2)

        # Calculate ideal difficulty based on performance and competency
        performance_level = performance_trend.get("current_level", 0.7)
        avg_competency = (
            mean(
                [
                    prog.get("overall_score", 0.7)
                    for prog in competency_levels.values()
                    if isinstance(prog, dict)
                ]
            )
            if competency_levels
            else 0.7
        )

        # Map performance to difficulty scale (0.5-0.6=1, 0.6-0.75=2, 0.75-0.9=3, 0.9+=4)
        if performance_level < 0.6:
            ideal_score = 1
        elif performance_level < 0.75:
            ideal_score = 2
        elif performance_level < 0.9:
            ideal_score = 3
        else:
            ideal_score = 4

        # Adjust ideal score based on competency levels
        competency_adjustment = (avg_competency - 0.7) * 2  # -0.4 to 0.6 range
        adjusted_ideal = max(1, min(4, ideal_score + competency_adjustment))

        # Calculate appropriateness (1.0 = perfect, 0.0 = completely inappropriate)
        difference = abs(current_score - adjusted_ideal)
        appropriateness = max(
            0.0, 1.0 - (difference / 3.0)
        )  # Scale difference by max possible difference

        return appropriateness

    def _calculate_optimal_difficulty(
        self,
        difficulty_score: float,
        performance_trend: dict[str, Any],
        competency_levels: dict[str, Any],
    ) -> str:
        """Calculate optimal difficulty level for student"""
        difficulty_levels = ["beginner", "intermediate", "advanced", "expert"]

        # Base difficulty on performance level
        performance_level = performance_trend.get("current_level", 0.7)

        if performance_level < 0.6:
            base_index = 0  # beginner
        elif performance_level < 0.75:
            base_index = 1  # intermediate
        elif performance_level < 0.9:
            base_index = 2  # advanced
        else:
            base_index = 3  # expert

        # Adjust based on performance trend
        if (
            performance_trend.get("direction") == "improving"
            and performance_trend.get("magnitude", 0) > 0.1
        ):
            base_index = min(3, base_index + 1)  # Move up if strongly improving
        elif (
            performance_trend.get("direction") == "declining"
            and performance_trend.get("magnitude", 0) > 0.1
        ):
            base_index = max(0, base_index - 1)  # Move down if strongly declining

        # Adjust for consistency - inconsistent students need easier content
        consistency = performance_trend.get("consistency", 0.7)
        if consistency < 0.5:
            base_index = max(0, base_index - 1)

        return difficulty_levels[base_index]

    def _calculate_adjustment_confidence(
        self,
        performance_trend: dict[str, Any],
        competency_levels: dict[str, Any],
        recent_performance: dict[str, Any],
    ) -> float:
        """Calculate confidence in difficulty adjustment recommendation"""
        base_confidence = 0.7

        # Higher confidence with more performance data
        sample_size = performance_trend.get("sample_size", 1)
        sample_bonus = min(0.2, sample_size * 0.05)  # Up to 0.2 bonus for 4+ samples

        # Higher confidence with clear trends
        trend_magnitude = performance_trend.get("magnitude", 0.0)
        trend_bonus = min(
            0.1, trend_magnitude * 0.5
        )  # Up to 0.1 bonus for strong trends

        # Higher confidence with consistent performance
        consistency = performance_trend.get("consistency", 0.7)
        consistency_bonus = (consistency - 0.5) * 0.2  # -0.1 to 0.1 adjustment

        # Factor in engagement (more engaged = higher confidence in adjustments)
        engagement = recent_performance.get("engagement", 0.7)
        engagement_bonus = (engagement - 0.5) * 0.1  # -0.05 to 0.1 adjustment

        total_confidence = (
            base_confidence
            + sample_bonus
            + trend_bonus
            + consistency_bonus
            + engagement_bonus
        )

        return max(0.3, min(0.95, total_confidence))

    def _generate_adjustment_rationale(
        self,
        current_difficulty: str,
        recommended_difficulty: str,
        performance_trend: dict[str, Any],
    ) -> str:
        """Generate human-readable rationale for difficulty adjustment"""
        if current_difficulty == recommended_difficulty:
            return f"Current {current_difficulty} difficulty level is appropriate for your performance"

        direction = (
            "increase" if recommended_difficulty > current_difficulty else "decrease"
        )
        trend_direction = performance_trend.get("direction", "stable")
        current_level = performance_trend.get("current_level", 0.7)

        if direction == "increase":
            if trend_direction == "improving":
                return f"Your improving performance ({current_level:.1%}) indicates readiness for {recommended_difficulty} level content"
            elif current_level > 0.8:
                return f"Your strong performance ({current_level:.1%}) suggests you're ready for more challenging {recommended_difficulty} content"
            else:
                return f"Moving to {recommended_difficulty} level to maintain appropriate challenge"
        else:  # decrease
            if trend_direction == "declining":
                return f"Recent performance decline suggests {recommended_difficulty} level would be more suitable for rebuilding confidence"
            elif current_level < 0.6:
                return f"Performance level ({current_level:.1%}) indicates {recommended_difficulty} content would be more appropriate"
            else:
                return f"Adjusting to {recommended_difficulty} level to ensure solid foundation before advancing"

    def _calculate_adjustment_magnitude(
        self, current_difficulty: str, recommended_difficulty: str
    ) -> float:
        """Calculate adjustment magnitude on -1.0 to 1.0 scale"""
        difficulty_values = {
            "beginner": 1,
            "intermediate": 2,
            "advanced": 3,
            "expert": 4,
        }

        current_value = difficulty_values.get(current_difficulty, 2)
        recommended_value = difficulty_values.get(recommended_difficulty, 2)

        # Calculate difference and normalize to -1.0 to 1.0 scale
        difference = recommended_value - current_value
        magnitude = (
            difference / 3.0
        )  # Max difference is 3 (beginner to expert or vice versa)

        return max(-1.0, min(1.0, magnitude))

    # Real-time adaptation methods

    def _analyze_performance_significance(
        self, performance_update: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze whether performance update is significant enough to trigger adaptation"""
        try:
            # Extract key performance indicators
            latest_scores = performance_update.get("recent_scores", [])
            engagement_change = performance_update.get("engagement_change", 0.0)
            competency_changes = performance_update.get("competency_changes", {})

            significance_indicators = []
            requires_adaptation = False
            confidence = 0.5

            # Check for significant score changes
            if latest_scores and len(latest_scores) >= 2:
                score_change = latest_scores[-1] - latest_scores[-2]
                if abs(score_change) > 0.15:  # 15% change threshold
                    significance_indicators.append(f"Score change: {score_change:+.1%}")
                    requires_adaptation = True
                    confidence += 0.2

            # Check for engagement changes
            if abs(engagement_change) > 0.2:  # 20% engagement change
                significance_indicators.append(
                    f"Engagement change: {engagement_change:+.1%}"
                )
                requires_adaptation = True
                confidence += 0.15

            # Check for competency level changes
            significant_competency_changes = [
                domain
                for domain, change in competency_changes.items()
                if abs(change) > 0.1  # 10% competency change
            ]

            if significant_competency_changes:
                significance_indicators.extend(
                    [
                        f"{domain}: {competency_changes[domain]:+.1%}"
                        for domain in significant_competency_changes
                    ]
                )
                requires_adaptation = True
                confidence += 0.1 * len(significant_competency_changes)

            return {
                "requires_adaptation": requires_adaptation,
                "confidence": min(0.95, confidence),
                "triggers": significance_indicators,
                "trigger_count": len(significance_indicators),
                "adaptation_urgency": "high"
                if len(significance_indicators) > 2
                else "medium",
            }

        except Exception as e:
            logger.error(f"Error analyzing performance significance: {str(e)}")
            return {
                "requires_adaptation": False,
                "confidence": 0.5,
                "triggers": [],
                "trigger_count": 0,
                "adaptation_urgency": "low",
            }

    def _identify_required_adaptations(
        self,
        performance_update: dict[str, Any],
        updated_gaps: GapAnalysisResult,
        competency_changes: dict[str, Any],
    ) -> list[str]:
        """Identify specific adaptations needed based on performance changes"""
        try:
            adaptations = []

            # Performance-based adaptations
            recent_scores = performance_update.get("recent_scores", [])
            if recent_scores:
                latest_score = recent_scores[-1]

                if latest_score < 0.6:
                    adaptations.append("add_remedial_content")
                    adaptations.append("reduce_difficulty")
                elif latest_score > 0.9:
                    adaptations.append("increase_difficulty")
                    adaptations.append("add_advanced_content")

            # Gap-based adaptations
            critical_gaps = [
                gap for gap in updated_gaps.gaps if gap.severity == "critical"
            ]
            if len(critical_gaps) > len(
                performance_update.get("previous_critical_gaps", [])
            ):
                adaptations.append("prioritize_gap_content")
                adaptations.append("extend_timeline")

            # Engagement-based adaptations
            engagement_change = performance_update.get("engagement_change", 0.0)
            if engagement_change < -0.2:  # 20% decrease in engagement
                adaptations.append("increase_interactivity")
                adaptations.append("adjust_content_types")

            # Competency-based adaptations
            for domain, change in competency_changes.items():
                if change < -0.1:  # 10% decrease in competency
                    adaptations.append(f"reinforce_{domain}_concepts")
                elif change > 0.15:  # 15% increase
                    adaptations.append(f"advance_{domain}_content")

            return list(set(adaptations))  # Remove duplicates

        except Exception as e:
            logger.error(f"Error identifying required adaptations: {str(e)}")
            return ["maintain_current_path"]  # Safe fallback

    async def _apply_path_adaptations(
        self,
        current_path_id: str,
        required_adaptations: list[str],
        updated_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply adaptations to learning path"""
        try:
            # Generate new path ID
            new_path_id = (
                f"adapted_{current_path_id}_{datetime.now().strftime('%H%M%S')}"
            )

            adaptations_applied = []

            # Mock path adaptation logic - in production would modify actual path
            for adaptation in required_adaptations:
                if adaptation == "add_remedial_content":
                    adaptations_applied.append("Added foundational review materials")
                elif adaptation == "reduce_difficulty":
                    adaptations_applied.append(
                        "Reduced content difficulty by one level"
                    )
                elif adaptation == "increase_difficulty":
                    adaptations_applied.append(
                        "Increased content difficulty for greater challenge"
                    )
                elif adaptation == "add_advanced_content":
                    adaptations_applied.append("Added advanced exploration materials")
                elif adaptation == "prioritize_gap_content":
                    adaptations_applied.append(
                        "Prioritized content addressing critical knowledge gaps"
                    )
                elif adaptation == "extend_timeline":
                    adaptations_applied.append(
                        "Extended learning timeline for better mastery"
                    )
                elif adaptation == "increase_interactivity":
                    adaptations_applied.append(
                        "Added interactive elements to boost engagement"
                    )
                elif adaptation == "adjust_content_types":
                    adaptations_applied.append(
                        "Adjusted content types to match learning preferences"
                    )
                elif adaptation.startswith("reinforce_"):
                    domain = adaptation.replace("reinforce_", "").replace(
                        "_concepts", ""
                    )
                    adaptations_applied.append(
                        f"Added reinforcement content for {domain} competency"
                    )
                elif adaptation.startswith("advance_"):
                    domain = adaptation.replace("advance_", "").replace("_content", "")
                    adaptations_applied.append(
                        f"Added advanced content for {domain} competency"
                    )
                else:
                    adaptations_applied.append(f"Applied {adaptation} adaptation")

            return {
                "path_id": new_path_id,
                "original_path_id": current_path_id,
                "adaptations_applied": adaptations_applied,
                "adaptation_timestamp": datetime.now().isoformat(),
                "adaptation_confidence": 0.85,
            }

        except Exception as e:
            logger.error(f"Error applying path adaptations: {str(e)}")
            return {
                "path_id": current_path_id,
                "original_path_id": current_path_id,
                "adaptations_applied": ["Error occurred - maintaining current path"],
                "adaptation_timestamp": datetime.now().isoformat(),
                "adaptation_confidence": 0.5,
            }

    def _calculate_adaptation_improvement(
        self,
        performance_update: dict[str, Any],
        adapted_path_data: dict[str, Any],
        required_adaptations: list[str],
    ) -> float:
        """Calculate estimated improvement from path adaptation"""
        try:
            base_improvement = 0.1  # 10% base improvement from any adaptation

            # Improvement based on adaptation types
            improvement_values = {
                "add_remedial_content": 0.15,
                "reduce_difficulty": 0.12,
                "increase_difficulty": 0.08,
                "add_advanced_content": 0.10,
                "prioritize_gap_content": 0.20,
                "extend_timeline": 0.08,
                "increase_interactivity": 0.12,
                "adjust_content_types": 0.10,
            }

            total_improvement = base_improvement
            for adaptation in required_adaptations:
                if adaptation in improvement_values:
                    total_improvement += improvement_values[adaptation]
                elif adaptation.startswith("reinforce_") or adaptation.startswith(
                    "advance_"
                ):
                    total_improvement += 0.10  # Domain-specific improvements

            # Cap improvement estimate
            return min(0.4, total_improvement)  # Maximum 40% improvement

        except Exception as e:
            logger.error(f"Error calculating adaptation improvement: {str(e)}")
            return 0.1  # Default modest improvement

    # Study plan generation methods

    async def _generate_weekly_schedule(
        self,
        optimized_path: dict[str, Any],
        weekly_time_budget: int,
        study_duration_weeks: int,
    ) -> list[dict[str, Any]]:
        """Generate weekly study schedule for adaptive study plan"""
        try:
            weekly_schedules = []
            path_steps = optimized_path.get("steps", [])

            # Distribute steps across weeks
            steps_per_week = max(1, len(path_steps) // study_duration_weeks)

            for week in range(study_duration_weeks):
                start_step = week * steps_per_week
                end_step = min((week + 1) * steps_per_week, len(path_steps))
                week_steps = path_steps[start_step:end_step]

                # Calculate weekly time allocation
                total_step_time = sum(
                    step.get("resource", {}).get("estimated_duration", 30)
                    for step in week_steps
                )

                # Adjust if over budget
                if total_step_time > weekly_time_budget:
                    time_scale_factor = weekly_time_budget / total_step_time
                    for step in week_steps:
                        step["allocated_time"] = int(
                            step.get("resource", {}).get("estimated_duration", 30)
                            * time_scale_factor
                        )
                else:
                    for step in week_steps:
                        step["allocated_time"] = step.get("resource", {}).get(
                            "estimated_duration", 30
                        )

                weekly_schedule = {
                    "week": week + 1,
                    "learning_steps": week_steps,
                    "total_time_minutes": min(total_step_time, weekly_time_budget),
                    "daily_sessions": self._distribute_weekly_sessions(
                        week_steps, 5
                    ),  # 5 days per week
                    "assessment_items": [],
                    "milestone_checks": [],
                }

                weekly_schedules.append(weekly_schedule)

            return weekly_schedules

        except Exception as e:
            logger.error(f"Error generating weekly schedule: {str(e)}")
            return []

    def _distribute_weekly_sessions(
        self, week_steps: list[dict[str, Any]], days_per_week: int
    ) -> list[dict[str, Any]]:
        """Distribute weekly learning steps across daily sessions"""
        daily_sessions = []

        steps_per_day = max(1, len(week_steps) // days_per_week)

        for day in range(days_per_week):
            start_step = day * steps_per_day
            end_step = min((day + 1) * steps_per_day, len(week_steps))
            day_steps = week_steps[start_step:end_step]

            if day_steps:
                session_time = sum(step.get("allocated_time", 30) for step in day_steps)
                daily_sessions.append(
                    {
                        "day": day + 1,
                        "steps": day_steps,
                        "session_time_minutes": session_time,
                        "recommended_time_of_day": "morning"
                        if session_time > 60
                        else "any",
                    }
                )

        return daily_sessions

    def _create_adaptive_milestones(
        self,
        learning_path: dict[str, Any],
        student_analysis: dict[str, Any],
        study_duration_weeks: int,
    ) -> list[dict[str, Any]]:
        """Create adaptive milestones that adjust based on progress"""
        try:
            milestones = []

            # Weekly progress milestones
            for week in range(1, study_duration_weeks + 1):
                progress_percentage = (week / study_duration_weeks) * 100

                milestone = {
                    "week": week,
                    "title": f"Week {week} Progress Check",
                    "description": f"Complete {progress_percentage:.0f}% of learning path",
                    "target_metrics": {
                        "completion_rate": progress_percentage / 100,
                        "competency_improvement": 0.05
                        * week,  # 5% improvement per week
                        "engagement_threshold": 0.7,
                    },
                    "adaptive_criteria": {
                        "adjust_if_behind": "extend_timeline_by_days",
                        "adjust_if_ahead": "add_advanced_content",
                        "minimum_performance": 0.6,
                    },
                }
                milestones.append(milestone)

            # Competency-based milestones
            competency_progression = student_analysis.get("competency_progression", {})
            domain_progressions = competency_progression.get("domain_progressions", {})

            for domain in domain_progressions.keys():
                milestone = {
                    "week": study_duration_weeks // 2,  # Mid-point check
                    "title": f"{domain.replace('_', ' ').title()} Competency Milestone",
                    "description": f"Demonstrate improved proficiency in {domain}",
                    "target_metrics": {
                        "competency_increase": 0.15,
                        "assessment_score": 0.75,
                    },
                    "adaptive_criteria": {
                        "adjust_if_not_met": f"add_{domain}_remedial_content"
                    },
                }
                milestones.append(milestone)

            return milestones

        except Exception as e:
            logger.error(f"Error creating adaptive milestones: {str(e)}")
            return []

    def _create_assessment_schedule(
        self, priority_competencies: list[str], study_duration_weeks: int
    ) -> list[dict[str, Any]]:
        """Create assessment schedule for progress tracking"""
        try:
            assessments = []

            # Weekly mini-assessments
            for week in range(1, study_duration_weeks + 1):
                assessment = {
                    "week": week,
                    "type": "progress_check",
                    "title": f"Week {week} Progress Assessment",
                    "duration_minutes": 15,
                    "competencies_assessed": priority_competencies[
                        :2
                    ],  # Focus on 2 competencies
                    "adaptive_features": {
                        "adjust_difficulty": True,
                        "personalize_questions": True,
                    },
                }
                assessments.append(assessment)

            # Mid-term comprehensive assessment
            if study_duration_weeks >= 4:
                mid_assessment = {
                    "week": study_duration_weeks // 2,
                    "type": "comprehensive",
                    "title": "Mid-Study Comprehensive Assessment",
                    "duration_minutes": 45,
                    "competencies_assessed": priority_competencies,
                    "adaptive_features": {
                        "determine_path_adjustments": True,
                        "identify_new_gaps": True,
                    },
                }
                assessments.append(mid_assessment)

            # Final assessment
            final_assessment = {
                "week": study_duration_weeks,
                "type": "final",
                "title": "Final Study Plan Assessment",
                "duration_minutes": 60,
                "competencies_assessed": priority_competencies,
                "adaptive_features": {
                    "measure_improvement": True,
                    "validate_learning_outcomes": True,
                },
            }
            assessments.append(final_assessment)

            return assessments

        except Exception as e:
            logger.error(f"Error creating assessment schedule: {str(e)}")
            return []

    async def _calculate_study_plan_predictions(
        self,
        student_analysis: dict[str, Any],
        learning_path: dict[str, Any],
        weekly_time_budget: int,
    ) -> dict[str, Any]:
        """Calculate predictions for study plan success"""
        try:
            # Extract baseline metrics
            progress_metrics = student_analysis.get("progress_metrics", {})
            current_performance = progress_metrics.get("overall_progress", 0.7)
            engagement_score = progress_metrics.get("engagement_score", 0.7)

            # Calculate completion probability
            time_factor = (
                1.0 if weekly_time_budget >= 300 else weekly_time_budget / 300
            )  # 300 min = optimal
            performance_factor = current_performance
            engagement_factor = engagement_score

            completion_probability = (
                time_factor + performance_factor + engagement_factor
            ) / 3
            completion_probability = max(0.5, min(0.95, completion_probability))

            # Calculate competency improvement predictions
            knowledge_gaps = student_analysis.get("knowledge_gaps", [])
            gap_count = len(knowledge_gaps)

            # More gaps = more room for improvement
            improvement_potential = min(0.4, 0.05 + (gap_count * 0.03))

            competency_targets = {}
            for domain in AACNDomain:
                current_level = (
                    student_analysis.get("competency_progression", {})
                    .get("domain_progressions", {})
                    .get(domain.value, {})
                    .get("current_score", 0.7)
                )

                target_improvement = improvement_potential * (
                    1.0 - current_level
                )  # More improvement for lower scores
                competency_targets[domain.value] = min(
                    0.95, current_level + target_improvement
                )

            return {
                "completion_probability": completion_probability,
                "competency_targets": competency_targets,
                "expected_improvement": improvement_potential,
                "time_efficiency": time_factor,
                "engagement_prediction": min(
                    0.95, engagement_score + 0.1
                ),  # Expect slight engagement boost
                "success_factors": [
                    "Personalized content selection",
                    "Adaptive difficulty progression",
                    "Real-time progress monitoring",
                    "Competency-based milestones",
                ],
                "risk_factors": [
                    factor
                    for factor in student_analysis.get("risk_assessment", {}).get(
                        "risk_factors", []
                    )
                    if factor
                ],
            }

        except Exception as e:
            logger.error(f"Error calculating study plan predictions: {str(e)}")
            return {
                "completion_probability": 0.75,
                "expected_improvement": 0.15,
                "engagement_prediction": 0.75,
            }

    # Additional helper methods for path enhancement

    async def _add_remedial_content(
        self, path: OptimizedLearningPath, student_analysis: dict[str, Any]
    ) -> OptimizedLearningPath:
        """Add remedial content for students at high risk"""
        # Mock implementation - would add actual remedial content
        logger.info("Adding remedial content to learning path")
        return path

    async def _add_advanced_content(
        self, path: OptimizedLearningPath, student_analysis: dict[str, Any]
    ) -> OptimizedLearningPath:
        """Add advanced content for high-performing students"""
        # Mock implementation - would add actual advanced content
        logger.info("Adding advanced content to learning path")
        return path

    def _adjust_for_low_engagement(
        self, path: OptimizedLearningPath
    ) -> OptimizedLearningPath:
        """Adjust path to boost engagement"""
        # Mock implementation - would modify content types for engagement
        logger.info("Adjusting path for increased engagement")
        return path
