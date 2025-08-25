import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from ..services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)


class LearningResource(BaseModel):
    id: str
    title: str
    type: str
    difficulty: str
    estimated_duration: int
    topics: list[str]
    prerequisites: list[str]


class LearningStep(BaseModel):
    sequence: int
    resource: LearningResource
    expected_outcome: str
    assessment_criteria: list[str]


class OptimizedLearningPath(BaseModel):
    student_id: str
    goal: str
    steps: list[LearningStep]
    total_duration: int
    milestones: list[str]
    success_metrics: dict[str, float]
    created_date: str


class LearningPathOptimizer:
    """
    Advanced Learning Path Optimizer for BSN Knowledge

    Creates personalized learning paths based on:
    - Individual knowledge gaps and competency levels
    - Learning preferences and styles
    - Time constraints and goals
    - RAGnostic content analysis
    - AACN competency framework alignment
    """

    def __init__(self, ragnostic_client: RAGnosticClient | None = None):
        self.ragnostic_client = ragnostic_client
        self.resources = {}
        self._load_default_resources()
        logger.info("Learning Path Optimizer initialized")

    def _load_default_resources(self):
        """Load default learning resources database"""
        # Mock learning resources - would be loaded from database in production
        self.resources = {
            "fundamental_nursing": LearningResource(
                id="fund_nursing_001",
                title="Fundamental Nursing Concepts",
                type="interactive_module",
                difficulty="beginner",
                estimated_duration=120,
                topics=["basic_patient_care", "nursing_process", "safety"],
                prerequisites=[],
            ),
            "pharmacology_basics": LearningResource(
                id="pharm_001",
                title="Basic Pharmacology for Nurses",
                type="video_lecture",
                difficulty="intermediate",
                estimated_duration=180,
                topics=[
                    "medication_administration",
                    "drug_interactions",
                    "dosage_calculations",
                ],
                prerequisites=["fundamental_nursing"],
            ),
            "clinical_judgment": LearningResource(
                id="clinical_001",
                title="Clinical Judgment and Decision Making",
                type="case_study",
                difficulty="advanced",
                estimated_duration=240,
                topics=[
                    "critical_thinking",
                    "patient_assessment",
                    "clinical_reasoning",
                ],
                prerequisites=["fundamental_nursing", "pharmacology_basics"],
            ),
        }

    async def create_optimized_path(
        self,
        student_id: str,
        knowledge_gaps: list[dict[str, Any]],
        learning_preferences: dict[str, Any],
        time_constraints: int | None = None,
    ) -> OptimizedLearningPath:
        """
        Create an optimized learning path tailored to the student's specific needs.

        Args:
            student_id: Student identifier
            knowledge_gaps: Identified knowledge gaps with severity and domain info
            learning_preferences: Student's learning style and preferences
            time_constraints: Available study time in minutes per week

        Returns:
            Optimized learning path with sequenced steps and resources
        """
        try:
            logger.info(f"Creating optimized learning path for student {student_id}")

            # Prioritize knowledge gaps by severity and impact
            prioritized_gaps = self._prioritize_gaps(knowledge_gaps)

            # Map gaps to learning resources
            required_resources = await self._map_gaps_to_resources(prioritized_gaps)

            # Optimize resource sequence based on prerequisites
            optimized_sequence = self._optimize_resource_sequence(required_resources)

            # Apply learning preferences to customize path
            customized_path = self._customize_for_preferences(
                optimized_sequence, learning_preferences
            )

            # Adjust for time constraints
            if time_constraints:
                customized_path = self._adjust_for_time_constraints(
                    customized_path, time_constraints
                )

            # Create learning steps
            learning_steps = []
            total_duration = 0

            for i, resource in enumerate(customized_path):
                step = LearningStep(
                    sequence=i + 1,
                    resource=resource,
                    expected_outcome=self._generate_expected_outcome(resource),
                    assessment_criteria=self._generate_assessment_criteria(resource),
                )
                learning_steps.append(step)
                total_duration += resource.estimated_duration

            # Generate milestones and success metrics
            milestones = self._generate_milestones(learning_steps)
            success_metrics = self._calculate_success_metrics(
                learning_steps, knowledge_gaps
            )

            optimized_path = OptimizedLearningPath(
                student_id=student_id,
                goal=f"Address {len(prioritized_gaps)} knowledge gaps with personalized learning",
                steps=learning_steps,
                total_duration=total_duration,
                milestones=milestones,
                success_metrics=success_metrics,
                created_date=datetime.now().isoformat(),
            )

            logger.info(
                f"Optimized learning path created: {len(learning_steps)} steps, {total_duration} minutes total"
            )
            return optimized_path

        except Exception as e:
            logger.error(f"Error creating optimized learning path: {str(e)}")
            raise

    async def adapt_path(
        self, path: OptimizedLearningPath, progress_data: dict[str, Any]
    ) -> OptimizedLearningPath:
        """
        Adapt existing learning path based on student progress and performance.

        Args:
            path: Current learning path
            progress_data: Student progress and performance data

        Returns:
            Adapted learning path with modified sequence or resources
        """
        try:
            logger.info(f"Adapting learning path for student {path.student_id}")

            # Analyze progress against current path
            progress_analysis = self._analyze_path_progress(path, progress_data)

            # Identify struggling areas
            struggling_areas = progress_analysis.get("struggling_areas", [])

            # Identify accelerating areas
            accelerating_areas = progress_analysis.get("accelerating_areas", [])

            adapted_steps = []

            for step in path.steps:
                if step.resource.id in struggling_areas:
                    # Add remedial resources for struggling areas
                    remedial_step = self._create_remedial_step(step)
                    if remedial_step:
                        adapted_steps.append(remedial_step)

                    # Modify original step for easier difficulty
                    modified_step = self._modify_step_difficulty(step, "easier")
                    adapted_steps.append(modified_step)

                elif step.resource.id in accelerating_areas:
                    # Add advanced resources for accelerating areas
                    advanced_step = self._create_advanced_step(step)
                    adapted_steps.append(step)  # Keep original
                    if advanced_step:
                        adapted_steps.append(advanced_step)
                else:
                    # Keep step as is
                    adapted_steps.append(step)

            # Recalculate metrics
            total_duration = sum(
                step.resource.estimated_duration for step in adapted_steps
            )
            milestones = self._generate_milestones(adapted_steps)

            # Update path
            adapted_path = OptimizedLearningPath(
                student_id=path.student_id,
                goal=path.goal + " (Adapted based on progress)",
                steps=adapted_steps,
                total_duration=total_duration,
                milestones=milestones,
                success_metrics=path.success_metrics,
                created_date=datetime.now().isoformat(),
            )

            logger.info(
                f"Learning path adapted: {len(adapted_steps)} steps, {total_duration} minutes"
            )
            return adapted_path

        except Exception as e:
            logger.error(f"Error adapting learning path: {str(e)}")
            raise

    async def recommend_next_action(
        self,
        student_id: str,
        current_path: OptimizedLearningPath,
        recent_performance: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Recommend the next learning action based on current path and performance.

        Args:
            student_id: Student identifier
            current_path: Current learning path
            recent_performance: Recent performance metrics

        Returns:
            Next action recommendation with rationale and alternatives
        """
        try:
            logger.info(
                f"Generating next action recommendation for student {student_id}"
            )

            # Find current position in path
            current_step = self._find_current_step(current_path, recent_performance)

            if current_step is None:
                # Path completed or not started
                next_action = self._recommend_path_completion_action(
                    current_path, recent_performance
                )
            else:
                # Recommend based on current step performance
                next_action = self._recommend_step_action(
                    current_step, recent_performance
                )

            # Add contextual information
            next_action.update(
                {
                    "student_id": student_id,
                    "recommendation_timestamp": datetime.now().isoformat(),
                    "path_progress": self._calculate_path_progress(
                        current_path, recent_performance
                    ),
                    "estimated_time_to_completion": self._estimate_completion_time(
                        current_path, recent_performance
                    ),
                    "confidence_score": 0.85,  # Mock confidence score
                }
            )

            logger.info(
                f"Next action recommended: {next_action.get('primary_action', {}).get('type', 'unknown')}"
            )
            return next_action

        except Exception as e:
            logger.error(f"Error recommending next action: {str(e)}")
            raise

    def validate_path_feasibility(
        self, path: OptimizedLearningPath, student_constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Validate the feasibility of a learning path against student constraints.

        Args:
            path: Learning path to validate
            student_constraints: Student's time, difficulty, and other constraints

        Returns:
            Feasibility analysis with recommendations for adjustment
        """
        try:
            logger.info(f"Validating path feasibility for student {path.student_id}")

            feasibility_analysis = {
                "is_feasible": True,
                "feasibility_score": 100.0,
                "constraint_violations": [],
                "recommendations": [],
            }

            # Check time constraints
            time_feasibility = self._check_time_feasibility(path, student_constraints)
            if not time_feasibility["feasible"]:
                feasibility_analysis["is_feasible"] = False
                feasibility_analysis["feasibility_score"] -= 30
                feasibility_analysis["constraint_violations"].append(
                    time_feasibility["violation"]
                )
                feasibility_analysis["recommendations"].append(
                    time_feasibility["recommendation"]
                )

            # Check difficulty feasibility
            difficulty_feasibility = self._check_difficulty_feasibility(
                path, student_constraints
            )
            if not difficulty_feasibility["feasible"]:
                feasibility_analysis["feasibility_score"] -= 20
                feasibility_analysis["constraint_violations"].append(
                    difficulty_feasibility["violation"]
                )
                feasibility_analysis["recommendations"].append(
                    difficulty_feasibility["recommendation"]
                )

            # Check prerequisite feasibility
            prerequisite_feasibility = self._check_prerequisite_feasibility(
                path, student_constraints
            )
            if not prerequisite_feasibility["feasible"]:
                feasibility_analysis["is_feasible"] = False
                feasibility_analysis["feasibility_score"] -= 40
                feasibility_analysis["constraint_violations"].append(
                    prerequisite_feasibility["violation"]
                )
                feasibility_analysis["recommendations"].append(
                    prerequisite_feasibility["recommendation"]
                )

            # Check learning style alignment
            style_alignment = self._check_learning_style_alignment(
                path, student_constraints
            )
            feasibility_analysis["feasibility_score"] += style_alignment["bonus_points"]
            if style_alignment["recommendations"]:
                feasibility_analysis["recommendations"].extend(
                    style_alignment["recommendations"]
                )

            # Ensure feasibility score is within bounds
            feasibility_analysis["feasibility_score"] = max(
                0, min(100, feasibility_analysis["feasibility_score"])
            )

            logger.info(
                f"Path feasibility validated: {feasibility_analysis['feasibility_score']:.1f}% feasible"
            )
            return feasibility_analysis

        except Exception as e:
            logger.error(f"Error validating path feasibility: {str(e)}")
            return {
                "is_feasible": False,
                "feasibility_score": 0.0,
                "constraint_violations": ["Validation error occurred"],
                "recommendations": ["Please try again or contact support"],
            }

    # Private helper methods

    def _prioritize_gaps(
        self, knowledge_gaps: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Prioritize knowledge gaps by severity and domain importance"""
        severity_weights = {"critical": 4, "major": 3, "moderate": 2, "minor": 1}

        def gap_priority(gap):
            severity_score = severity_weights.get(gap.get("severity", "minor"), 1)
            domain_score = (
                2 if gap.get("domain") in ["patient_safety", "clinical_judgment"] else 1
            )
            return severity_score * domain_score

        return sorted(knowledge_gaps, key=gap_priority, reverse=True)

    async def _map_gaps_to_resources(
        self, gaps: list[dict[str, Any]]
    ) -> list[LearningResource]:
        """Map knowledge gaps to appropriate learning resources"""
        resources = []
        for gap in gaps:
            # Simple mapping logic - would be more sophisticated in production
            gap_topics = gap.get("topics", [])
            for _resource_id, resource in self.resources.items():
                if any(topic in resource.topics for topic in gap_topics):
                    resources.append(resource)
                    break
        return list(set(resources))  # Remove duplicates

    def _optimize_resource_sequence(
        self, resources: list[LearningResource]
    ) -> list[LearningResource]:
        """Optimize the sequence of resources based on prerequisites"""
        # Topological sort based on prerequisites
        sequenced = []
        remaining = resources.copy()

        while remaining:
            # Find resources with no unmet prerequisites
            ready = [
                r
                for r in remaining
                if all(
                    prereq in [s.id for s in sequenced] or prereq == ""
                    for prereq in r.prerequisites
                )
            ]

            if not ready:
                # Add fundamental resources if stuck
                ready = [r for r in remaining if not r.prerequisites]
                if not ready:
                    ready = [remaining[0]]  # Fallback

            # Sort by difficulty (easier first)
            difficulty_order = {"beginner": 1, "intermediate": 2, "advanced": 3}
            ready.sort(key=lambda x: difficulty_order.get(x.difficulty, 2))

            next_resource = ready[0]
            sequenced.append(next_resource)
            remaining.remove(next_resource)

        return sequenced

    def _customize_for_preferences(
        self, resources: list[LearningResource], preferences: dict[str, Any]
    ) -> list[LearningResource]:
        """Customize resource selection based on learning preferences"""
        preferred_types = preferences.get("preferred_content_types", [])
        if not preferred_types:
            return resources

        # Reorder to prefer certain types
        customized = []
        for pref_type in preferred_types:
            customized.extend([r for r in resources if r.type == pref_type])

        # Add remaining resources
        for resource in resources:
            if resource not in customized:
                customized.append(resource)

        return customized

    def _adjust_for_time_constraints(
        self, resources: list[LearningResource], time_constraint: int
    ) -> list[LearningResource]:
        """Adjust path to fit within time constraints"""
        total_time = sum(r.estimated_duration for r in resources)
        if total_time <= time_constraint:
            return resources

        # Prioritize by importance and reduce duration
        adjusted = []
        remaining_time = time_constraint

        for resource in resources:
            if resource.estimated_duration <= remaining_time:
                adjusted.append(resource)
                remaining_time -= resource.estimated_duration
            elif remaining_time > 60:  # At least 1 hour remaining
                # Create shortened version
                shortened = LearningResource(
                    id=resource.id + "_short",
                    title=resource.title + " (Essential)",
                    type=resource.type,
                    difficulty=resource.difficulty,
                    estimated_duration=min(resource.estimated_duration, remaining_time),
                    topics=resource.topics[:2],  # Limit topics
                    prerequisites=resource.prerequisites,
                )
                adjusted.append(shortened)
                break

        return adjusted

    def _generate_expected_outcome(self, resource: LearningResource) -> str:
        """Generate expected learning outcome for a resource"""
        return f"Master {', '.join(resource.topics[:2])} concepts at {resource.difficulty} level"

    def _generate_assessment_criteria(self, resource: LearningResource) -> list[str]:
        """Generate assessment criteria for a resource"""
        criteria = []
        for topic in resource.topics[:2]:
            criteria.append(f"Demonstrate understanding of {topic}")
        criteria.append(f"Complete {resource.type} with 80% accuracy")
        return criteria

    def _generate_milestones(self, steps: list[LearningStep]) -> list[str]:
        """Generate learning milestones"""
        milestones = []
        milestone_points = [
            len(steps) // 4,
            len(steps) // 2,
            3 * len(steps) // 4,
            len(steps),
        ]

        for point in milestone_points:
            if point > 0 and point <= len(steps):
                milestone = f"Complete {point} learning steps - {steps[point - 1].resource.title}"
                milestones.append(milestone)

        return milestones

    def _calculate_success_metrics(
        self, steps: list[LearningStep], gaps: list[dict[str, Any]]
    ) -> dict[str, float]:
        """Calculate success metrics for the path"""
        return {
            "knowledge_gap_closure_rate": min(1.0, len(steps) / max(len(gaps), 1)),
            "competency_improvement_target": 0.85,
            "engagement_target": 0.80,
            "completion_target": 0.90,
        }

    # Additional helper methods would be implemented here for complete functionality
    # Including methods for:
    # - _analyze_path_progress
    # - _create_remedial_step
    # - _modify_step_difficulty
    # - _check_time_feasibility
    # - _check_difficulty_feasibility
    # - etc.

    def _find_current_step(
        self, path: OptimizedLearningPath, performance: dict[str, Any]
    ) -> LearningStep | None:
        """Find current step in learning path"""
        completed_steps = performance.get("completed_steps", [])
        for step in path.steps:
            if step.sequence not in completed_steps:
                return step
        return None

    def _recommend_step_action(
        self, step: LearningStep, performance: dict[str, Any]
    ) -> dict[str, Any]:
        """Recommend action for current step"""
        return {
            "primary_action": {
                "type": "continue_learning",
                "resource": step.resource.title,
                "description": f"Continue with {step.resource.title} ({step.resource.type})",
            },
            "alternative_actions": [
                {
                    "type": "review_prerequisites",
                    "description": "Review prerequisite concepts if struggling",
                },
                {
                    "type": "seek_help",
                    "description": "Request instructor assistance for difficult concepts",
                },
            ],
            "rationale": f"Based on your progress, continuing with {step.resource.title} will help address your knowledge gaps in {', '.join(step.resource.topics)}",
        }

    def _recommend_path_completion_action(
        self, path: OptimizedLearningPath, performance: dict[str, Any]
    ) -> dict[str, Any]:
        """Recommend action when path is completed or not started"""
        if not performance.get("completed_steps"):
            return {
                "primary_action": {
                    "type": "start_learning_path",
                    "description": f"Begin your personalized learning path with {path.steps[0].resource.title}",
                },
                "rationale": "Start your learning journey with the first step in your optimized path",
            }
        else:
            return {
                "primary_action": {
                    "type": "assess_progress",
                    "description": "Take a competency assessment to measure your progress",
                },
                "alternative_actions": [
                    {
                        "type": "advanced_learning",
                        "description": "Explore advanced topics in your areas of strength",
                    }
                ],
                "rationale": "You've completed your learning path - time to assess your competency gains",
            }

    def _calculate_path_progress(
        self, path: OptimizedLearningPath, performance: dict[str, Any]
    ) -> float:
        """Calculate progress through learning path"""
        completed_steps = len(performance.get("completed_steps", []))
        total_steps = len(path.steps)
        return completed_steps / total_steps if total_steps > 0 else 0.0

    def _estimate_completion_time(
        self, path: OptimizedLearningPath, performance: dict[str, Any]
    ) -> int:
        """Estimate time to complete remaining path"""
        completed_steps = set(performance.get("completed_steps", []))
        remaining_duration = sum(
            step.resource.estimated_duration
            for step in path.steps
            if step.sequence not in completed_steps
        )
        return remaining_duration

    def _check_time_feasibility(
        self, path: OptimizedLearningPath, constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """Check if path fits within time constraints"""
        available_time = (
            constraints.get("available_hours_per_week", 0) * 60
        )  # Convert to minutes
        weekly_duration = path.total_duration / 4  # Assume 4-week path

        if weekly_duration <= available_time:
            return {"feasible": True}
        else:
            return {
                "feasible": False,
                "violation": f"Path requires {weekly_duration:.0f} minutes/week but only {available_time:.0f} available",
                "recommendation": "Consider reducing path scope or extending timeline",
            }

    def _check_difficulty_feasibility(
        self, path: OptimizedLearningPath, constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """Check if path difficulty aligns with student level"""
        max_difficulty = constraints.get("max_difficulty_level", "advanced")
        difficulty_levels = {"beginner": 1, "intermediate": 2, "advanced": 3}
        max_level = difficulty_levels.get(max_difficulty, 3)

        path_difficulties = [
            difficulty_levels.get(step.resource.difficulty, 2) for step in path.steps
        ]
        if all(level <= max_level for level in path_difficulties):
            return {"feasible": True}
        else:
            return {
                "feasible": False,
                "violation": f"Path contains resources above {max_difficulty} difficulty level",
                "recommendation": "Replace advanced resources with intermediate alternatives",
            }

    def _check_prerequisite_feasibility(
        self, path: OptimizedLearningPath, constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """Check if student meets prerequisites"""
        completed_courses = set(constraints.get("completed_courses", []))
        missing_prerequisites = []

        for step in path.steps:
            for prereq in step.resource.prerequisites:
                if prereq and prereq not in completed_courses:
                    missing_prerequisites.append(prereq)

        if not missing_prerequisites:
            return {"feasible": True}
        else:
            return {
                "feasible": False,
                "violation": f"Missing prerequisites: {', '.join(set(missing_prerequisites))}",
                "recommendation": "Complete prerequisite courses or modify path sequence",
            }

    def _check_learning_style_alignment(
        self, path: OptimizedLearningPath, constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """Check alignment with learning style preferences"""
        preferred_types = set(constraints.get("preferred_content_types", []))
        if not preferred_types:
            return {"bonus_points": 0, "recommendations": []}

        path_types = [step.resource.type for step in path.steps]
        alignment_score = sum(1 for ptype in path_types if ptype in preferred_types)
        alignment_ratio = alignment_score / len(path_types) if path_types else 0

        bonus_points = alignment_ratio * 10  # Up to 10 bonus points
        recommendations = []

        if alignment_ratio < 0.5:
            recommendations.append(
                "Consider adding more resources of your preferred content types"
            )

        return {"bonus_points": bonus_points, "recommendations": recommendations}
