#!/usr/bin/env python3
"""
B.5 Adaptive Learning Engine Implementation Test Suite

Comprehensive testing for B.5 Adaptive Learning Engine per REVISED_PHASE3_PLAN.md:
- Personalized content generation with performance analysis
- Dynamic difficulty adjustment using B.4 competency data
- Learning path optimization with RAGnostic integration
- Real-time path adaptation based on performance updates
- Adaptive study plan generation with tracking features

Tests B.4 Learning Analytics foundation integration and validates
all REVISED_PHASE3_PLAN.md B.5 success criteria.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def print_test_header(test_name: str):
    """Print formatted test header"""
    print("\n" + "=" * 80)
    print(f"🧪 TESTING: {test_name}")
    print("=" * 80)


def print_success(message: str):
    """Print success message"""
    print(f"✅ SUCCESS: {message}")


def print_error(message: str):
    """Print error message"""
    print(f"❌ ERROR: {message}")


def print_info(message: str):
    """Print info message"""
    print(f"ℹ️  INFO: {message}")


class MockRAGnosticClient:
    """Mock RAGnostic client for testing"""

    async def search_content(self, query: str) -> Dict[str, Any]:
        """Mock content search"""
        return {
            "results": [
                {
                    "id": f"content_{hash(query) % 1000}",
                    "title": f"Content for: {query[:30]}...",
                    "type": "interactive_module",
                    "difficulty": "intermediate",
                    "duration": 45,
                    "learning_objectives": [
                        "Understand key concepts",
                        "Apply knowledge",
                    ],
                    "prerequisites": ["basic_nursing"],
                    "concepts": ["patient_safety", "clinical_judgment"],
                }
            ]
        }


class MockAnalyticsService:
    """Mock analytics service for testing"""

    async def get_student_progress(self, student_id: str) -> Any:
        """Mock student progress data"""
        from src.models.assessment_models import StudentProgressMetrics

        return StudentProgressMetrics(
            student_id=student_id,
            average_score=0.75,
            engagement_score=0.8,
            consistency_score=0.7,
            learning_velocity=0.6,
            improvement_rate=0.05,
            success_factors=["consistent_study", "active_participation"],
            risk_factors=["time_management"]
            if student_id == "struggling_student"
            else [],
            last_updated=datetime.now(),
        )

    async def _get_student_competency_profile(self, student_id: str) -> Any:
        """Mock competency profile"""
        from src.models.assessment_models import StudentCompetencyProfile

        return StudentCompetencyProfile(
            student_id=student_id,
            competency_gpa=3.2,
            graduation_readiness_score=0.75,
            semester=4,
            last_assessment_date=datetime.now(),
        )

    async def _get_student_profile(self, student_id: str) -> Dict[str, Any]:
        """Mock student profile"""
        return {
            "student_id": student_id,
            "preferences": {
                "learning_style": "visual",
                "content_types": ["interactive", "video"],
                "difficulty_preference": "adaptive",
                "study_time": {"weekly_hours": 10, "session_length": 60},
            },
            "academic_record": {
                "courses_completed": ["nursing_fundamentals", "anatomy"]
            },
        }


async def test_adaptive_learning_engine_initialization():
    """Test B.5 AdaptiveLearningEngine initialization with B.4 integration"""
    print_test_header("B.5 AdaptiveLearningEngine Initialization")

    try:
        from src.services.adaptive_learning_engine import AdaptiveLearningEngine
        from src.services.learning_analytics import LearningAnalytics
        from src.assessment.knowledge_gap_analyzer import KnowledgeGapAnalyzer
        from src.assessment.learning_path_optimizer import LearningPathOptimizer

        # Create mock dependencies
        ragnostic_client = MockRAGnosticClient()
        analytics_service = MockAnalyticsService()

        # Initialize B.4 components
        learning_analytics = LearningAnalytics(ragnostic_client, analytics_service)
        gap_analyzer = KnowledgeGapAnalyzer(ragnostic_client)
        path_optimizer = LearningPathOptimizer(ragnostic_client)

        # Initialize B.5 AdaptiveLearningEngine
        adaptive_engine = AdaptiveLearningEngine(
            learning_analytics=learning_analytics,
            ragnostic_client=ragnostic_client,
            analytics_service=analytics_service,
            gap_analyzer=gap_analyzer,
            path_optimizer=path_optimizer,
        )

        print_success(
            "AdaptiveLearningEngine initialized successfully with B.4 integration"
        )
        print_info(
            "Engine components: learning_analytics, gap_analyzer, path_optimizer"
        )
        print_info(
            f"Performance thresholds configured: {adaptive_engine.performance_thresholds}"
        )

        return adaptive_engine

    except Exception as e:
        print_error(f"Failed to initialize AdaptiveLearningEngine: {str(e)}")
        raise


async def test_personalized_content_generation(adaptive_engine):
    """Test B.5 personalized content generation"""
    print_test_header("B.5 Personalized Content Generation")

    try:
        # Test student profile
        student_profile = {
            "student_id": "test_student_001",
            "learning_style": "visual",
            "difficulty_preference": "adaptive",
            "content_types": ["interactive", "visual"],
            "time_constraints": {"daily_minutes": 90},
        }

        # Target competencies
        target_competencies = [
            "person_centered_care",
            "clinical_judgment",
            "healthcare_systems",
        ]

        # Generate personalized content
        print_info("Generating personalized content recommendations...")
        recommendations = await adaptive_engine.generate_personalized_content(
            student_profile=student_profile, target_competencies=target_competencies
        )

        # Validate results
        assert len(recommendations) > 0, "No recommendations generated"
        assert all(
            hasattr(rec, "personalization_score") for rec in recommendations
        ), "Missing personalization scores"
        assert all(
            rec.personalization_score > 0 for rec in recommendations
        ), "Invalid personalization scores"

        print_success(f"Generated {len(recommendations)} personalized recommendations")

        # Display sample recommendations
        for i, rec in enumerate(recommendations[:3]):
            print_info(
                f"Recommendation {i+1}: {rec.title} (Score: {rec.personalization_score:.2f}, Success Prob: {rec.success_probability:.2f})"
            )

        return recommendations

    except Exception as e:
        print_error(f"Failed personalized content generation test: {str(e)}")
        raise


async def test_learning_path_optimization(adaptive_engine):
    """Test B.5 learning path optimization with RAGnostic integration"""
    print_test_header("B.5 Learning Path Optimization")

    try:
        student_id = "test_student_002"
        target_competencies = [
            "knowledge_for_nursing_practice",
            "person_centered_care",
            "population_health",
        ]

        time_constraints = {"weekly_minutes": 300}  # 5 hours per week
        performance_context = {"current_performance": 0.7, "engagement": 0.8}

        print_info(
            "Optimizing learning path with B.4 analytics and RAGnostic integration..."
        )

        # Optimize learning path
        path_result = await adaptive_engine.optimize_learning_path(
            student_id=student_id,
            target_competencies=target_competencies,
            time_constraints=time_constraints,
            performance_context=performance_context,
        )

        # Validate results
        assert "path_id" in path_result, "Missing path_id"
        assert "optimized_path" in path_result, "Missing optimized path"
        assert "success_metrics" in path_result, "Missing success metrics"
        assert (
            "performance_predictions" in path_result
        ), "Missing performance predictions"

        # Check adaptive features
        adaptive_features = path_result.get("adaptation_features", {})
        expected_features = [
            "dynamic_difficulty",
            "real_time_adjustment",
            "performance_tracking",
            "prerequisite_optimization",
        ]

        for feature in expected_features:
            assert adaptive_features.get(
                feature, False
            ), f"Missing adaptive feature: {feature}"

        print_success(f"Learning path optimized: {path_result['path_id']}")
        print_info(
            f"Success probability: {path_result['performance_predictions']['completion_probability']:.2f}"
        )
        print_info(
            f"Adaptive features enabled: {len([f for f, enabled in adaptive_features.items() if enabled])}"
        )

        return path_result

    except Exception as e:
        print_error(f"Failed learning path optimization test: {str(e)}")
        raise


async def test_dynamic_difficulty_adjustment(adaptive_engine):
    """Test B.5 dynamic difficulty adjustment"""
    print_test_header("B.5 Dynamic Difficulty Adjustment")

    try:
        student_id = "test_student_003"
        current_content = {
            "difficulty_level": "intermediate",
            "content_type": "case_study",
            "duration": 45,
        }

        # Test different performance scenarios
        test_scenarios = [
            {
                "name": "High Performance",
                "recent_performance": {"scores": [0.9, 0.88, 0.92], "engagement": 0.85},
                "competency_context": {
                    "domain_progressions": {
                        "clinical_judgment": {"current_score": 0.85}
                    }
                },
            },
            {
                "name": "Low Performance",
                "recent_performance": {"scores": [0.5, 0.48, 0.52], "engagement": 0.6},
                "competency_context": {
                    "domain_progressions": {"clinical_judgment": {"current_score": 0.5}}
                },
            },
            {
                "name": "Declining Performance",
                "recent_performance": {"scores": [0.8, 0.7, 0.6], "engagement": 0.65},
                "competency_context": {
                    "domain_progressions": {
                        "clinical_judgment": {"current_score": 0.65}
                    }
                },
            },
        ]

        for scenario in test_scenarios:
            print_info(f"Testing scenario: {scenario['name']}")

            difficulty_adjustment = await adaptive_engine.adjust_difficulty_dynamically(
                student_id=student_id,
                current_content=current_content,
                recent_performance=scenario["recent_performance"],
                competency_context=scenario["competency_context"],
            )

            # Validate adjustment
            assert hasattr(
                difficulty_adjustment, "recommended_difficulty"
            ), "Missing recommended difficulty"
            assert hasattr(
                difficulty_adjustment, "confidence_score"
            ), "Missing confidence score"
            assert hasattr(
                difficulty_adjustment, "adjustment_reason"
            ), "Missing adjustment reason"
            assert (
                0 <= difficulty_adjustment.confidence_score <= 1
            ), "Invalid confidence score"

            print_info(f"  Current: {difficulty_adjustment.current_difficulty}")
            print_info(f"  Recommended: {difficulty_adjustment.recommended_difficulty}")
            print_info(f"  Confidence: {difficulty_adjustment.confidence_score:.2f}")
            print_info(f"  Reason: {difficulty_adjustment.adjustment_reason[:80]}...")

        print_success(
            "Dynamic difficulty adjustment working correctly for all scenarios"
        )

    except Exception as e:
        print_error(f"Failed dynamic difficulty adjustment test: {str(e)}")
        raise


async def test_realtime_path_adaptation(adaptive_engine):
    """Test B.5 real-time learning path adaptation"""
    print_test_header("B.5 Real-time Learning Path Adaptation")

    try:
        student_id = "test_student_004"
        current_path_id = "path_001"

        # Test significant performance change
        performance_update = {
            "recent_scores": [0.6, 0.5, 0.45],  # Declining performance
            "engagement_change": -0.3,  # 30% decrease in engagement
            "competency_changes": {
                "person_centered_care": -0.15,  # 15% decrease
                "clinical_judgment": -0.1,  # 10% decrease
            },
            "previous_critical_gaps": [],
        }

        competency_changes = {"person_centered_care": -0.15, "clinical_judgment": -0.1}

        print_info("Analyzing performance update for adaptation triggers...")

        # Perform real-time adaptation
        adaptation_result = await adaptive_engine.adapt_learning_path_realtime(
            student_id=student_id,
            current_path_id=current_path_id,
            performance_update=performance_update,
            competency_changes=competency_changes,
        )

        # Validate adaptation
        assert hasattr(
            adaptation_result, "adaptations_made"
        ), "Missing adaptations made"
        assert hasattr(
            adaptation_result, "estimated_improvement"
        ), "Missing improvement estimate"
        assert hasattr(
            adaptation_result, "adaptation_confidence"
        ), "Missing adaptation confidence"
        assert len(adaptation_result.adaptations_made) > 0, "No adaptations identified"

        print_success(
            f"Real-time adaptation completed: {adaptation_result.adapted_path_id}"
        )
        print_info(f"Adaptations made: {len(adaptation_result.adaptations_made)}")
        print_info(
            f"Estimated improvement: {adaptation_result.estimated_improvement:.2f}"
        )
        print_info(
            f"Adaptation confidence: {adaptation_result.adaptation_confidence:.2f}"
        )

        for adaptation in adaptation_result.adaptations_made[:3]:
            print_info(f"  - {adaptation}")

        return adaptation_result

    except Exception as e:
        print_error(f"Failed real-time path adaptation test: {str(e)}")
        raise


async def test_adaptive_study_plan_generation(adaptive_engine):
    """Test B.5 adaptive study plan generation"""
    print_test_header("B.5 Adaptive Study Plan Generation")

    try:
        student_id = "test_student_005"
        study_duration_weeks = 8
        weekly_time_budget = 420  # 7 hours per week
        priority_competencies = [
            "knowledge_for_nursing_practice",
            "person_centered_care",
            "population_health",
            "clinical_judgment",
        ]

        print_info(f"Generating {study_duration_weeks}-week adaptive study plan...")

        # Generate adaptive study plan
        study_plan = await adaptive_engine.generate_adaptive_study_plan(
            student_id=student_id,
            study_duration_weeks=study_duration_weeks,
            weekly_time_budget=weekly_time_budget,
            priority_competencies=priority_competencies,
        )

        # Validate study plan
        required_fields = [
            "plan_id",
            "personalized_content",
            "learning_path",
            "weekly_schedule",
            "milestones",
            "assessment_schedule",
            "adaptive_features",
            "success_predictions",
            "tracking_metrics",
        ]

        for field in required_fields:
            assert field in study_plan, f"Missing required field: {field}"

        # Validate adaptive features
        adaptive_features = study_plan["adaptive_features"]
        expected_adaptive_features = [
            "dynamic_difficulty_adjustment",
            "real_time_path_adaptation",
            "performance_based_content_selection",
            "automatic_milestone_adjustment",
            "competency_based_progression",
        ]

        for feature in expected_adaptive_features:
            assert adaptive_features.get(
                feature, False
            ), f"Missing adaptive feature: {feature}"

        # Validate success predictions
        success_predictions = study_plan["success_predictions"]
        assert (
            "completion_probability" in success_predictions
        ), "Missing completion probability"
        assert "competency_targets" in success_predictions, "Missing competency targets"
        assert (
            0 <= success_predictions["completion_probability"] <= 1
        ), "Invalid completion probability"

        print_success(f"Adaptive study plan generated: {study_plan['plan_id']}")
        print_info(
            f"Study duration: {study_duration_weeks} weeks, {weekly_time_budget} min/week"
        )
        print_info(
            f"Personalized content items: {len(study_plan['personalized_content'])}"
        )
        print_info(f"Weekly schedule entries: {len(study_plan['weekly_schedule'])}")
        print_info(f"Milestones: {len(study_plan['milestones'])}")
        print_info(f"Assessments scheduled: {len(study_plan['assessment_schedule'])}")
        print_info(
            f"Completion probability: {success_predictions['completion_probability']:.2f}"
        )

        return study_plan

    except Exception as e:
        print_error(f"Failed adaptive study plan generation test: {str(e)}")
        raise


async def test_b4_integration_validation(adaptive_engine):
    """Test B.4 Learning Analytics integration validation"""
    print_test_header("B.4 Learning Analytics Integration Validation")

    try:
        student_id = "integration_test_student"

        # Test B.4 LearningAnalytics integration
        print_info("Testing B.4 LearningAnalytics integration...")
        student_analysis = (
            await adaptive_engine.learning_analytics.analyze_student_progress(
                student_id
            )
        )

        # Validate B.4 analysis structure
        required_analysis_fields = [
            "progress_metrics",
            "competency_progression",
            "knowledge_gaps",
            "learning_recommendations",
            "risk_assessment",
        ]

        for field in required_analysis_fields:
            assert field in student_analysis, f"Missing B.4 analysis field: {field}"

        print_success("B.4 LearningAnalytics integration validated")

        # Test B.4 KnowledgeGapAnalyzer integration
        print_info("Testing B.4 KnowledgeGapAnalyzer integration...")

        # Mock assessment results
        assessment_results = {
            "domain_scores": {
                "person_centered_care": 0.7,
                "clinical_judgment": 0.6,
                "healthcare_systems": 0.8,
            }
        }

        target_competencies = ["person_centered_care", "clinical_judgment"]

        gap_analysis = await adaptive_engine.gap_analyzer.analyze_gaps(
            student_id=student_id,
            assessment_results=assessment_results,
            target_competencies=target_competencies,
        )

        # Validate gap analysis structure
        assert hasattr(gap_analysis, "gaps"), "Missing gaps in analysis"
        assert hasattr(gap_analysis, "overall_readiness"), "Missing overall readiness"
        assert hasattr(gap_analysis, "intervention_plan"), "Missing intervention plan"

        print_success("B.4 KnowledgeGapAnalyzer integration validated")

        # Test B.4 LearningPathOptimizer integration
        print_info("Testing B.4 LearningPathOptimizer integration...")

        # Mock learning preferences
        learning_preferences = {
            "preferred_content_types": ["interactive", "visual"],
            "learning_style": "visual",
            "available_hours_per_week": 8,
        }

        optimized_path = await adaptive_engine.path_optimizer.create_optimized_path(
            student_id=student_id,
            knowledge_gaps=gap_analysis.gaps,
            learning_preferences=learning_preferences,
            time_constraints=480,  # 8 hours in minutes
        )

        # Validate optimized path structure
        assert hasattr(optimized_path, "steps"), "Missing path steps"
        assert hasattr(optimized_path, "total_duration"), "Missing total duration"
        assert hasattr(optimized_path, "success_metrics"), "Missing success metrics"

        print_success("B.4 LearningPathOptimizer integration validated")

        print_success("All B.4 integrations validated successfully")

        return {
            "learning_analytics": student_analysis,
            "gap_analysis": gap_analysis,
            "optimized_path": optimized_path,
        }

    except Exception as e:
        print_error(f"Failed B.4 integration validation: {str(e)}")
        raise


async def test_performance_and_caching(adaptive_engine):
    """Test performance and caching features"""
    print_test_header("B.5 Performance and Caching Validation")

    try:
        student_id = "performance_test_student"

        # Test personalization cache
        student_profile = {
            "student_id": student_id,
            "learning_style": "kinesthetic",
            "difficulty_preference": "challenging",
        }

        print_info("Testing personalization caching...")

        # First request (cache miss)
        start_time = datetime.now()
        recommendations1 = await adaptive_engine.generate_personalized_content(
            student_profile
        )
        first_duration = (datetime.now() - start_time).total_seconds()

        # Check cache
        cache_key = f"personalized_content_{student_id}"
        assert cache_key in adaptive_engine.personalization_cache, "Cache not populated"

        cached_data = adaptive_engine.personalization_cache[cache_key]
        assert "recommendations" in cached_data, "Missing recommendations in cache"
        assert "generated_at" in cached_data, "Missing timestamp in cache"

        print_success(f"Cache populated successfully (duration: {first_duration:.3f}s)")

        # Test adaptation history tracking
        print_info("Testing adaptation history tracking...")

        if student_id in adaptive_engine.adaptation_history:
            adaptation_history = adaptive_engine.adaptation_history[student_id]
            assert "adaptation" in adaptation_history, "Missing adaptation in history"
            assert "timestamp" in adaptation_history, "Missing timestamp in history"
            print_success("Adaptation history tracked successfully")
        else:
            print_info("No adaptation history yet (expected for fresh test)")

        return {
            "cache_performance": first_duration,
            "cache_populated": len(adaptive_engine.personalization_cache),
            "history_tracked": len(adaptive_engine.adaptation_history),
        }

    except Exception as e:
        print_error(f"Failed performance and caching test: {str(e)}")
        raise


async def run_comprehensive_b5_tests():
    """Run comprehensive B.5 Adaptive Learning Engine test suite"""
    print(
        "\
"
        + "=" * 100
    )
    print("🚀 COMPREHENSIVE B.5 ADAPTIVE LEARNING ENGINE TEST SUITE")
    print("   Per REVISED_PHASE3_PLAN.md B.5 Specifications")
    print("=" * 100)

    test_results = {
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "test_details": {},
    }

    tests = [
        ("Engine Initialization", test_adaptive_learning_engine_initialization),
        ("Personalized Content Generation", test_personalized_content_generation),
        ("Learning Path Optimization", test_learning_path_optimization),
        ("Dynamic Difficulty Adjustment", test_dynamic_difficulty_adjustment),
        ("Real-time Path Adaptation", test_realtime_path_adaptation),
        ("Adaptive Study Plan Generation", test_adaptive_study_plan_generation),
        ("B.4 Integration Validation", test_b4_integration_validation),
        ("Performance and Caching", test_performance_and_caching),
    ]

    adaptive_engine = None

    for test_name, test_func in tests:
        test_results["total_tests"] += 1
        try:
            if test_name == "Engine Initialization":
                adaptive_engine = await test_func()
            elif adaptive_engine:
                await test_func(adaptive_engine)
            else:
                raise Exception("AdaptiveLearningEngine not initialized")

            test_results["passed_tests"] += 1
            test_results["test_details"][test_name] = "PASSED"

        except Exception as e:
            test_results["failed_tests"] += 1
            test_results["test_details"][test_name] = f"FAILED: {str(e)[:100]}"
            logger.error(f"Test '{test_name}' failed: {str(e)}")

    # Print comprehensive test summary
    print(
        "\
"
        + "=" * 100
    )
    print("📋 COMPREHENSIVE TEST RESULTS SUMMARY")
    print("=" * 100)

    print(
        "\
📊 OVERALL STATISTICS:"
    )
    print(f"   Total Tests Run: {test_results['total_tests']}")
    print(f"   Tests Passed: {test_results['passed_tests']} ✅")
    print(f"   Tests Failed: {test_results['failed_tests']} ❌")
    print(
        f"   Success Rate: {(test_results['passed_tests'] / test_results['total_tests'] * 100):.1f}%"
    )

    print(
        "\
📋 DETAILED TEST RESULTS:"
    )
    for test_name, result in test_results["test_details"].items():
        status_icon = "✅" if result == "PASSED" else "❌"
        print(f"   {status_icon} {test_name}: {result}")

    # B.5 Success Criteria Validation
    print(
        "\
🎯 B.5 SUCCESS CRITERIA VALIDATION:"
    )
    success_criteria = [
        (
            "Personalization algorithm implemented",
            "Personalized Content Generation" in test_results["test_details"]
            and test_results["test_details"]["Personalized Content Generation"]
            == "PASSED",
        ),
        (
            "Dynamic difficulty adjustment working",
            "Dynamic Difficulty Adjustment" in test_results["test_details"]
            and test_results["test_details"]["Dynamic Difficulty Adjustment"]
            == "PASSED",
        ),
        (
            "Learning path optimization functional",
            "Learning Path Optimization" in test_results["test_details"]
            and test_results["test_details"]["Learning Path Optimization"] == "PASSED",
        ),
        (
            "Integration with RAGnostic graphs tested",
            "Learning Path Optimization" in test_results["test_details"]
            and test_results["test_details"]["Learning Path Optimization"] == "PASSED",
        ),
        (
            "Performance metrics tracked",
            "Performance and Caching" in test_results["test_details"]
            and test_results["test_details"]["Performance and Caching"] == "PASSED",
        ),
    ]

    criteria_met = 0
    for criteria, met in success_criteria:
        status_icon = "✅" if met else "❌"
        print(f"   {status_icon} {criteria}")
        if met:
            criteria_met += 1

    print(f"\
🏆 B.5 SUCCESS CRITERIA: {criteria_met}/{len(success_criteria)} MET ({criteria_met/len(success_criteria)*100:.1f}%)")

    if test_results["failed_tests"] == 0 and criteria_met == len(success_criteria):
        print(
            "\
🎉 B.5 ADAPTIVE LEARNING ENGINE IMPLEMENTATION: ✅ COMPLETE"
        )
        print("   All tests passed and success criteria met per REVISED_PHASE3_PLAN.md")
    else:
        print(
            "\
⚠️  B.5 IMPLEMENTATION STATUS: NEEDS ATTENTION"
        )
        print(
            f"   Failed tests: {test_results['failed_tests']}, Unmet criteria: {len(success_criteria) - criteria_met}"
        )

    return test_results


if __name__ == "__main__":
    # Run comprehensive B.5 test suite
    results = asyncio.run(run_comprehensive_b5_tests())
