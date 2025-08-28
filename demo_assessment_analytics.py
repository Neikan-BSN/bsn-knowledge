#!/usr/bin/env python3
"""
Demonstration script for BSN Knowledge Assessment & Analytics Systems
Shows the implemented AACN competency framework and learning analytics
"""

import asyncio
from datetime import datetime
import logging
import sys

# Add src to path for imports
sys.path.insert(0, "src")

from src.models.assessment_models import (
    AACNDomain,
    CompetencyProficiencyLevel,
)
from src.assessment.competency_framework import AACNCompetencyFramework
from src.services.analytics_service import AnalyticsService
from src.services.ragnostic_client import RAGnosticClient

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    """Demonstrate assessment and analytics functionality"""

    print("🎓 BSN Knowledge - Assessment & Analytics Systems Demo")
    print("=" * 60)

    # Initialize services
    print("\n📚 Initializing Services...")
    ragnostic_client = RAGnosticClient("http://localhost:8000")
    competency_framework = AACNCompetencyFramework(ragnostic_client)
    analytics_service = AnalyticsService(ragnostic_client)

    # Demo 1: AACN Competency Framework
    print("\n🏥 AACN Competency Framework Demonstration")
    print("-" * 50)

    # Show available competencies
    competencies = competency_framework.get_all_competencies()
    print(f"✅ Loaded {len(competencies)} AACN competencies")

    for domain in AACNDomain:
        domain_competencies = competency_framework.get_competencies_by_domain(domain)
        print(
            f"   • {domain.value.replace('_', ' ').title()}: {len(domain_competencies)} competencies"
        )

    # Demo specific competency
    demo_competency = competency_framework.get_competency_by_id("aacn_1_1")
    if demo_competency:
        print(f"\n📋 Sample Competency: {demo_competency.name}")
        print(f"   Domain: {demo_competency.domain.value.replace('_', ' ').title()}")
        print(f"   Description: {demo_competency.description}")
        print(f"   Learning Outcomes: {len(demo_competency.learning_outcomes)}")
        print(f"   Assessment Methods: {', '.join(demo_competency.assessment_methods)}")

    # Demo 2: Competency Assessment
    print("\n🎯 Competency Assessment Demonstration")
    print("-" * 50)

    # Sample student performance data
    sample_performance_data = {
        "assessment_scores": [85, 78, 92, 88],
        "clinical_scores": [90, 85, 87],
        "simulation_scores": [82, 89],
        "self_assessment": 80,
        "artifacts": ["Care plan submission", "Clinical reflection"],
        "observations": [
            "Strong patient communication",
            "Needs improvement in medication calculations",
        ],
    }

    try:
        # Perform competency assessment
        assessment_result = await competency_framework.assess_competency(
            student_id="demo_student_001",
            competency_id="aacn_1_1",
            performance_data=sample_performance_data,
            assessment_id=f"demo_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )

        print("✅ Assessment completed for student demo_student_001")
        print(f"   Competency: {assessment_result.competency_id}")
        print(f"   Current Level: {assessment_result.current_level.value.title()}")
        print(f"   Proficiency Score: {assessment_result.proficiency_score:.1f}%")
        print(f"   Confidence Score: {assessment_result.confidence_score:.2f}")
        print(f"   Evidence Items: {len(assessment_result.evidence_items)}")

        if assessment_result.strengths:
            print(f"   Strengths: {', '.join(assessment_result.strengths[:2])}")

        if assessment_result.improvement_areas:
            print(
                f"   Improvement Areas: {', '.join(assessment_result.improvement_areas[:2])}"
            )

        print(
            f"   Next Assessment Due: {assessment_result.next_assessment_due.strftime('%Y-%m-%d') if assessment_result.next_assessment_due else 'Not scheduled'}"
        )

    except Exception as e:
        print(f"⚠️ Assessment demo failed: {str(e)}")

    # Demo 3: Gap Analysis
    print("\n🔍 Competency Gap Analysis Demonstration")
    print("-" * 50)

    try:
        target_competencies = ["aacn_1_1", "aacn_2_1", "aacn_3_1"]
        gaps_by_domain = await competency_framework.get_competency_gaps(
            student_id="demo_student_001", target_competencies=target_competencies
        )

        total_gaps = sum(len(gaps) for gaps in gaps_by_domain.values())
        print(
            f"✅ Gap analysis completed: {total_gaps} gaps identified across {len(gaps_by_domain)} domains"
        )

        for domain, gaps in gaps_by_domain.items():
            if gaps:
                print(f"   • {domain.replace('_', ' ').title()}: {len(gaps)} gaps")
                for gap in gaps[:2]:  # Show first 2 gaps
                    print(f"     - {gap.description} (Severity: {gap.severity})")
                    print(
                        f"       Remediation Time: {gap.estimated_remediation_time} hours"
                    )

    except Exception as e:
        print(f"⚠️ Gap analysis demo failed: {str(e)}")

    # Demo 4: Learning Path Recommendation
    print("\n🛤️ Learning Path Recommendation Demonstration")
    print("-" * 50)

    try:
        target_competencies = ["aacn_1_1", "aacn_2_1"]
        current_proficiency = {"aacn_1_1": 65.0, "aacn_2_1": 72.0}

        learning_path = await competency_framework.recommend_learning_path(
            student_id="demo_student_001",
            target_competencies=target_competencies,
            current_proficiency=current_proficiency,
        )

        print("✅ Learning path generated")
        print(f"   Target Competencies: {len(learning_path.target_competencies)}")
        print(f"   Estimated Duration: {learning_path.estimated_duration_hours} hours")
        print(f"   Success Probability: {learning_path.success_probability:.1%}")
        print(
            f"   Learning Sequence: {len(learning_path.recommended_sequence)} activities"
        )

        # Show first few learning activities
        for i, activity in enumerate(learning_path.recommended_sequence[:3]):
            print(
                f"   Activity {i+1}: {activity.get('competency_name', 'Learning Activity')}"
            )
            print(f"     - Current Level: {activity.get('current_level', 'Unknown')}")
            print(f"     - Target Level: {activity.get('target_level', 'Unknown')}")
            print(f"     - Estimated Hours: {activity.get('estimated_hours', 0)}")

        if len(learning_path.recommended_sequence) > 3:
            print(
                f"   ... and {len(learning_path.recommended_sequence) - 3} more activities"
            )

    except Exception as e:
        print(f"⚠️ Learning path demo failed: {str(e)}")

    # Demo 5: Student Analytics
    print("\n📊 Student Analytics Demonstration")
    print("-" * 50)

    try:
        # Get student progress metrics
        progress_metrics = await analytics_service.get_student_progress(
            "demo_student_001"
        )

        print("✅ Progress analysis completed")
        print(f"   Time Period: {progress_metrics.time_period}")
        print(f"   Study Time: {progress_metrics.total_study_time_minutes} minutes")
        print(f"   Assessments Completed: {progress_metrics.assessments_completed}")
        print(f"   Average Score: {progress_metrics.average_score:.1f}%")
        print(f"   Improvement Rate: {progress_metrics.improvement_rate:.1f}%")
        print(f"   Engagement Score: {progress_metrics.engagement_score:.1f}/100")
        print(f"   Consistency Score: {progress_metrics.consistency_score:.1f}/100")
        print(
            f"   Learning Velocity: {progress_metrics.learning_velocity:.1f} objectives/week"
        )
        print(f"   Difficulty Preference: {progress_metrics.difficulty_preference}")

        if progress_metrics.risk_factors:
            print(f"   Risk Factors: {', '.join(progress_metrics.risk_factors[:2])}")

        if progress_metrics.success_factors:
            print(
                f"   Success Factors: {', '.join(progress_metrics.success_factors[:2])}"
            )

    except Exception as e:
        print(f"⚠️ Analytics demo failed: {str(e)}")

    # Demo 6: Learning Insights
    print("\n💡 Learning Insights Demonstration")
    print("-" * 50)

    try:
        insights = await analytics_service.get_learning_insights("demo_student_001")

        print("✅ Learning insights generated")
        print(
            f"   Overall Competency Score: {insights.get('overall_competency_score', 0):.1f}"
        )
        print(
            f"   Graduation Readiness: {insights.get('graduation_readiness', 0):.1f}%"
        )

        learning_style = insights.get("learning_style", {})
        if learning_style:
            print(
                f"   Learning Style: {learning_style.get('primary', 'Unknown')} (Confidence: {learning_style.get('confidence', 0):.1%})"
            )

        advancement = insights.get("advancement_readiness", {})
        if advancement:
            print(
                f"   Advancement Readiness: {advancement.get('overall_readiness', 0):.1%}"
            )

        recommendations = insights.get("personalized_recommendations", [])
        if recommendations:
            print("   Personalized Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"     {i}. {rec}")

    except Exception as e:
        print(f"⚠️ Learning insights demo failed: {str(e)}")

    # Demo 7: Performance Prediction
    print("\n🔮 Performance Prediction Demonstration")
    print("-" * 50)

    try:
        prediction = await analytics_service.predict_performance(
            student_id="demo_student_001", target_assessment="nclex_practice_exam"
        )

        print("✅ Performance prediction completed")
        print(f"   Target Assessment: {prediction.get('target_assessment', 'Unknown')}")
        print(f"   Predicted Score: {prediction.get('predicted_score', 0):.1f}%")
        print(f"   Success Probability: {prediction.get('success_probability', 0):.1%}")

        confidence_interval = prediction.get("confidence_interval", {})
        if confidence_interval:
            margin = confidence_interval.get("margin", 0)
            print(f"   Confidence Interval: ±{margin:.1f}%")

        model_confidence = prediction.get("model_confidence", 0)
        print(f"   Model Confidence: {model_confidence:.1%}")

        risk_factors = prediction.get("risk_factors", [])
        if risk_factors:
            print(f"   Risk Factors: {', '.join(risk_factors[:2])}")

        prep_recommendations = prediction.get("preparation_recommendations", [])
        if prep_recommendations:
            print("   Preparation Recommendations:")
            for i, rec in enumerate(prep_recommendations[:3], 1):
                print(f"     {i}. {rec}")

    except Exception as e:
        print(f"⚠️ Performance prediction demo failed: {str(e)}")

    # Demo 8: Proficiency Levels
    print("\n📈 Proficiency Levels & Standards")
    print("-" * 50)

    print("AACN Proficiency Levels:")
    for level in CompetencyProficiencyLevel:
        threshold = competency_framework.proficiency_thresholds[level] * 100
        print(
            f"   • {level.value.replace('_', ' ').title()}: {threshold:.0f}% and above"
        )

    # Summary
    print("\n🎯 Summary")
    print("-" * 50)
    print("✅ AACN Competency Framework: Fully implemented with 8+ competencies")
    print("✅ Competency Assessment: RAGnostic-enhanced analysis and recommendations")
    print("✅ Gap Analysis: Targeted remediation planning with time estimates")
    print("✅ Learning Paths: Personalized, sequenced learning recommendations")
    print("✅ Student Analytics: Comprehensive progress and engagement metrics")
    print("✅ Predictive Analytics: Performance forecasting with confidence intervals")
    print("✅ Learning Insights: AI-driven personalized learning recommendations")
    print(
        "✅ Institutional Reporting: Support for accreditation and effectiveness metrics"
    )

    print("\n🚀 BSN Knowledge Assessment & Analytics Systems are ready for deployment!")
    print("\nAPI Endpoints Available:")
    print(
        "   • POST /api/v1/assessment/competency/assess - Individual competency assessment"
    )
    print(
        "   • POST /api/v1/assessment/competency/assess/bulk - Bulk competency assessment"
    )
    print("   • POST /api/v1/assessment/gaps/analyze - Competency gap analysis")
    print(
        "   • POST /api/v1/assessment/learning-path/generate - Learning path generation"
    )
    print(
        "   • GET  /api/v1/analytics/student/{id}/progress - Student progress metrics"
    )
    print("   • GET  /api/v1/analytics/student/{id}/insights - Learning insights")
    print(
        "   • POST /api/v1/analytics/student/{id}/predict-performance - Performance prediction"
    )
    print("   • POST /api/v1/analytics/institutional/report - Institutional reporting")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback

        traceback.print_exc()
