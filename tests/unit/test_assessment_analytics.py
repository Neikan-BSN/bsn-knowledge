"""
Unit tests for assessment and analytics functionality
Tests the AACN competency framework and learning analytics services
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from src.models.assessment_models import (
    AACNDomain,
    CompetencyProficiencyLevel,
    CompetencyAssessmentResult,
    StudentProgressMetrics,
    KnowledgeGap,
    LearningPathRecommendation
)
from src.assessment.competency_framework import AACNCompetencyFramework
from src.services.analytics_service import AnalyticsService
from src.services.ragnostic_client import RAGnosticClient


@pytest.fixture
def mock_ragnostic_client():
    """Mock RAGnostic client for testing"""
    client = AsyncMock(spec=RAGnosticClient)
    
    # Mock search responses
    client.search_content.return_value = {
        "items": [
            {
                "content": "Test content for competency analysis",
                "metadata": {
                    "title": "Clinical Reasoning Module",
                    "skill_area": "clinical_reasoning",
                    "resource_type": "module"
                }
            }
        ]
    }
    
    # Mock content retrieval
    client.get_content_by_metadata.return_value = {
        "items": [
            {
                "metadata": {
                    "title": "Pathophysiology Study Guide",
                    "resource_type": "study_guide",
                    "difficulty_level": "intermediate"
                }
            }
        ]
    }
    
    return client


@pytest.fixture
def competency_framework(mock_ragnostic_client):
    """AACN competency framework instance for testing"""
    return AACNCompetencyFramework(mock_ragnostic_client)


@pytest.fixture
def analytics_service(mock_ragnostic_client):
    """Analytics service instance for testing"""
    return AnalyticsService(mock_ragnostic_client, db_connection=None)


@pytest.fixture
def sample_performance_data():
    """Sample performance data for testing"""
    return {
        "assessment_scores": [85, 78, 92, 88],
        "clinical_scores": [90, 85, 87],
        "simulation_scores": [82, 89],
        "self_assessment": 80,
        "artifacts": ["Care plan submission", "Clinical reflection"],
        "observations": ["Strong patient communication", "Needs improvement in medication calculations"]
    }


class TestAACNCompetencyFramework:
    """Test cases for AACN Competency Framework"""
    
    def test_framework_initialization(self, competency_framework):
        """Test that framework initializes with AACN competencies"""
        competencies = competency_framework.get_all_competencies()
        
        # Should have at least 8 competencies (one per domain)
        assert len(competencies) >= 8
        
        # Check that all AACN domains are represented
        domains_present = {comp.domain for comp in competencies}
        expected_domains = set(AACNDomain)
        assert domains_present == expected_domains
    
    def test_get_competencies_by_domain(self, competency_framework):
        """Test filtering competencies by domain"""
        domain = AACNDomain.KNOWLEDGE_FOR_NURSING_PRACTICE
        competencies = competency_framework.get_competencies_by_domain(domain)
        
        assert len(competencies) >= 1
        for comp in competencies:
            assert comp.domain == domain
    
    def test_get_competency_by_id(self, competency_framework):
        """Test retrieving specific competency by ID"""
        competency = competency_framework.get_competency_by_id("aacn_1_1")
        
        assert competency is not None
        assert competency.id == "aacn_1_1"
        assert competency.domain == AACNDomain.KNOWLEDGE_FOR_NURSING_PRACTICE
    
    @pytest.mark.asyncio
    async def test_assess_competency(self, competency_framework, sample_performance_data):
        """Test competency assessment functionality"""
        student_id = "student_123"
        competency_id = "aacn_1_1"
        assessment_id = "assessment_001"
        
        result = await competency_framework.assess_competency(
            student_id=student_id,
            competency_id=competency_id,
            performance_data=sample_performance_data,
            assessment_id=assessment_id
        )
        
        assert isinstance(result, CompetencyAssessmentResult)
        assert result.student_id == student_id
        assert result.competency_id == competency_id
        assert result.assessment_id == assessment_id
        assert 0 <= result.proficiency_score <= 100
        assert result.current_level in CompetencyProficiencyLevel
        assert len(result.evidence_items) > 0
        assert result.confidence_score > 0
    
    @pytest.mark.asyncio
    async def test_assess_competency_invalid_id(self, competency_framework, sample_performance_data):
        """Test assessment with invalid competency ID"""
        with pytest.raises(ValueError):
            await competency_framework.assess_competency(
                student_id="student_123",
                competency_id="invalid_competency",
                performance_data=sample_performance_data,
                assessment_id="assessment_001"
            )
    
    @pytest.mark.asyncio
    async def test_competency_gap_analysis(self, competency_framework):
        """Test competency gap analysis"""
        student_id = "student_123"
        target_competencies = ["aacn_1_1", "aacn_2_1"]
        
        gaps = await competency_framework.get_competency_gaps(
            student_id=student_id,
            target_competencies=target_competencies
        )
        
        assert isinstance(gaps, dict)
        # Should have gaps for domains where competencies exist
        for domain_gaps in gaps.values():
            for gap in domain_gaps:
                assert isinstance(gap, KnowledgeGap)
                assert gap.student_id == student_id
                assert gap.severity in ["low", "medium", "high", "critical"]
    
    @pytest.mark.asyncio
    async def test_learning_path_recommendation(self, competency_framework):
        """Test learning path generation"""
        student_id = "student_123"
        target_competencies = ["aacn_1_1", "aacn_2_1"]
        current_proficiency = {"aacn_1_1": 65.0, "aacn_2_1": 70.0}
        
        path = await competency_framework.recommend_learning_path(
            student_id=student_id,
            target_competencies=target_competencies,
            current_proficiency=current_proficiency
        )
        
        assert isinstance(path, LearningPathRecommendation)
        assert path.student_id == student_id
        assert path.target_competencies == target_competencies
        assert path.estimated_duration_hours > 0
        assert len(path.recommended_sequence) > 0
        assert 0 <= path.success_probability <= 1.0
    
    def test_proficiency_level_determination(self, competency_framework):
        """Test proficiency level calculation"""
        # Test various scores
        test_cases = [
            (20, CompetencyProficiencyLevel.NOVICE),
            (45, CompetencyProficiencyLevel.ADVANCED_BEGINNER),
            (65, CompetencyProficiencyLevel.COMPETENT),
            (85, CompetencyProficiencyLevel.PROFICIENT),
            (95, CompetencyProficiencyLevel.EXPERT)
        ]
        
        for score, expected_level in test_cases:
            level = competency_framework._determine_proficiency_level(score)
            assert level == expected_level
    
    def test_confidence_score_calculation(self, competency_framework, sample_performance_data):
        """Test confidence score calculation"""
        evidence_items = ["Assessment score: 85%", "Clinical evaluation: 88%"]
        
        confidence = competency_framework._calculate_confidence_score(
            sample_performance_data, evidence_items
        )
        
        assert 0 <= confidence <= 1.0
        # More data should result in higher confidence
        assert confidence > 0.3  # Should have decent confidence with sample data


class TestAnalyticsService:
    """Test cases for Analytics Service"""
    
    @pytest.mark.asyncio
    async def test_get_student_progress(self, analytics_service):
        """Test student progress metrics calculation"""
        student_id = "student_123"
        time_period = "semester_2024_1"
        
        progress = await analytics_service.get_student_progress(
            student_id=student_id,
            time_period=time_period
        )
        
        assert isinstance(progress, StudentProgressMetrics)
        assert progress.student_id == student_id
        assert progress.time_period == time_period
        assert progress.total_study_time_minutes >= 0
        assert progress.assessments_completed >= 0
        assert 0 <= progress.average_score <= 100
        assert 0 <= progress.engagement_score <= 100
        assert 0 <= progress.consistency_score <= 100
        assert progress.difficulty_preference in ["easy", "balanced", "challenging"]
    
    @pytest.mark.asyncio
    async def test_get_learning_insights(self, analytics_service):
        """Test learning insights generation"""
        student_id = "student_123"
        
        insights = await analytics_service.get_learning_insights(student_id)
        
        assert isinstance(insights, dict)
        assert insights["student_id"] == student_id
        assert "competency_strengths" in insights
        assert "development_areas" in insights
        assert "personalized_recommendations" in insights
        assert "learning_style" in insights
        assert "advancement_readiness" in insights
        assert "generated_at" in insights
    
    @pytest.mark.asyncio
    async def test_content_performance_analysis(self, analytics_service):
        """Test content performance analysis"""
        content_id = "content_123"
        time_period = "month"
        
        performance = await analytics_service.get_content_performance(
            content_id=content_id,
            time_period=time_period
        )
        
        assert isinstance(performance, dict)
        assert performance["content_id"] == content_id
        assert performance["time_period"] == time_period
        assert "engagement_metrics" in performance
        assert "learning_impact" in performance
    
    @pytest.mark.asyncio
    async def test_quiz_analytics(self, analytics_service):
        """Test quiz analytics generation"""
        quiz_id = "quiz_123"
        
        analytics = await analytics_service.get_quiz_analytics(quiz_id)
        
        assert isinstance(analytics, dict)
        assert analytics["quiz_id"] == quiz_id
        assert "basic_statistics" in analytics
        assert "analyzed_at" in analytics
    
    @pytest.mark.asyncio
    async def test_cohort_comparison(self, analytics_service):
        """Test cohort comparison analysis"""
        student_id = "student_123"
        comparison_group = "year"
        
        comparison = await analytics_service.get_cohort_comparison(
            student_id=student_id,
            comparison_group=comparison_group
        )
        
        assert isinstance(comparison, dict)
        assert comparison["student_id"] == student_id
        assert comparison["comparison_group"] == comparison_group
        assert "cohort_size" in comparison
        assert "student_percentiles" in comparison
        assert "generated_at" in comparison
    
    @pytest.mark.asyncio
    async def test_performance_prediction(self, analytics_service):
        """Test performance prediction functionality"""
        student_id = "student_123"
        target_assessment = "final_exam"
        
        prediction = await analytics_service.predict_performance(
            student_id=student_id,
            target_assessment=target_assessment
        )
        
        assert isinstance(prediction, dict)
        assert prediction["student_id"] == student_id
        assert prediction["target_assessment"] == target_assessment
        assert 0 <= prediction["predicted_score"] <= 100
        assert "confidence_interval" in prediction
        assert "success_probability" in prediction
        assert "predicted_at" in prediction
    
    @pytest.mark.asyncio
    async def test_engagement_tracking(self, analytics_service):
        """Test engagement metrics tracking"""
        student_id = "student_123"
        activity_data = {
            "activity_type": "quiz_attempt",
            "timestamp": datetime.now(),
            "duration_minutes": 30,
            "score": 85
        }
        
        # Should not raise exception
        await analytics_service.track_engagement_metrics(
            student_id=student_id,
            activity_data=activity_data
        )
        
        # Verify data is cached
        cache_key = f"engagement_{student_id}"
        assert cache_key in analytics_service._cache
        assert len(analytics_service._cache[cache_key]) == 1
    
    @pytest.mark.asyncio
    async def test_learning_report_generation(self, analytics_service):
        """Test comprehensive learning report generation"""
        student_id = "student_123"
        report_type = "comprehensive"
        
        report = await analytics_service.generate_learning_report(
            student_id=student_id,
            report_type=report_type
        )
        
        assert isinstance(report, dict)
        assert report["student_id"] == student_id
        assert report["report_type"] == report_type
        assert "generated_at" in report
        assert "executive_summary" in report
        
        # Comprehensive report should include all sections
        if report_type == "comprehensive":
            assert "progress_metrics" in report
            assert "competency_profile" in report
            assert "performance_predictions" in report
    
    def test_engagement_score_calculation(self, analytics_service):
        """Test engagement score calculation logic"""
        # Test with various activity patterns
        high_engagement_data = [
            {"type": "study", "duration_minutes": 90},
            {"type": "quiz", "duration_minutes": 30},
            {"type": "simulation", "duration_minutes": 60},
            {"type": "reading", "duration_minutes": 45}
        ] * 10  # 40 total activities
        
        low_engagement_data = [
            {"type": "study", "duration_minutes": 15}
        ] * 2  # 2 activities
        
        # Test high engagement
        high_score = analytics_service._calculate_engagement_score(high_engagement_data)
        assert 80 <= high_score <= 100
        
        # Test low engagement
        low_score = analytics_service._calculate_engagement_score(low_engagement_data)
        assert low_score < 50
        
        # Empty data should return 0
        empty_score = analytics_service._calculate_engagement_score([])
        assert empty_score == 0
    
    def test_consistency_score_calculation(self, analytics_service):
        """Test study consistency score calculation"""
        # Consistent study pattern
        consistent_data = []
        for i in range(10):
            consistent_data.append({
                "timestamp": datetime.now() - timedelta(days=i),
                "duration_minutes": 60  # Same duration each day
            })
        
        # Inconsistent study pattern
        inconsistent_data = []
        durations = [10, 180, 5, 120, 15, 200, 8, 150]
        for i, duration in enumerate(durations):
            inconsistent_data.append({
                "timestamp": datetime.now() - timedelta(days=i),
                "duration_minutes": duration
            })
        
        # Consistent should score higher
        consistent_score = analytics_service._calculate_consistency_score(
            consistent_data, "current"
        )
        inconsistent_score = analytics_service._calculate_consistency_score(
            inconsistent_data, "current"
        )
        
        assert consistent_score > inconsistent_score
        assert 0 <= consistent_score <= 100
        assert 0 <= inconsistent_score <= 100
    
    def test_difficulty_preference_analysis(self, analytics_service):
        """Test difficulty preference analysis"""
        # Test easy preference
        easy_data = [{"difficulty_rating": 2}, {"difficulty_rating": 1.5}, {"difficulty_rating": 2.5}]
        easy_pref = analytics_service._analyze_difficulty_preference(easy_data)
        assert easy_pref == "easy"
        
        # Test challenging preference
        hard_data = [{"difficulty_rating": 4}, {"difficulty_rating": 4.5}, {"difficulty_rating": 3.8}]
        hard_pref = analytics_service._analyze_difficulty_preference(hard_data)
        assert hard_pref == "challenging"
        
        # Test balanced preference
        balanced_data = [{"difficulty_rating": 3}, {"difficulty_rating": 3.2}, {"difficulty_rating": 2.8}]
        balanced_pref = analytics_service._analyze_difficulty_preference(balanced_data)
        assert balanced_pref == "balanced"
        
        # Test no data
        no_data_pref = analytics_service._analyze_difficulty_preference([])
        assert no_data_pref == "balanced"


class TestPerformanceMetrics:
    """Test performance calculation methods"""
    
    def test_proficiency_score_calculation(self, competency_framework, sample_performance_data):
        """Test weighted proficiency score calculation"""
        competency = competency_framework.get_competency_by_id("aacn_1_1")
        
        score = competency_framework._calculate_proficiency_score(
            sample_performance_data, competency
        )
        
        assert 0 <= score <= 100
        # Should be weighted average, so between min and max of input scores
        all_scores = (
            sample_performance_data["assessment_scores"] +
            sample_performance_data["clinical_scores"] +
            sample_performance_data["simulation_scores"] +
            [sample_performance_data["self_assessment"]]
        )
        min_score = min(all_scores)
        max_score = max(all_scores)
        assert min_score <= score <= max_score
    
    def test_gap_severity_calculation(self, competency_framework):
        """Test competency gap severity calculation"""
        # Test different gap sizes
        assert competency_framework._calculate_gap_severity(40, 70) == "high"  # 30 point gap
        assert competency_framework._calculate_gap_severity(55, 70) == "medium"  # 15 point gap
        assert competency_framework._calculate_gap_severity(65, 70) == "low"  # 5 point gap
        assert competency_framework._calculate_gap_severity(30, 70) == "critical"  # 40 point gap
    
    def test_remediation_time_estimation(self, competency_framework):
        """Test remediation time estimation"""
        # Larger gaps should require more time
        time_large_gap = competency_framework._estimate_remediation_time(40, 80)  # 40 point gap
        time_small_gap = competency_framework._estimate_remediation_time(70, 80)  # 10 point gap
        
        assert time_large_gap > time_small_gap
        assert time_large_gap >= 5  # Minimum time
        assert time_small_gap >= 5  # Minimum time


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    @pytest.mark.asyncio
    async def test_ragnostic_client_failure(self, mock_ragnostic_client, competency_framework):
        """Test handling of RAGnostic client failures"""
        # Mock RAGnostic failure
        mock_ragnostic_client.search_content.side_effect = Exception("RAGnostic unavailable")
        
        # Assessment should still work with fallback logic
        result = await competency_framework.assess_competency(
            student_id="student_123",
            competency_id="aacn_1_1",
            performance_data={"assessment_scores": [80]},
            assessment_id="test_001"
        )
        
        assert isinstance(result, CompetencyAssessmentResult)
        # Should have fallback recommendations
        assert len(result.recommended_resources) > 0
    
    @pytest.mark.asyncio
    async def test_empty_performance_data(self, competency_framework):
        """Test handling of empty performance data"""
        result = await competency_framework.assess_competency(
            student_id="student_123",
            competency_id="aacn_1_1",
            performance_data={},  # Empty data
            assessment_id="test_001"
        )
        
        assert isinstance(result, CompetencyAssessmentResult)
        assert result.proficiency_score == 0.0
        assert result.current_level == CompetencyProficiencyLevel.NOVICE
    
    def test_invalid_input_validation(self, analytics_service):
        """Test validation of invalid inputs"""
        # Test engagement tracking with incomplete data
        incomplete_data = {"activity_type": "study"}  # Missing required fields
        
        # Should handle gracefully without raising exception
        import asyncio
        try:
            asyncio.run(analytics_service.track_engagement_metrics("student_123", incomplete_data))
        except Exception:
            pytest.fail("Should handle incomplete engagement data gracefully")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])