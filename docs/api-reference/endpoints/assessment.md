# Assessment & Competency Endpoints

Comprehensive nursing competency assessment using the AACN Essentials framework with detailed analytics, gap identification, and personalized learning recommendations.

## Overview

The assessment endpoints provide robust competency evaluation aligned with the **American Association of Colleges of Nursing (AACN) Essentials**, enabling detailed tracking of student progress across all eight nursing domains.

**Base Path:** `/api/v1/assessment`

**Rate Limit:** 200 requests per hour (assessment tier)

## AACN Essentials Framework

The assessment system is built around the eight AACN Essential domains:

1. **Knowledge for Nursing Practice** - Foundational nursing and scientific knowledge
2. **Person-Centered Care** - Holistic, culturally responsive nursing care
3. **Population Health** - Community and population-focused care
4. **Scholarship for Nursing Discipline** - Evidence-based practice and research
5. **Information Technology** - Healthcare informatics and technology
6. **Healthcare Systems** - Navigation and leadership within healthcare systems
7. **Interprofessional Partnerships** - Collaborative healthcare teamwork
8. **Personal Professional Development** - Lifelong learning and professional growth

## Endpoints

### Assess Student Competency

Evaluate student performance against specific AACN competencies.

```http
POST /api/v1/assessment/competency
```

**Authentication:** Required (Student for own assessments, Instructor/Admin for any)

#### Request Body

```json
{
  "student_id": "student_12345",
  "competency_id": "aacn_domain_2_comp_1",
  "performance_data": {
    "quiz_scores": [85, 92, 78],
    "clinical_evaluation": {
      "communication_skills": 4.2,
      "critical_thinking": 3.8,
      "patient_care": 4.0,
      "professionalism": 4.5
    },
    "simulation_results": {
      "scenario_completion": true,
      "time_to_completion": 18.5,
      "safety_score": 95,
      "decision_accuracy": 88
    },
    "case_study_scores": [90, 85, 92],
    "peer_evaluations": {
      "teamwork": 4.3,
      "leadership": 3.9,
      "communication": 4.1
    }
  },
  "assessment_type": "comprehensive",
  "assessor_id": "instructor_001"
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `student_id` | string | Yes | Unique student identifier |
| `competency_id` | string | Yes | AACN competency identifier |
| `performance_data` | object | Yes | Assessment results and evaluation data |
| `assessment_type` | string | No | Type of assessment (default: comprehensive) |
| `assessor_id` | string | No | Evaluator identifier (default: system) |

#### Assessment Types

- `comprehensive` - Full competency evaluation using multiple data sources
- `quiz_based` - Assessment based primarily on quiz/test performance
- `clinical_only` - Clinical skills and simulation-based assessment
- `peer_review` - Peer evaluation and 360-degree feedback
- `self_assessment` - Student self-evaluation component

#### Response

```json
{
  "assessment_id": "assessment_20240824_001",
  "student_id": "student_12345",
  "competency_id": "aacn_domain_2_comp_1",
  "competency_name": "Person-Centered Care - Therapeutic Communication",
  "current_level": "competent",
  "previous_level": "advanced_beginner",
  "proficiency_score": 78.5,
  "assessment_details": {
    "strengths": [
      "Demonstrates excellent active listening skills",
      "Shows cultural sensitivity in patient interactions",
      "Effectively uses therapeutic communication techniques"
    ],
    "areas_for_improvement": [
      "Needs to improve handling of difficult conversations",
      "Could enhance family communication strategies",
      "Should develop advanced de-escalation techniques"
    ],
    "specific_feedback": {
      "clinical_skills": {
        "score": 4.0,
        "feedback": "Shows strong foundational skills in patient communication"
      },
      "knowledge_application": {
        "score": 3.8,
        "feedback": "Good understanding of communication theory with room for practical application"
      },
      "professional_behavior": {
        "score": 4.5,
        "feedback": "Consistently demonstrates professional communication standards"
      }
    }
  },
  "learning_recommendations": [
    {
      "priority": "high",
      "type": "skill_development",
      "description": "Practice difficult conversation scenarios",
      "resources": [
        "Difficult Conversations in Healthcare module",
        "Communication simulation lab sessions"
      ],
      "estimated_time_hours": 8
    },
    {
      "priority": "medium",
      "type": "knowledge_building",
      "description": "Study family-centered communication approaches",
      "resources": [
        "Family Communication in Healthcare textbook chapters 3-5",
        "Online module: Family Dynamics in Care"
      ],
      "estimated_time_hours": 4
    }
  ],
  "competency_progression": {
    "current_semester": 3,
    "expected_level_for_semester": "competent",
    "on_track_for_graduation": true,
    "projected_final_level": "proficient",
    "areas_needing_attention": [
      "Advanced communication techniques",
      "Crisis communication skills"
    ]
  },
  "benchmark_comparison": {
    "peer_average": 75.2,
    "class_percentile": 68,
    "program_average": 76.8,
    "national_average": 74.5
  },
  "metadata": {
    "assessment_date": "2024-08-24T10:00:00Z",
    "assessor_id": "instructor_001",
    "assessment_duration_minutes": 45,
    "ai_analysis_confidence": 0.92
  }
}
```

#### cURL Example

```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/assessment/competency \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "student_id": "student_12345",
    "competency_id": "aacn_domain_1_comp_2",
    "performance_data": {
      "quiz_scores": [88, 91, 85],
      "clinical_evaluation": {
        "critical_thinking": 4.1,
        "patient_safety": 4.3,
        "evidence_application": 3.9
      }
    },
    "assessment_type": "comprehensive"
  }'
```

### Bulk Competency Assessment

Assess multiple competencies in a single batch request for efficient processing.

```http
POST /api/v1/assessment/competency/assess/bulk
```

#### Request Body

```json
{
  "assessments": [
    {
      "student_id": "student_12345",
      "competency_id": "aacn_domain_1_comp_1",
      "performance_data": { /* assessment data */ },
      "assessor_id": "instructor_001"
    },
    {
      "student_id": "student_12345",
      "competency_id": "aacn_domain_1_comp_2",
      "performance_data": { /* assessment data */ },
      "assessor_id": "instructor_001"
    }
  ],
  "batch_id": "semester_3_midterm_2024"
}
```

#### Response

```json
{
  "batch_id": "semester_3_midterm_2024",
  "total_assessments": 15,
  "successful_assessments": 14,
  "failed_assessments": 1,
  "results": [
    {
      "assessment_id": "assessment_001",
      "student_id": "student_12345",
      "competency_id": "aacn_domain_1_comp_1",
      "current_level": "proficient",
      "proficiency_score": 85.2
    }
  ],
  "errors": [
    {
      "index": 12,
      "student_id": "student_67890",
      "competency_id": "aacn_domain_3_comp_2",
      "error": "Insufficient performance data for assessment"
    }
  ],
  "processed_at": "2024-08-24T10:00:00Z"
}
```

### Get Student Competency Profile

Retrieve comprehensive competency profile for a student.

```http
GET /api/v1/assessment/competency/profile/{student_id}
```

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_historical` | boolean | false | Include historical assessment data |

#### Response

```json
{
  "student_id": "student_12345",
  "program": "BSN",
  "semester": 3,
  "overall_gpa": 3.4,
  "competency_gpa": 3.2,
  "graduation_readiness_score": 75.0,
  "competency_summary": {
    "total_competencies": 24,
    "assessed_competencies": 18,
    "competencies_met": 15,
    "competencies_in_progress": 3,
    "competencies_needing_attention": 2
  },
  "domain_performance": {
    "knowledge_for_nursing_practice": {
      "average_score": 82.5,
      "proficiency_level": "competent",
      "competencies_completed": 4,
      "competencies_total": 5
    },
    "person_centered_care": {
      "average_score": 78.2,
      "proficiency_level": "competent",
      "competencies_completed": 3,
      "competencies_total": 4
    }
  },
  "strengths_summary": [
    "Strong clinical reasoning in acute care settings",
    "Excellent interprofessional communication skills",
    "Proficient in health assessment techniques",
    "Demonstrates cultural competency consistently"
  ],
  "development_plan": [
    {
      "priority": "high",
      "area": "Pharmacology knowledge for complex medications",
      "target_competency": "aacn_domain_1_comp_3",
      "recommended_actions": [
        "Complete advanced pharmacology module",
        "Practice medication calculation scenarios"
      ],
      "target_completion": "2024-09-30"
    },
    {
      "priority": "medium",
      "area": "Population health assessment skills",
      "target_competency": "aacn_domain_3_comp_2",
      "recommended_actions": [
        "Participate in community health rotation",
        "Complete epidemiology coursework"
      ],
      "target_completion": "2024-10-31"
    }
  ],
  "progression_tracking": {
    "semester_1": { "average_score": 68.5, "level": "advanced_beginner" },
    "semester_2": { "average_score": 74.8, "level": "competent" },
    "semester_3": { "average_score": 78.2, "level": "competent" },
    "projected_graduation": { "estimated_score": 84.0, "level": "proficient" }
  },
  "last_updated": "2024-08-24T10:00:00Z"
}
```

### Analyze Competency Gaps

Identify knowledge and skill gaps across competency domains.

```http
POST /api/v1/assessment/gaps/analyze
```

#### Request Body

```json
{
  "student_id": "student_12345",
  "target_competencies": [
    "aacn_domain_1_comp_1",
    "aacn_domain_2_comp_3",
    "aacn_domain_4_comp_2"
  ],
  "include_prerequisites": true,
  "severity_filter": "high"
}
```

#### Response

```json
{
  "knowledge_for_nursing_practice": [
    {
      "gap_id": "gap_001",
      "competency_id": "aacn_domain_1_comp_2",
      "competency_name": "Pathophysiology Application",
      "severity": "high",
      "current_level": "advanced_beginner",
      "target_level": "competent",
      "gap_score": 15.5,
      "description": "Student demonstrates limited understanding of complex pathophysiological processes",
      "specific_deficiencies": [
        "Cardiovascular system pathophysiology",
        "Endocrine disorder mechanisms",
        "Neurological condition presentations"
      ],
      "impact_on_practice": "May struggle with patient assessment and care planning for complex conditions",
      "remediation_priority": "immediate",
      "estimated_time_to_close": "4-6 weeks"
    }
  ],
  "person_centered_care": [
    {
      "gap_id": "gap_002",
      "competency_id": "aacn_domain_2_comp_1",
      "competency_name": "Cultural Competency",
      "severity": "medium",
      "current_level": "competent",
      "target_level": "proficient",
      "gap_score": 8.2,
      "description": "Good foundation with opportunities for advanced cultural competency",
      "specific_deficiencies": [
        "Working with specific ethnic populations",
        "Advanced cultural assessment techniques"
      ]
    }
  ]
}
```

### Generate Learning Path

Create personalized learning path recommendations based on competency gaps.

```http
POST /api/v1/assessment/learning-path/generate
```

#### Request Body

```json
{
  "student_id": "student_12345",
  "target_competencies": [
    "aacn_domain_1_comp_2",
    "aacn_domain_2_comp_3"
  ],
  "current_proficiency": {
    "aacn_domain_1_comp_2": 2.3,
    "aacn_domain_2_comp_3": 2.8
  },
  "learning_preferences": {
    "preferred_modalities": ["visual", "hands_on"],
    "time_availability_hours_per_week": 10,
    "difficulty_progression": "gradual"
  },
  "timeline_weeks": 8
}
```

#### Response

```json
{
  "learning_path_id": "path_12345_001",
  "student_id": "student_12345",
  "total_competencies": 2,
  "estimated_duration_hours": 32,
  "estimated_completion_weeks": 8,
  "difficulty_progression": "gradual",
  "recommended_sequence": [
    {
      "phase": 1,
      "duration_weeks": 3,
      "focus_competency": "aacn_domain_1_comp_2",
      "learning_activities": [
        {
          "activity_type": "foundation_review",
          "title": "Basic Pathophysiology Concepts",
          "estimated_hours": 4,
          "resources": [
            "Pathophysiology textbook chapters 1-3",
            "Online anatomy review modules"
          ],
          "assessment_method": "quiz"
        },
        {
          "activity_type": "case_study",
          "title": "Cardiovascular Pathophysiology Cases",
          "estimated_hours": 6,
          "resources": [
            "Interactive case study platform",
            "Clinical simulation scenarios"
          ],
          "assessment_method": "case_analysis"
        }
      ]
    },
    {
      "phase": 2,
      "duration_weeks": 3,
      "focus_competency": "aacn_domain_2_comp_3",
      "learning_activities": [
        {
          "activity_type": "skill_practice",
          "title": "Advanced Communication Techniques",
          "estimated_hours": 8,
          "resources": [
            "Communication skills lab",
            "Standardized patient interactions"
          ],
          "assessment_method": "practical_demonstration"
        }
      ]
    }
  ],
  "success_metrics": {
    "competency_score_targets": {
      "aacn_domain_1_comp_2": 3.5,
      "aacn_domain_2_comp_3": 3.8
    },
    "milestone_assessments": [
      {
        "week": 3,
        "assessment_type": "formative",
        "expected_score": 75
      },
      {
        "week": 6,
        "assessment_type": "summative",
        "expected_score": 85
      }
    ]
  },
  "adaptive_features": {
    "automatic_difficulty_adjustment": true,
    "personalized_resource_recommendations": true,
    "progress_based_pacing": true
  }
}
```

### Get Available Competencies

Retrieve list of available AACN competencies.

```http
GET /api/v1/assessment/competencies/available
```

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Filter by AACN domain |

#### Response

```json
{
  "competencies": [
    {
      "id": "aacn_domain_1_comp_1",
      "domain": "knowledge_for_nursing_practice",
      "name": "Foundational Knowledge Application",
      "description": "Applies foundational scientific knowledge to nursing practice",
      "sub_competencies": [
        "anatomy_physiology_application",
        "pathophysiology_understanding",
        "pharmacology_principles"
      ],
      "learning_outcomes": [
        "Demonstrates understanding of normal body functions",
        "Explains pathophysiological changes in disease processes",
        "Applies pharmacological principles in medication administration"
      ],
      "assessment_methods": [
        "written_examination",
        "case_study_analysis",
        "clinical_demonstration"
      ],
      "prerequisites": [],
      "minimum_level": "competent",
      "weight": 0.15
    }
  ],
  "total_count": 24,
  "domain_filter": null
}
```

### Get AACN Domains

Retrieve all AACN essential domains.

```http
GET /api/v1/assessment/domains
```

#### Response

```json
{
  "domains": [
    {
      "id": "knowledge_for_nursing_practice",
      "name": "Knowledge For Nursing Practice",
      "description": "Foundational knowledge from nursing and other sciences for professional nursing practice"
    },
    {
      "id": "person_centered_care",
      "name": "Person Centered Care",
      "description": "Holistic nursing care that recognizes the individual within family, community, and cultural contexts"
    },
    {
      "id": "population_health",
      "name": "Population Health",
      "description": "Health promotion and disease prevention across diverse populations and communities"
    }
  ]
}
```

### Get Proficiency Levels

Retrieve available competency proficiency levels.

```http
GET /api/v1/assessment/proficiency-levels
```

#### Response

```json
{
  "proficiency_levels": [
    {
      "id": "novice",
      "name": "Novice",
      "description": "Beginning level with limited experience",
      "order": 0
    },
    {
      "id": "advanced_beginner",
      "name": "Advanced Beginner",
      "description": "Demonstrates marginally acceptable performance",
      "order": 1
    },
    {
      "id": "competent",
      "name": "Competent",
      "description": "Demonstrates efficient and organized performance",
      "order": 2
    },
    {
      "id": "proficient",
      "name": "Proficient",
      "description": "Demonstrates holistic understanding and fluid performance",
      "order": 3
    },
    {
      "id": "expert",
      "name": "Expert",
      "description": "Demonstrates intuitive grasp and highly skilled performance",
      "order": 4
    }
  ]
}
```

## SDK Examples

### Python

```python
from bsn_knowledge_sdk import BSNKnowledgeClient

client = BSNKnowledgeClient()
client.login('instructor1', 'password123')

# Assess student competency
assessment_result = client.assessment.assess_competency(
    student_id="student_12345",
    competency_id="aacn_domain_2_comp_1",
    performance_data={
        "quiz_scores": [88, 91, 85],
        "clinical_evaluation": {
            "communication_skills": 4.2,
            "patient_care": 4.0,
            "critical_thinking": 3.8
        },
        "simulation_results": {
            "scenario_completion": True,
            "safety_score": 95
        }
    }
)

print(f"Current Level: {assessment_result.current_level}")
print(f"Proficiency Score: {assessment_result.proficiency_score}")

# Get student competency profile
profile = client.assessment.get_student_profile("student_12345")
print(f"Overall GPA: {profile.competency_gpa}")
print(f"Graduation Readiness: {profile.graduation_readiness_score}%")

# Analyze competency gaps
gaps = client.assessment.analyze_gaps(
    student_id="student_12345",
    target_competencies=["aacn_domain_1_comp_1", "aacn_domain_2_comp_2"],
    severity_filter="high"
)

for domain, domain_gaps in gaps.items():
    print(f"Domain: {domain}")
    for gap in domain_gaps:
        print(f"  Gap: {gap.competency_name} (Severity: {gap.severity})")
```

### JavaScript

```javascript
const BSNKnowledgeClient = require('bsn-knowledge-sdk');

const client = new BSNKnowledgeClient();
await client.login('instructor1', 'password123');

// Bulk competency assessment
const bulkResults = await client.assessment.assessBulk({
  assessments: [
    {
      student_id: 'student_001',
      competency_id: 'aacn_domain_1_comp_1',
      performance_data: {
        quiz_scores: [85, 90, 88],
        clinical_evaluation: { patient_care: 4.1 }
      }
    },
    {
      student_id: 'student_001',
      competency_id: 'aacn_domain_1_comp_2',
      performance_data: {
        quiz_scores: [82, 87, 91],
        clinical_evaluation: { critical_thinking: 3.9 }
      }
    }
  ],
  batch_id: 'midterm_assessment_2024'
});

console.log(`Processed ${bulkResults.successful_assessments} assessments`);

// Generate personalized learning path
const learningPath = await client.assessment.generateLearningPath({
  student_id: 'student_001',
  target_competencies: ['aacn_domain_2_comp_1'],
  learning_preferences: {
    preferred_modalities: ['visual', 'hands_on'],
    time_availability_hours_per_week: 8
  },
  timeline_weeks: 6
});

console.log(`Learning path duration: ${learningPath.estimated_duration_hours} hours`);
learningPath.recommended_sequence.forEach(phase => {
  console.log(`Phase ${phase.phase}: ${phase.focus_competency} (${phase.duration_weeks} weeks)`);
});
```

## Error Handling

### Common Errors

| Status Code | Error Code | Description | Resolution |
|-------------|------------|-------------|------------|
| `400` | `VALIDATION_ERROR` | Invalid assessment parameters | Verify student_id and competency_id format |
| `404` | `RESOURCE_NOT_FOUND` | Student or competency not found | Check that IDs exist in system |
| `422` | `ASSESSMENT_ERROR` | Insufficient data for assessment | Provide more comprehensive performance data |
| `429` | `RATE_LIMIT_EXCEEDED` | Too many assessment requests | Wait for rate limit reset |

### Error Response Example

```json
{
  "error": true,
  "error_code": "ASSESSMENT_ERROR",
  "message": "Assessment failed for competency evaluation: Insufficient performance data",
  "details": {
    "assessment_type": "competency_evaluation",
    "reason": "Performance data must include at least 3 assessment points",
    "missing_data_types": [
      "clinical_evaluation",
      "simulation_results"
    ]
  },
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123"
}
```

---

**Related Documentation:**
- [NCLEX Generation](nclex.md) - Practice question generation
- [Analytics Endpoints](analytics.md) - Progress tracking and reporting
- [Study Guide Creation](study-guides.md) - Personalized learning materials
