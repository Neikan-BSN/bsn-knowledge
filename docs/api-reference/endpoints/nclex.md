# NCLEX Generation Endpoints

Generate NCLEX-style nursing practice questions with AI-powered content creation, evidence-based rationales, and medical accuracy validation.

## Overview

The NCLEX generation endpoints provide intelligent question generation using the RAGnostic AI service, ensuring medically accurate content aligned with current nursing standards and the NCLEX-RN test plan.

**Base Path:** `/api/v1/nclex`

**Rate Limit:** 50 requests per hour (content generation tier)

## Endpoints

### Generate NCLEX Questions

Create NCLEX-style practice questions with customizable parameters.

```http
POST /api/v1/nclex/generate
```

**Authentication:** Required (Student, Instructor, or Admin)

#### Request Body

```json
{
  "topic": "Cardiovascular Nursing",
  "difficulty": "intermediate",
  "question_count": 5,
  "question_types": ["multiple_choice", "select_all"],
  "focus_areas": [
    "pharmacology",
    "pathophysiology",
    "nursing_interventions"
  ],
  "client_needs_category": "physiological_integrity",
  "cognitive_level": "application",
  "settings": {
    "include_rationales": true,
    "include_references": true,
    "medical_accuracy_check": true
  }
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `topic` | string | Yes | Main nursing topic/specialty area |
| `difficulty` | string | No | `beginner`, `intermediate`, `advanced` (default: intermediate) |
| `question_count` | integer | No | Number of questions to generate (1-20, default: 5) |
| `question_types` | array | No | Types of questions to generate |
| `focus_areas` | array | No | Specific areas within the topic |
| `client_needs_category` | string | No | NCLEX client needs category |
| `cognitive_level` | string | No | Bloom's taxonomy cognitive level |
| `settings` | object | No | Generation preferences |

#### Question Types

- `multiple_choice` - Traditional multiple choice (default)
- `select_all` - Select all that apply (SATA)
- `fill_in_blank` - Fill in the blank/calculation
- `drag_and_drop` - Ordered response
- `hotspot` - Image-based hotspot questions

#### Client Needs Categories

- `safe_effective_care` - Safe and Effective Care Environment
- `health_promotion` - Health Promotion and Maintenance
- `psychosocial_integrity` - Psychosocial Integrity
- `physiological_integrity` - Physiological Integrity

#### Cognitive Levels

- `knowledge` - Remember factual information
- `comprehension` - Understand concepts
- `application` - Apply knowledge to situations
- `analysis` - Analyze information and relationships
- `synthesis` - Create new ideas from existing knowledge
- `evaluation` - Judge the value of ideas or materials

#### Response

```json
{
  "questions": [
    {
      "id": "q_001",
      "question_text": "A nurse is caring for a patient with acute myocardial infraction. Which of the following medications would be most appropriate for immediate administration?",
      "question_type": "multiple_choice",
      "options": [
        {
          "id": "A",
          "text": "Aspirin 325 mg chewed",
          "correct": true
        },
        {
          "id": "B",
          "text": "Morphine 4 mg IV",
          "correct": false
        },
        {
          "id": "C",
          "text": "Nitroglycerin 0.4 mg sublingual",
          "correct": false
        },
        {
          "id": "D",
          "text": "Metoprolol 25 mg PO",
          "correct": false
        }
      ],
      "correct_answer": ["A"],
      "rationale": {
        "correct": "Aspirin should be given immediately to patients with suspected MI due to its antiplatelet effects, which help prevent further clot formation and reduce mortality.",
        "incorrect": {
          "B": "While morphine may be used for pain relief, it is not the first priority medication.",
          "C": "Nitroglycerin helps with chest pain but does not address the underlying pathophysiology like aspirin does.",
          "D": "Beta-blockers are important but not typically the first medication administered."
        }
      },
      "topic": "Cardiovascular Nursing",
      "difficulty": "intermediate",
      "client_needs_category": "physiological_integrity",
      "cognitive_level": "application",
      "tags": ["myocardial_infarction", "emergency_care", "pharmacology"],
      "references": [
        {
          "source": "American Heart Association Guidelines",
          "citation": "2020 AHA Guidelines for CPR and ECC",
          "url": "https://www.ahajournals.org/doi/10.1161/CIR.0000000000000916"
        }
      ],
      "metadata": {
        "created_at": "2024-08-24T10:00:00Z",
        "medical_accuracy_score": 0.98,
        "difficulty_level_verified": true
      }
    }
  ],
  "generation_metadata": {
    "total_questions": 5,
    "generation_time_seconds": 12.5,
    "ai_model_used": "gpt-4",
    "medical_validation_passed": true,
    "topic_coverage_score": 0.92,
    "request_id": "nclex_gen_abc123"
  },
  "recommendations": {
    "study_focus_areas": [
      "Review cardiac medication administration timing",
      "Practice emergency cardiac care protocols"
    ],
    "additional_topics": [
      "Post-MI nursing care",
      "Cardiac rehabilitation principles"
    ]
  }
}
```

#### cURL Example

```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/nclex/generate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "Cardiovascular Nursing",
    "difficulty": "intermediate",
    "question_count": 3,
    "question_types": ["multiple_choice"],
    "focus_areas": ["pharmacology", "nursing_interventions"],
    "settings": {
      "include_rationales": true,
      "medical_accuracy_check": true
    }
  }'
```

### Health Check

Check the status of the NCLEX generation service.

```http
GET /api/v1/nclex/health
```

**Authentication:** Not required

#### Response

```json
{
  "service": "nclex_generation",
  "status": "operational",
  "features": [
    "nclex_style_questions",
    "nursing_specific_content",
    "medical_accuracy_validation",
    "evidence_based_rationales"
  ]
}
```

## SDK Examples

### Python

```python
from bsn_knowledge_sdk import BSNKnowledgeClient

client = BSNKnowledgeClient()
client.login('student1', 'password123')

# Generate NCLEX questions
questions = client.nclex.generate(
    topic="Maternal-Newborn Nursing",
    difficulty="intermediate",
    question_count=5,
    question_types=["multiple_choice", "select_all"],
    focus_areas=["labor_delivery", "postpartum_care"],
    settings={
        "include_rationales": True,
        "medical_accuracy_check": True
    }
)

print(f"Generated {len(questions.questions)} questions")
for q in questions.questions:
    print(f"Question: {q.question_text}")
    print(f"Correct Answer: {q.correct_answer}")
    print(f"Rationale: {q.rationale.correct}")
    print("---")
```

### JavaScript

```javascript
const BSNKnowledgeClient = require('bsn-knowledge-sdk');

const client = new BSNKnowledgeClient();
await client.login('student1', 'password123');

// Generate pediatric nursing questions
const response = await client.nclex.generate({
  topic: 'Pediatric Nursing',
  difficulty: 'advanced',
  question_count: 10,
  question_types: ['multiple_choice', 'select_all'],
  focus_areas: ['growth_development', 'common_conditions'],
  client_needs_category: 'health_promotion',
  settings: {
    include_rationales: true,
    include_references: true
  }
});

console.log(`Generated ${response.questions.length} questions`);
response.questions.forEach((question, index) => {
  console.log(`${index + 1}. ${question.question_text}`);
  console.log(`Answer: ${question.correct_answer.join(', ')}`);
});
```

## Advanced Features

### Custom Question Templates

Create questions based on specific clinical scenarios:

```json
{
  "topic": "Emergency Nursing",
  "scenario_template": {
    "patient_demographics": {
      "age": "65",
      "gender": "male",
      "medical_history": ["diabetes", "hypertension"]
    },
    "presenting_symptoms": ["chest_pain", "shortness_of_breath"],
    "clinical_setting": "emergency_department"
  },
  "question_focus": "priority_nursing_interventions",
  "difficulty": "advanced"
}
```

### Competency-Aligned Generation

Generate questions aligned with specific AACN competencies:

```json
{
  "topic": "Person-Centered Care",
  "competency_alignment": {
    "aacn_domain": "person_centered_care",
    "sub_competencies": [
      "cultural_sensitivity",
      "patient_advocacy",
      "therapeutic_communication"
    ]
  },
  "learning_objectives": [
    "Demonstrate culturally sensitive care practices",
    "Advocate for patient rights and preferences"
  ]
}
```

### Batch Question Generation

Generate multiple question sets efficiently:

```json
{
  "batch_requests": [
    {
      "topic": "Medical-Surgical Nursing",
      "focus_areas": ["diabetes_management"],
      "question_count": 5
    },
    {
      "topic": "Mental Health Nursing",
      "focus_areas": ["anxiety_disorders"],
      "question_count": 5
    },
    {
      "topic": "Community Health Nursing",
      "focus_areas": ["health_promotion"],
      "question_count": 5
    }
  ],
  "global_settings": {
    "difficulty": "intermediate",
    "include_rationales": true
  }
}
```

## Quality Assurance

### Medical Accuracy Validation

All generated questions undergo automated medical accuracy validation:

- **Clinical Guidelines Compliance**: Alignment with current evidence-based practice
- **Medication Accuracy**: Verification of drug names, dosages, and interactions
- **Procedure Validation**: Confirmation of nursing procedures and protocols
- **Terminology Consistency**: Use of standardized medical terminology

### Content Review Metrics

Questions include quality metrics:

```json
{
  "quality_metrics": {
    "medical_accuracy_score": 0.98,
    "readability_score": 0.85,
    "difficulty_consistency": 0.92,
    "evidence_base_strength": 0.94,
    "clinical_relevance": 0.96
  }
}
```

## Error Handling

### Common Errors

| Status Code | Error Code | Description | Resolution |
|-------------|------------|-------------|------------|
| `400` | `VALIDATION_ERROR` | Invalid request parameters | Check request format and required fields |
| `422` | `CONTENT_GENERATION_ERROR` | Failed to generate questions | Try different topic or reduce question count |
| `429` | `RATE_LIMIT_EXCEEDED` | Too many generation requests | Wait for rate limit reset |
| `503` | `EXTERNAL_SERVICE_ERROR` | RAGnostic AI service unavailable | Retry request or contact support |

### Error Response Example

```json
{
  "error": true,
  "error_code": "CONTENT_GENERATION_ERROR",
  "message": "Failed to generate NCLEX questions: Topic too specialized",
  "details": {
    "content_type": "nclex_questions",
    "reason": "Insufficient training data for highly specialized topic",
    "suggestions": [
      "Try a broader topic category",
      "Reduce the number of requested questions",
      "Use a different difficulty level"
    ]
  },
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123"
}
```

## Best Practices

### Effective Question Generation

1. **Topic Specificity**: Use clear, well-defined nursing topics
2. **Appropriate Difficulty**: Match difficulty to learner level
3. **Balanced Question Types**: Mix multiple choice with SATA questions
4. **Focus Areas**: Specify 2-3 focus areas for targeted learning
5. **Rationale Inclusion**: Always include rationales for learning effectiveness

### Performance Optimization

```python
# Efficient batch processing
def generate_study_session(topics, question_count_per_topic=5):
    questions = []

    for topic in topics:
        response = client.nclex.generate(
            topic=topic,
            question_count=question_count_per_topic,
            settings={
                "include_rationales": True,
                "medical_accuracy_check": True
            }
        )
        questions.extend(response.questions)

    return questions

# Cache frequently used topics
@lru_cache(maxsize=32)
def get_cached_questions(topic, difficulty):
    return client.nclex.generate(topic=topic, difficulty=difficulty)
```

### Integration with Learning Management Systems

```python
class LMSIntegration:
    def create_quiz_from_nclex(self, topic, student_level):
        # Generate questions based on student competency level
        questions = client.nclex.generate(
            topic=topic,
            difficulty=self.map_student_level_to_difficulty(student_level),
            question_count=10,
            settings={"include_rationales": True}
        )

        # Convert to LMS format
        lms_quiz = self.convert_to_lms_format(questions)

        # Upload to LMS
        return self.lms_client.create_quiz(lms_quiz)
```

---

**Related Documentation:**
- [Study Guide Generation](study-guides.md) - Create personalized study materials
- [Assessment Endpoints](assessment.md) - Competency evaluation
- [Analytics](analytics.md) - Track question performance and learning progress
