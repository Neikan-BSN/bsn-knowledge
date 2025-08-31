"""
Clinical Recommendation Engine for BSN Knowledge
Generates evidence-based clinical recommendations using RAGnostic's enriched medical content
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import openai
from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import get_settings
from ..services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)
settings = get_settings()


class EvidenceStrength(str, Enum):
    """Evidence strength levels based on medical research hierarchy"""

    SYSTEMATIC_REVIEW = "systematic_review_meta_analysis"  # Level 1
    RANDOMIZED_TRIAL = "randomized_controlled_trial"  # Level 2
    CONTROLLED_TRIAL = "controlled_trial_without_randomization"  # Level 3
    CASE_CONTROL = "case_control_cohort_study"  # Level 4
    DESCRIPTIVE = "descriptive_study"  # Level 5
    EXPERT_OPINION = "expert_opinion"  # Level 6


class ClinicalPriority(str, Enum):
    """Clinical priority levels for recommendations"""

    CRITICAL = "critical"  # Immediate life-threatening
    HIGH = "high"  # Urgent intervention needed
    MODERATE = "moderate"  # Important but not urgent
    LOW = "low"  # Can be delayed


class CaseScenario(BaseModel):
    """Patient case scenario for clinical recommendation generation"""

    patient_demographics: dict[str, Any] = Field(
        description="Patient age, gender, relevant demographic factors"
    )
    clinical_presentation: dict[str, Any] = Field(
        description="Current symptoms, vital signs, physical assessment findings"
    )
    relevant_history: dict[str, Any] = Field(
        description="Medical history, medications, allergies, social factors"
    )
    learning_objectives: list[str] = Field(
        description="Specific learning goals for this case scenario"
    )
    case_complexity: str = Field(
        default="intermediate",
        description="Case complexity level: basic, intermediate, advanced",
    )

    @field_validator("learning_objectives")
    @classmethod
    def validate_learning_objectives(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one learning objective must be provided")
        return v


class Recommendation(BaseModel):
    """Individual evidence-based clinical recommendation"""

    recommendation_text: str = Field(description="Clear, actionable recommendation")
    evidence_citations: list[str] = Field(
        description="Source citations supporting this recommendation"
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score based on evidence strength (0.0-1.0)",
    )
    reasoning_steps: list[str] = Field(
        description="Step-by-step clinical reasoning process"
    )
    evidence_strength: EvidenceStrength = Field(
        description="Level of supporting evidence"
    )
    priority: ClinicalPriority = Field(
        description="Clinical priority of this recommendation"
    )
    contraindications: list[str] = Field(
        default=[],
        description="Situations where this recommendation should not be applied",
    )
    monitoring_parameters: list[str] = Field(
        default=[],
        description="Parameters to monitor when implementing this recommendation",
    )
    umls_concepts: list[str] = Field(
        default=[], description="Relevant UMLS medical concepts"
    )

    @model_validator(mode="after")
    def validate_confidence_score(self):
        # Adjust confidence based on evidence strength
        if self.evidence_strength:
            max_confidence_by_evidence = {
                EvidenceStrength.SYSTEMATIC_REVIEW: 0.95,
                EvidenceStrength.RANDOMIZED_TRIAL: 0.90,
                EvidenceStrength.CONTROLLED_TRIAL: 0.80,
                EvidenceStrength.CASE_CONTROL: 0.70,
                EvidenceStrength.DESCRIPTIVE: 0.60,
                EvidenceStrength.EXPERT_OPINION: 0.50,
            }
            max_allowed = max_confidence_by_evidence.get(self.evidence_strength, 0.50)
            if self.confidence_score > max_allowed:
                logger.warning(
                    f"Confidence score {self.confidence_score} exceeds maximum {max_allowed} "
                    f"for evidence strength {self.evidence_strength}. Adjusting."
                )
                self.confidence_score = max_allowed
        return self


class RecommendationResult(BaseModel):
    """Complete result with multiple recommendations and metadata"""

    recommendations: list[Recommendation] = Field(
        description="List of evidence-based recommendations"
    )
    case_id: str = Field(description="Unique identifier for this case")
    generated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when recommendations were generated",
    )
    overall_confidence: float = Field(
        ge=0.0, le=1.0, description="Overall confidence across all recommendations"
    )
    evidence_summary: dict[str, Any] = Field(
        description="Summary of evidence used in generating recommendations"
    )
    ragnostic_context: dict[str, Any] = Field(
        default={}, description="Context and metadata from RAGnostic queries"
    )

    @model_validator(mode="after")
    def calculate_overall_confidence(self):
        if self.recommendations:
            # Weighted average based on priority
            priority_weights = {
                ClinicalPriority.CRITICAL: 4,
                ClinicalPriority.HIGH: 3,
                ClinicalPriority.MODERATE: 2,
                ClinicalPriority.LOW: 1,
            }
            total_weighted_score = sum(
                rec.confidence_score * priority_weights.get(rec.priority, 1)
                for rec in self.recommendations
            )
            total_weights = sum(
                priority_weights.get(rec.priority, 1) for rec in self.recommendations
            )
            self.overall_confidence = total_weighted_score / max(total_weights, 1)
        return self


@dataclass
class ContentChunk:
    """Represents a piece of medical content from RAGnostic"""

    content: str
    metadata: dict[str, Any]
    relevance_score: float
    umls_concepts: list[str]
    evidence_level: str | None = None


class ClinicalDecisionSupport:
    """Provides evidence-based clinical recommendations per REVISED_PHASE3_PLAN.md B.3 specifications"""

    def __init__(self, ragnostic_client: RAGnosticClient | None = None):
        """Initialize the clinical recommendation engine"""
        self.ragnostic_client = ragnostic_client or RAGnosticClient(
            **settings.get_ragnostic_client_config()
        )

        # Configure OpenAI
        openai.api_key = settings.openai_api_key
        self.openai_model = settings.openai_model
        self.temperature = settings.openai_temperature
        self.max_tokens = settings.openai_max_tokens

        # Clinical reasoning prompts
        self.system_prompt = """
You are an expert clinical nurse educator and evidence-based practice specialist.
Your role is to generate safe, evidence-based clinical recommendations for nursing students.

Core Principles:
1. Patient safety is paramount
2. All recommendations must be evidence-based
3. Consider individual patient factors and contraindications
4. Provide clear clinical reasoning
5. Include appropriate monitoring parameters
6. Ensure recommendations align with current nursing standards and scope of practice
7. Consider cultural, ethical, and psychosocial factors
8. Promote collaborative care and patient/family involvement

Evidence Hierarchy (use to assign evidence strength):
- Systematic Reviews/Meta-analyses (highest)
- Randomized Controlled Trials
- Controlled Trials without Randomization
- Case-Control and Cohort Studies
- Descriptive Studies
- Expert Opinion (lowest)

Response Format: Always respond in valid JSON format.
"""

        # Initialize recommendation cache
        self._recommendation_cache: dict[str, RecommendationResult] = {}
        self._cache_expiry: dict[str, datetime] = {}
        self._cache_ttl = timedelta(hours=2)  # Cache recommendations for 2 hours

        logger.info("Clinical Recommendation Engine initialized")

    def _generate_case_id(self, case_scenario: CaseScenario) -> str:
        """Generate unique case identifier for caching using HIPAA-compliant hashing"""
        # Use SHA-256 instead of MD5 for medical data security compliance
        case_hash = hashlib.sha256(
            json.dumps(case_scenario.dict(), sort_keys=True).encode()
        ).hexdigest()[:16]
        return f"case_{case_hash}"

    async def _query_ragnostic_context(
        self, case_scenario: CaseScenario
    ) -> tuple[list[ContentChunk], dict[str, Any]]:
        """Query RAGnostic for relevant medical content and context"""
        try:
            # Construct comprehensive search query
            search_terms = []

            # Add clinical presentation terms
            if "chief_complaint" in case_scenario.clinical_presentation:
                search_terms.append(
                    case_scenario.clinical_presentation["chief_complaint"]
                )
            if "diagnosis" in case_scenario.clinical_presentation:
                search_terms.append(case_scenario.clinical_presentation["diagnosis"])

            # Add demographic factors that affect care
            demographics = case_scenario.patient_demographics
            if demographics.get("age_group"):
                search_terms.append(f"{demographics['age_group']} patient care")

            # Add learning objectives as search context
            search_terms.extend(case_scenario.learning_objectives)

            primary_query = " ".join(search_terms)

            # Perform multiple targeted searches
            search_tasks = [
                # Primary clinical content search
                self.ragnostic_client.search_content(
                    query=primary_query,
                    filters={
                        "content_type": "clinical_guidelines",
                        "evidence_based": True,
                    },
                    limit=15,
                    cache_ttl=600,  # Cache clinical searches longer
                ),
                # Nursing-specific interventions
                self.ragnostic_client.search_content(
                    query=f"nursing interventions {primary_query}",
                    filters={
                        "content_type": "nursing_practice",
                        "scope": "registered_nurse",
                    },
                    limit=10,
                    cache_ttl=600,
                ),
                # Evidence-based protocols
                self.ragnostic_client.search_content(
                    query=f"evidence based protocol {primary_query}",
                    filters={
                        "content_type": "protocol",
                        "evidence_level": ["level_1", "level_2", "level_3"],
                    },
                    limit=8,
                    cache_ttl=600,
                ),
            ]

            # Execute searches concurrently
            search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

            # Process and combine results
            all_content_chunks = []
            metadata = {
                "search_queries": [primary_query],
                "total_sources": 0,
                "ragnostic_response_times": [],
                "fallback_mode": False,
            }

            for i, result in enumerate(search_results):
                if isinstance(result, Exception):
                    logger.warning(f"RAGnostic search {i} failed: {str(result)}")
                    metadata["fallback_mode"] = True
                    continue

                if result and "items" in result:
                    for item in result["items"]:
                        content_chunk = ContentChunk(
                            content=item.get("content", ""),
                            metadata=item.get("metadata", {}),
                            relevance_score=item.get("relevance_score", 0.0),
                            umls_concepts=item.get("umls_concepts", []),
                            evidence_level=item.get("evidence_level"),
                        )
                        all_content_chunks.append(content_chunk)

                    metadata["total_sources"] += len(result["items"])
                    if "processing_time" in result:
                        metadata["ragnostic_response_times"].append(
                            result["processing_time"]
                        )

            # Sort by relevance and evidence level
            all_content_chunks.sort(
                key=lambda x: (
                    x.relevance_score,
                    self._evidence_level_score(x.evidence_level),
                ),
                reverse=True,
            )

            logger.info(
                f"Retrieved {len(all_content_chunks)} content chunks from RAGnostic "
                f"for case scenario (fallback mode: {metadata['fallback_mode']})"
            )

            return all_content_chunks[:20], metadata  # Limit to top 20 most relevant

        except Exception as e:
            logger.error(f"RAGnostic context query failed: {str(e)}")
            # Return minimal context to allow degraded functionality
            return [], {"error": str(e), "fallback_mode": True}

    def _evidence_level_score(self, evidence_level: str | None) -> float:
        """Convert evidence level to numeric score for sorting"""
        level_scores = {
            "systematic_review_meta_analysis": 6.0,
            "randomized_controlled_trial": 5.0,
            "controlled_trial_without_randomization": 4.0,
            "case_control_cohort_study": 3.0,
            "descriptive_study": 2.0,
            "expert_opinion": 1.0,
        }
        return level_scores.get(evidence_level, 0.0)

    def _apply_clinical_reasoning(
        self, content: list[ContentChunk], scenario: CaseScenario
    ) -> list[dict[str, Any]]:
        """Apply clinical reasoning algorithms to generate recommendations"""
        reasoning_results = []

        # Group content by clinical domain
        domains = {
            "assessment": [],
            "intervention": [],
            "monitoring": [],
            "education": [],
            "safety": [],
        }

        # Categorize content chunks
        for chunk in content:
            content_lower = chunk.content.lower()

            # Use metadata and content analysis to categorize
            if any(
                term in content_lower
                for term in ["assess", "evaluate", "monitor", "observe"]
            ):
                domains["assessment"].append(chunk)
            elif any(
                term in content_lower
                for term in ["intervention", "treatment", "care", "manage"]
            ):
                domains["intervention"].append(chunk)
            elif any(
                term in content_lower
                for term in ["monitor", "watch", "track", "measure"]
            ):
                domains["monitoring"].append(chunk)
            elif any(
                term in content_lower
                for term in ["teach", "educate", "explain", "instruct"]
            ):
                domains["education"].append(chunk)
            elif any(
                term in content_lower
                for term in ["safety", "risk", "precaution", "contraindication"]
            ):
                domains["safety"].append(chunk)
            else:
                # Default to intervention if unclear
                domains["intervention"].append(chunk)

        # Generate reasoning for each domain with content
        for domain, chunks in domains.items():
            if not chunks:
                continue

            # Take top chunks by relevance for this domain
            top_chunks = sorted(chunks, key=lambda x: x.relevance_score, reverse=True)[
                :3
            ]

            reasoning_result = {
                "domain": domain,
                "evidence_chunks": top_chunks,
                "reasoning_priority": self._calculate_domain_priority(domain, scenario),
                "clinical_indicators": self._extract_clinical_indicators(
                    top_chunks, scenario
                ),
            }
            reasoning_results.append(reasoning_result)

        return reasoning_results

    def _calculate_domain_priority(
        self, domain: str, scenario: CaseScenario
    ) -> ClinicalPriority:
        """Determine priority level for clinical domain based on scenario"""
        # Analyze scenario for urgency indicators
        presentation = scenario.clinical_presentation
        history = scenario.relevant_history

        # Safety domain is always high priority
        if domain == "safety":
            return ClinicalPriority.HIGH

        # Check for critical indicators
        critical_indicators = [
            "respiratory distress",
            "chest pain",
            "altered consciousness",
            "severe bleeding",
            "anaphylaxis",
            "cardiac arrest",
        ]

        scenario_text = json.dumps({**presentation, **history}).lower()
        if any(indicator in scenario_text for indicator in critical_indicators):
            if domain in ["assessment", "intervention"]:
                return ClinicalPriority.CRITICAL
            else:
                return ClinicalPriority.HIGH

        # Default priorities by domain
        domain_priorities = {
            "assessment": ClinicalPriority.HIGH,
            "intervention": ClinicalPriority.HIGH,
            "monitoring": ClinicalPriority.MODERATE,
            "education": ClinicalPriority.MODERATE,
            "safety": ClinicalPriority.HIGH,
        }

        return domain_priorities.get(domain, ClinicalPriority.MODERATE)

    def _extract_clinical_indicators(
        self, chunks: list[ContentChunk], scenario: CaseScenario
    ) -> list[str]:
        """Extract relevant clinical indicators from content chunks"""
        indicators = []

        for chunk in chunks:
            # Extract UMLS concepts as indicators
            indicators.extend(chunk.umls_concepts[:3])  # Top 3 concepts per chunk

            # Extract specific clinical terms from metadata
            metadata = chunk.metadata
            if "clinical_terms" in metadata:
                indicators.extend(metadata["clinical_terms"][:2])

        # Remove duplicates and return top indicators
        unique_indicators = list(dict.fromkeys(indicators))  # Preserve order
        return unique_indicators[:10]  # Limit to top 10 indicators

    def _calculate_confidence_score(
        self, recommendation: str, evidence: list[ContentChunk]
    ) -> float:
        """Calculate confidence score based on evidence strength and consistency"""
        if not evidence:
            return 0.3  # Low confidence without evidence

        # Base score on evidence levels
        evidence_scores = []
        for chunk in evidence:
            level_score = self._evidence_level_score(chunk.evidence_level)
            relevance_score = chunk.relevance_score
            # Combine evidence level and relevance
            combined_score = (level_score * 0.7) + (relevance_score * 0.3)
            evidence_scores.append(combined_score)

        # Calculate weighted average with diminishing returns
        if evidence_scores:
            # Weight first piece of evidence most heavily
            weights = [1.0, 0.8, 0.6, 0.4, 0.2]  # Diminishing weights
            weighted_sum = sum(
                score * weights[min(i, len(weights) - 1)]
                for i, score in enumerate(sorted(evidence_scores, reverse=True))
            )
            total_weight = sum(weights[: min(len(evidence_scores), len(weights))])
            base_confidence = weighted_sum / total_weight
        else:
            base_confidence = 0.3

        # Normalize to 0-1 range
        confidence = min(max(base_confidence / 6.0, 0.0), 1.0)

        # Apply conservative adjustment for clinical safety
        if confidence > 0.9:
            confidence = 0.9  # Cap at 90% for clinical recommendations

        return round(confidence, 3)

    async def generate_recommendations(
        self, case_scenario: dict
    ) -> RecommendationResult:
        """
        Generate evidence-based clinical recommendations for a case scenario
        Per REVISED_PHASE3_PLAN.md B.3: Query RAGnostic for relevant clinical content,
        apply clinical reasoning algorithms, generate evidence-based recommendations,
        and include citations with confidence scores.

        Args:
            case_scenario: Dict with patient case scenario data

        Returns:
            RecommendationResult with prioritized, evidence-based recommendations
        """
        # Convert dict to CaseScenario if needed
        if isinstance(case_scenario, dict):
            case_scenario = CaseScenario(**case_scenario)
        case_id = self._generate_case_id(case_scenario)

        # Check cache first
        if (
            case_id in self._recommendation_cache
            and case_id in self._cache_expiry
            and datetime.utcnow() < self._cache_expiry[case_id]
        ):
            logger.info(f"Returning cached recommendations for case {case_id}")
            return self._recommendation_cache[case_id]

        try:
            start_time = datetime.utcnow()

            # Step 1: Query RAGnostic for relevant medical content
            logger.info(f"Querying RAGnostic for case {case_id}")
            content_chunks, ragnostic_metadata = await self._query_ragnostic_context(
                case_scenario
            )

            # Step 2: Apply clinical reasoning algorithms
            logger.info(f"Applying clinical reasoning for case {case_id}")
            reasoning_results = self._apply_clinical_reasoning(
                content_chunks, case_scenario
            )

            # Step 3: Generate recommendations using OpenAI
            recommendations = []
            evidence_summary = {
                "total_content_chunks": len(content_chunks),
                "reasoning_domains": len(reasoning_results),
                "evidence_levels": {},
                "umls_concepts_count": 0,
            }

            for reasoning in reasoning_results:
                domain = reasoning["domain"]
                chunks = reasoning["evidence_chunks"]
                priority = reasoning["reasoning_priority"]

                if not chunks:
                    continue

                # Prepare evidence context for OpenAI
                evidence_context = "\n\n".join(
                    [
                        f"Evidence {i + 1} (Relevance: {chunk.relevance_score:.2f}, "
                        f"Level: {chunk.evidence_level or 'unspecified'}):\n{chunk.content}"
                        for i, chunk in enumerate(
                            chunks[:3]
                        )  # Top 3 pieces of evidence
                    ]
                )

                # Create domain-specific prompt
                domain_prompt = f"""
Case Scenario:
- Patient Demographics: {json.dumps(case_scenario.patient_demographics, indent=2)}
- Clinical Presentation: {json.dumps(case_scenario.clinical_presentation, indent=2)}
- Relevant History: {json.dumps(case_scenario.relevant_history, indent=2)}
- Learning Objectives: {", ".join(case_scenario.learning_objectives)}

Clinical Domain: {domain.title()}
Priority Level: {priority.value}

Evidence-Based Context:
{evidence_context}

Generate 1-2 specific, evidence-based clinical recommendations for this {domain} domain.
For each recommendation, provide:
1. Clear, actionable recommendation text
2. Step-by-step clinical reasoning
3. Evidence citations from the provided context
4. Appropriate contraindications and monitoring parameters
5. Relevant UMLS medical concepts

Respond in JSON format:
{{
    "recommendations": [
        {{
            "recommendation_text": "specific actionable recommendation",
            "reasoning_steps": ["step 1", "step 2", "step 3"],
            "evidence_citations": ["citation from provided evidence"],
            "contraindications": ["contraindication 1", "contraindication 2"],
            "monitoring_parameters": ["parameter 1", "parameter 2"],
            "umls_concepts": ["concept 1", "concept 2"],
            "evidence_strength": "systematic_review_meta_analysis|randomized_controlled_trial|controlled_trial_without_randomization|case_control_cohort_study|descriptive_study|expert_opinion"
        }}
    ]
}}
"""

                try:
                    # Call OpenAI for this domain
                    response = await openai.ChatCompletion.acreate(
                        model=self.openai_model,
                        messages=[
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": domain_prompt},
                        ],
                        temperature=self.temperature,
                        max_tokens=self.max_tokens,
                        response_format={"type": "json_object"},
                    )

                    response_content = response.choices[0].message.content
                    domain_recommendations = json.loads(response_content)

                    # Process each recommendation in this domain
                    for rec_data in domain_recommendations.get("recommendations", []):
                        # Calculate confidence score based on evidence
                        confidence = self._calculate_confidence_score(
                            rec_data.get("recommendation_text", ""), chunks
                        )

                        # Create recommendation object
                        recommendation = Recommendation(
                            recommendation_text=rec_data.get("recommendation_text", ""),
                            evidence_citations=rec_data.get("evidence_citations", []),
                            confidence_score=confidence,
                            reasoning_steps=rec_data.get("reasoning_steps", []),
                            evidence_strength=EvidenceStrength(
                                rec_data.get(
                                    "evidence_strength",
                                    EvidenceStrength.EXPERT_OPINION.value,
                                )
                            ),
                            priority=priority,
                            contraindications=rec_data.get("contraindications", []),
                            monitoring_parameters=rec_data.get(
                                "monitoring_parameters", []
                            ),
                            umls_concepts=rec_data.get("umls_concepts", []),
                        )

                        recommendations.append(recommendation)

                        # Update evidence summary
                        evidence_level = recommendation.evidence_strength.value
                        evidence_summary["evidence_levels"][evidence_level] = (
                            evidence_summary["evidence_levels"].get(evidence_level, 0)
                            + 1
                        )
                        evidence_summary["umls_concepts_count"] += len(
                            recommendation.umls_concepts
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to generate recommendations for {domain} domain: {str(e)}"
                    )
                    continue

            # Sort recommendations by priority and confidence
            priority_order = {p: i for i, p in enumerate(ClinicalPriority)}
            recommendations.sort(
                key=lambda r: (priority_order.get(r.priority, 999), -r.confidence_score)
            )

            # Create final result
            result = RecommendationResult(
                recommendations=recommendations,
                case_id=case_id,
                generated_at=datetime.utcnow(),
                evidence_summary=evidence_summary,
                ragnostic_context=ragnostic_metadata,
                overall_confidence=0.0,  # Will be calculated by validator
            )

            # Cache the result
            self._recommendation_cache[case_id] = result
            self._cache_expiry[case_id] = datetime.utcnow() + self._cache_ttl

            generation_time = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"Generated {len(recommendations)} clinical recommendations "
                f"for case {case_id} in {generation_time:.2f}s"
            )

            return result

        except Exception as e:
            logger.error(
                f"Clinical recommendation generation failed for case {case_id}: {str(e)}"
            )
            # Return minimal result to prevent complete failure
            return RecommendationResult(
                recommendations=[],
                case_id=case_id,
                generated_at=datetime.utcnow(),
                evidence_summary={"error": str(e)},
                ragnostic_context={"error": str(e)},
                overall_confidence=0.0,
            )

    async def create_case_studies(
        self, learning_objectives: list[str]
    ) -> list[dict[str, Any]]:
        """
        Create case studies using RAGnostic content aligned with learning objectives
        Per REVISED_PHASE3_PLAN.md B.3: Use RAGnostic content to build scenarios,
        align with specified learning objectives, include assessment questions.

        Args:
            learning_objectives: List of learning goals for case studies

        Returns:
            List of case study dictionaries with scenarios and assessment questions
        """
        case_studies = []

        try:
            for objective in learning_objectives:
                # Query RAGnostic for content related to the learning objective
                content_search = await self.ragnostic_client.search_content(
                    query=objective,
                    filters={
                        "content_type": "clinical_case_material",
                        "educational_level": "undergraduate_nursing",
                        "evidence_based": True,
                    },
                    limit=5,
                    cache_ttl=600,
                )

                if not content_search or "items" not in content_search:
                    logger.warning(
                        f"No content found for learning objective: {objective}"
                    )
                    continue

                # Extract medical concepts from retrieved content
                content_chunks = []
                for item in content_search["items"]:
                    chunk = ContentChunk(
                        content=item.get("content", ""),
                        metadata=item.get("metadata", {}),
                        relevance_score=item.get("relevance_score", 0.0),
                        umls_concepts=item.get("umls_concepts", []),
                        evidence_level=item.get("evidence_level"),
                    )
                    content_chunks.append(chunk)

                # Generate case study using OpenAI with RAGnostic context
                case_study_prompt = f"""
                Learning Objective: {objective}

                Medical Content Context:
                {self._format_content_for_prompt(content_chunks[:3])}

                Create a comprehensive clinical case study that addresses this learning objective.
                Include:

                1. Patient Demographics and History
                2. Clinical Presentation (symptoms, vital signs, assessment findings)
                3. Relevant Medical History and Current Medications
                4. Case Scenario Progression (multiple decision points)
                5. Assessment Questions (multiple choice and open-ended)
                6. Expected Learning Outcomes
                7. Evidence-Based Rationales

                Format as JSON:
                {{
                    "case_id": "unique_case_id",
                    "learning_objective": "{objective}",
                    "patient_demographics": {{
                        "age": 0,
                        "gender": "",
                        "relevant_factors": []
                    }},
                    "clinical_presentation": {{
                        "chief_complaint": "",
                        "symptoms": [],
                        "vital_signs": {{}},
                        "physical_assessment": []
                    }},
                    "relevant_history": {{
                        "medical_history": [],
                        "medications": [],
                        "allergies": [],
                        "social_factors": []
                    }},
                    "case_progression": [
                        {{
                            "time_point": "",
                            "situation": "",
                            "decision_required": "",
                            "options": []
                        }}
                    ],
                    "assessment_questions": [
                        {{
                            "question_type": "multiple_choice",
                            "question": "",
                            "options": [],
                            "correct_answer": "",
                            "rationale": "",
                            "difficulty": "intermediate"
                        }}
                    ],
                    "expected_outcomes": [],
                    "evidence_citations": [],
                    "umls_concepts": [],
                    "case_complexity": "intermediate"
                }}
                """

                try:
                    response = await openai.ChatCompletion.acreate(
                        model=self.openai_model,
                        messages=[
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": case_study_prompt},
                        ],
                        temperature=0.7,  # Slightly higher for creative case studies
                        max_tokens=2000,
                        response_format={"type": "json_object"},
                    )

                    case_study_data = json.loads(response.choices[0].message.content)
                    case_study_data["generated_at"] = datetime.utcnow().isoformat()
                    case_study_data["ragnostic_source_count"] = len(content_chunks)

                    case_studies.append(case_study_data)

                    logger.info(
                        f"Generated case study for learning objective: {objective}"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to generate case study for '{objective}': {str(e)}"
                    )
                    # Create minimal fallback case study
                    fallback_case = {
                        "case_id": f"fallback_{len(case_studies) + 1}",
                        "learning_objective": objective,
                        "error": f"Generation failed: {str(e)}",
                        "generated_at": datetime.utcnow().isoformat(),
                        "fallback_mode": True,
                    }
                    case_studies.append(fallback_case)

            logger.info(
                f"Generated {len(case_studies)} case studies for {len(learning_objectives)} learning objectives"
            )
            return case_studies

        except Exception as e:
            logger.error(f"Case study generation failed: {str(e)}")
            raise

    def _format_content_for_prompt(self, content_chunks: list[ContentChunk]) -> str:
        """Format content chunks for inclusion in prompts"""
        formatted_content = []
        for i, chunk in enumerate(content_chunks, 1):
            formatted_content.append(
                f"Source {i} (Relevance: {chunk.relevance_score:.2f}):\n"
                f"Content: {chunk.content[:500]}...\n"
                f"UMLS Concepts: {', '.join(chunk.umls_concepts[:5])}\n"
            )
        return "\n\n".join(formatted_content)

    async def validate_recommendation(
        self,
        recommendation: Recommendation,
        case_context: CaseScenario | None = None,
    ) -> dict[str, Any]:
        """
        Validate a clinical recommendation for safety and evidence base

        Args:
            recommendation: The recommendation to validate
            case_context: Optional case context for contextual validation

        Returns:
            Dict with validation results including safety warnings
        """
        validation_result = {
            "is_safe": True,
            "safety_warnings": [],
            "evidence_assessment": "acceptable",
            "confidence_assessment": "appropriate",
            "recommendations": [],
        }

        try:
            # Validate evidence strength vs confidence score
            max_confidence_by_evidence = {
                EvidenceStrength.SYSTEMATIC_REVIEW: 0.95,
                EvidenceStrength.RANDOMIZED_TRIAL: 0.90,
                EvidenceStrength.CONTROLLED_TRIAL: 0.80,
                EvidenceStrength.CASE_CONTROL: 0.70,
                EvidenceStrength.DESCRIPTIVE: 0.60,
                EvidenceStrength.EXPERT_OPINION: 0.50,
            }

            max_allowed = max_confidence_by_evidence.get(
                recommendation.evidence_strength, 0.50
            )
            if recommendation.confidence_score > max_allowed + 0.05:  # 5% tolerance
                validation_result["confidence_assessment"] = "overconfident"
                validation_result["recommendations"].append(
                    f"Confidence score {recommendation.confidence_score} may be too high "
                    f"for evidence level {recommendation.evidence_strength.value}"
                )

            # Check for critical priority without appropriate evidence
            if (
                recommendation.priority == ClinicalPriority.CRITICAL
                and recommendation.evidence_strength
                in [EvidenceStrength.DESCRIPTIVE, EvidenceStrength.EXPERT_OPINION]
            ):
                validation_result["safety_warnings"].append(
                    "Critical priority recommendation should have stronger evidence base"
                )

            # Validate presence of required components for high-risk recommendations
            if recommendation.priority in [
                ClinicalPriority.CRITICAL,
                ClinicalPriority.HIGH,
            ]:
                if not recommendation.contraindications:
                    validation_result["safety_warnings"].append(
                        "High-priority recommendation missing contraindications"
                    )
                if not recommendation.monitoring_parameters:
                    validation_result["safety_warnings"].append(
                        "High-priority recommendation missing monitoring parameters"
                    )

            # Check evidence citations
            if not recommendation.evidence_citations:
                validation_result["evidence_assessment"] = "insufficient"
                validation_result["recommendations"].append(
                    "Recommendation should include specific evidence citations"
                )

            # Assess overall safety
            if validation_result["safety_warnings"]:
                validation_result["is_safe"] = (
                    len(validation_result["safety_warnings"]) <= 1
                )

            return validation_result

        except Exception as e:
            logger.error(f"Recommendation validation failed: {str(e)}")
            return {
                "is_safe": False,
                "safety_warnings": [f"Validation error: {str(e)}"],
                "evidence_assessment": "error",
                "confidence_assessment": "error",
                "recommendations": ["Manual review required due to validation error"],
            }

    async def get_emergency_protocols(
        self, emergency_type: str, patient_factors: dict[str, Any] | None = None
    ) -> RecommendationResult:
        """
        Generate emergency clinical protocols and recommendations

        Args:
            emergency_type: Type of emergency (e.g., "cardiac arrest", "anaphylaxis")
            patient_factors: Optional patient-specific factors

        Returns:
            RecommendationResult with emergency protocols
        """
        # Create emergency case scenario
        emergency_scenario = CaseScenario(
            patient_demographics=patient_factors or {},
            clinical_presentation={
                "emergency_type": emergency_type,
                "acuity": "critical",
            },
            relevant_history=patient_factors or {},
            learning_objectives=[
                f"Emergency management of {emergency_type}",
                "Immediate life-saving interventions",
                "Team coordination and communication",
                "Post-emergency care and monitoring",
            ],
            case_complexity="advanced",
        )

        # Generate recommendations with emergency context
        recommendations = await self.generate_recommendations(emergency_scenario)

        # Filter and prioritize for emergency context
        emergency_recommendations = [
            rec
            for rec in recommendations.recommendations
            if rec.priority in [ClinicalPriority.CRITICAL, ClinicalPriority.HIGH]
        ]

        # Update result for emergency context
        recommendations.recommendations = emergency_recommendations
        recommendations.case_id = f"emergency_{emergency_type.replace(' ', '_')}"

        logger.info(
            f"Generated {len(emergency_recommendations)} emergency protocols for {emergency_type}"
        )

        return recommendations

    async def batch_generate_recommendations(
        self, case_scenarios: list[CaseScenario], max_concurrent: int = 5
    ) -> list[RecommendationResult]:
        """
        Generate recommendations for multiple case scenarios concurrently

        Args:
            case_scenarios: List of case scenarios to process
            max_concurrent: Maximum concurrent processing

        Returns:
            List of RecommendationResult objects
        """
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        async def generate_with_semaphore(scenario: CaseScenario):
            async with semaphore:
                return await self.generate_recommendations(scenario)

        # Process all scenarios concurrently
        tasks = [generate_with_semaphore(scenario) for scenario in case_scenarios]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions and return valid results
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch generation failed for scenario {i}: {str(result)}")
                # Create minimal result for failed scenario
                valid_results.append(
                    RecommendationResult(
                        recommendations=[],
                        case_id=f"failed_scenario_{i}",
                        generated_at=datetime.utcnow(),
                        evidence_summary={"error": str(result)},
                        ragnostic_context={"error": str(result)},
                        overall_confidence=0.0,
                    )
                )
            else:
                valid_results.append(result)

        logger.info(
            f"Batch generated recommendations for {len(case_scenarios)} scenarios"
        )
        return valid_results

    def get_cache_stats(self) -> dict[str, Any]:
        """Get recommendation cache statistics"""
        now = datetime.utcnow()
        active_cache_entries = sum(
            1 for case_id, expiry in self._cache_expiry.items() if now < expiry
        )

        return {
            "total_cache_entries": len(self._recommendation_cache),
            "active_cache_entries": active_cache_entries,
            "expired_cache_entries": len(self._recommendation_cache)
            - active_cache_entries,
            "cache_ttl_hours": self._cache_ttl.total_seconds() / 3600,
        }

    def clear_cache(self):
        """Clear the recommendation cache"""
        self._recommendation_cache.clear()
        self._cache_expiry.clear()
        logger.info("Clinical recommendation cache cleared")

    async def health_check(self) -> dict[str, Any]:
        """Check health of the clinical recommendation engine"""
        try:
            # Test RAGnostic connectivity
            ragnostic_health = await self.ragnostic_client.health_check()

            # Test OpenAI connectivity with minimal request
            try:
                await openai.ChatCompletion.acreate(
                    model=self.openai_model,
                    messages=[{"role": "user", "content": "Test"}],
                    max_tokens=5,
                )
                openai_healthy = True
            except Exception as e:
                openai_healthy = False
                logger.error(f"OpenAI health check failed: {str(e)}")

            return {
                "status": "healthy"
                if ragnostic_health.get("status") == "healthy" and openai_healthy
                else "degraded",
                "ragnostic_status": ragnostic_health,
                "openai_status": "healthy" if openai_healthy else "unhealthy",
                "cache_stats": self.get_cache_stats(),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def close(self):
        """Clean up resources"""
        if self.ragnostic_client:
            await self.ragnostic_client.close()
        self.clear_cache()
        logger.info("Clinical Recommendation Engine closed")
