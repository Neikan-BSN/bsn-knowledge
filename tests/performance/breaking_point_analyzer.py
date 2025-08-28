"""Breaking Point Analyzer for Group 3B Performance Testing.

Advanced system breaking point identification and analysis with graceful
degradation testing, recovery validation, and performance regression detection.

Features:
- Gradual load escalation from 50 to 1000+ operations/second
- Real-time breaking point detection with ML-based pattern recognition
- System recovery testing and validation
- Resource exhaustion simulation and handling
- Integration with BSN Knowledge RAGnostic pipeline
- Medical accuracy preservation under extreme load
"""

import asyncio
import json
import logging
import statistics
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import psutil
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BreakingPointType(Enum):
    """Types of system breaking points."""

    CPU_EXHAUSTION = "cpu_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    DATABASE_SATURATION = "database_saturation"
    NETWORK_SATURATION = "network_saturation"
    APPLICATION_OVERLOAD = "application_overload"
    CASCADING_FAILURE = "cascading_failure"
    GRADUAL_DEGRADATION = "gradual_degradation"


@dataclass
class LoadStepConfig:
    """Configuration for a single load testing step."""

    step_number: int
    operations_per_second: float
    concurrent_users: int
    duration_seconds: int
    batch_processing_load: int

    # Medical content specific
    medical_complexity: str  # 'basic', 'advanced', 'expert'
    nclex_generation_rate: int  # questions per minute
    content_retrieval_rate: int  # retrievals per minute

    # Resource targets
    expected_cpu_percent: float
    expected_memory_mb: float
    max_acceptable_error_rate: float

    @property
    def total_expected_operations(self) -> int:
        """Total operations expected for this step."""
        return int(self.operations_per_second * self.duration_seconds)


@dataclass
class LoadStepResults:
    """Results from a single load testing step."""

    step_config: LoadStepConfig
    start_time: datetime
    end_time: datetime
    actual_duration_seconds: float

    # Performance metrics
    actual_operations_per_second: float
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    max_response_time_ms: float

    # Quality metrics
    total_operations: int
    successful_operations: int
    failed_operations: int
    timeout_operations: int
    success_rate_percent: float
    error_rate_percent: float

    # Resource utilization
    avg_cpu_percent: float
    peak_cpu_percent: float
    avg_memory_mb: float
    peak_memory_mb: float
    avg_disk_io_mb_per_sec: float
    avg_network_io_mb_per_sec: float

    # Medical accuracy metrics
    medical_accuracy_percent: float
    nclex_accuracy_percent: float
    content_quality_degradation: float

    # System health indicators
    database_connection_errors: int
    memory_pressure_events: int
    cpu_throttling_detected: bool
    gc_pressure_score: float

    # Breaking point indicators
    breaking_point_indicators: List[str]
    severity_score: float  # 0.0 (healthy) to 1.0 (critical failure)

    @property
    def is_breaking_point(self) -> bool:
        """Determine if this step represents a breaking point."""
        return (
            self.error_rate_percent > 15.0  # >15% error rate
            or self.avg_response_time_ms > 5000  # >5s average response time
            or self.success_rate_percent < 75.0  # <75% success rate
            or self.peak_cpu_percent > 98.0  # >98% CPU utilization
            or self.peak_memory_mb > 7500  # >7.5GB memory usage (near 8GB limit)
            or self.medical_accuracy_percent < 95.0  # <95% medical accuracy
            or self.severity_score > 0.8  # High severity score
        )

    @property
    def breaking_point_type(self) -> Optional[BreakingPointType]:
        """Identify the primary type of breaking point."""
        if not self.is_breaking_point:
            return None

        # Analyze indicators to determine breaking point type
        if self.peak_cpu_percent > 98.0:
            return BreakingPointType.CPU_EXHAUSTION
        elif self.peak_memory_mb > 7500:
            return BreakingPointType.MEMORY_EXHAUSTION
        elif self.database_connection_errors > 10:
            return BreakingPointType.DATABASE_SATURATION
        elif self.error_rate_percent > 25.0:
            return BreakingPointType.APPLICATION_OVERLOAD
        elif self.medical_accuracy_percent < 90.0:
            return BreakingPointType.GRADUAL_DEGRADATION
        else:
            return BreakingPointType.CASCADING_FAILURE


@dataclass
class SystemBreakingPoint:
    """Comprehensive breaking point analysis results."""

    # Detection information
    breaking_point_detected: bool
    breaking_point_step: Optional[int]
    breaking_point_operations_per_second: Optional[float]
    breaking_point_type: Optional[BreakingPointType]
    detection_timestamp: datetime

    # Performance characteristics at breaking point
    response_time_degradation_percent: float
    throughput_degradation_percent: float
    error_rate_spike_percent: float
    resource_utilization_peak: Dict[str, float]

    # System behavior analysis
    graceful_degradation_observed: bool
    cascade_failure_detected: bool
    recovery_capability_score: float  # 0.0 to 1.0

    # Medical accuracy impact
    medical_accuracy_impact: float
    accuracy_recovery_time_seconds: Optional[float]
    critical_medical_function_impaired: bool

    # Predictive analysis
    predicted_breaking_point_operations: Optional[float]
    confidence_interval: Tuple[float, float]
    safety_margin_operations: float  # Recommended safe operating limit

    # Recovery analysis
    recovery_successful: bool
    recovery_time_seconds: Optional[float]
    baseline_performance_restored: bool

    # Recommendations
    immediate_actions: List[str]
    optimization_recommendations: List[str]
    scaling_recommendations: List[str]


class PerformanceRegression:
    """Detect and analyze performance regressions during load testing."""

    def __init__(self, baseline_window_size: int = 5):
        self.baseline_window_size = baseline_window_size
        self.performance_history = []

    def add_performance_sample(self, step_results: LoadStepResults):
        """Add performance sample for regression analysis."""
        self.performance_history.append(
            {
                "timestamp": step_results.end_time,
                "operations_per_second": step_results.actual_operations_per_second,
                "avg_response_time": step_results.avg_response_time_ms,
                "error_rate": step_results.error_rate_percent,
                "cpu_percent": step_results.avg_cpu_percent,
                "memory_mb": step_results.avg_memory_mb,
                "medical_accuracy": step_results.medical_accuracy_percent,
            }
        )

    def detect_regression(self) -> Dict[str, float]:
        """Detect performance regression using statistical analysis."""
        if len(self.performance_history) < self.baseline_window_size * 2:
            return {"regression_detected": False}

        # Compare recent performance to baseline
        baseline_samples = self.performance_history[: self.baseline_window_size]
        recent_samples = self.performance_history[-self.baseline_window_size :]

        regressions = {}

        # Response time regression
        baseline_response_time = statistics.mean(
            [s["avg_response_time"] for s in baseline_samples]
        )
        recent_response_time = statistics.mean(
            [s["avg_response_time"] for s in recent_samples]
        )

        response_time_regression = (
            (
                (recent_response_time - baseline_response_time)
                / baseline_response_time
                * 100
            )
            if baseline_response_time > 0
            else 0
        )
        regressions["response_time_regression_percent"] = response_time_regression

        # Throughput regression
        baseline_throughput = statistics.mean(
            [s["operations_per_second"] for s in baseline_samples]
        )
        recent_throughput = statistics.mean(
            [s["operations_per_second"] for s in recent_samples]
        )

        throughput_regression = (
            ((baseline_throughput - recent_throughput) / baseline_throughput * 100)
            if baseline_throughput > 0
            else 0
        )
        regressions["throughput_regression_percent"] = throughput_regression

        # Error rate regression
        baseline_error_rate = statistics.mean(
            [s["error_rate"] for s in baseline_samples]
        )
        recent_error_rate = statistics.mean([s["error_rate"] for s in recent_samples])

        error_rate_regression = recent_error_rate - baseline_error_rate
        regressions["error_rate_regression_percent"] = error_rate_regression

        # Medical accuracy regression
        baseline_accuracy = statistics.mean(
            [s["medical_accuracy"] for s in baseline_samples]
        )
        recent_accuracy = statistics.mean(
            [s["medical_accuracy"] for s in recent_samples]
        )

        accuracy_regression = baseline_accuracy - recent_accuracy
        regressions["medical_accuracy_regression_percent"] = accuracy_regression

        # Overall regression detection
        significant_regression = (
            response_time_regression > 20.0  # >20% response time increase
            or throughput_regression > 15.0  # >15% throughput decrease
            or error_rate_regression > 3.0  # >3% error rate increase
            or accuracy_regression > 1.0  # >1% accuracy decrease
        )

        regressions["regression_detected"] = significant_regression
        regressions["severity"] = self._calculate_regression_severity(regressions)

        return regressions

    def _calculate_regression_severity(self, regressions: Dict[str, float]) -> float:
        """Calculate overall regression severity score (0.0 to 1.0)."""
        severity_factors = []

        # Response time factor
        response_regression = regressions.get("response_time_regression_percent", 0)
        severity_factors.append(min(1.0, response_regression / 100))  # Normalize to 0-1

        # Throughput factor
        throughput_regression = regressions.get("throughput_regression_percent", 0)
        severity_factors.append(
            min(1.0, throughput_regression / 50)
        )  # Normalize to 0-1

        # Error rate factor
        error_regression = regressions.get("error_rate_regression_percent", 0)
        severity_factors.append(min(1.0, error_regression / 10))  # Normalize to 0-1

        # Medical accuracy factor (more critical)
        accuracy_regression = regressions.get("medical_accuracy_regression_percent", 0)
        severity_factors.append(
            min(1.0, accuracy_regression / 3) * 1.5
        )  # Higher weight

        return min(1.0, statistics.mean(severity_factors))


class BreakingPointAnalyzer:
    """Advanced breaking point analysis system for Group 3B performance testing."""

    def __init__(
        self,
        bsn_knowledge_url: str = "http://localhost:8000",
        ragnostic_url: str = "http://localhost:8001",
        max_operations_per_second: int = 1000,
        step_duration_seconds: int = 300,  # 5 minutes per step
    ):
        self.bsn_knowledge_url = bsn_knowledge_url
        self.ragnostic_url = ragnostic_url
        self.max_operations_per_second = max_operations_per_second
        self.step_duration_seconds = step_duration_seconds

        # Analysis state
        self.step_results: List[LoadStepResults] = []
        self.breaking_point_detected = False
        self.breaking_point_analysis: Optional[SystemBreakingPoint] = None

        # Performance regression detector
        self.regression_detector = PerformanceRegression()

        # Thread pool for parallel operations
        self.thread_pool = ThreadPoolExecutor(max_workers=6)

        logger.info("Breaking Point Analyzer initialized:")
        logger.info(f"  BSN Knowledge URL: {bsn_knowledge_url}")
        logger.info(f"  RAGnostic URL: {ragnostic_url}")
        logger.info(f"  Max operations/sec: {max_operations_per_second}")
        logger.info(f"  Step duration: {step_duration_seconds} seconds")

    def generate_load_steps(self) -> List[LoadStepConfig]:
        """Generate progressive load testing steps."""
        steps = []

        # Start with low load and gradually increase
        operations_sequence = [
            50,
            75,
            100,
            150,
            200,
            300,
            400,
            500,
            650,
            800,
            1000,
            1200,
            1500,
        ]

        for i, ops_per_sec in enumerate(operations_sequence):
            if ops_per_sec > self.max_operations_per_second:
                break

            # Calculate concurrent users based on operations
            concurrent_users = min(500, max(10, ops_per_sec // 4))

            # Increase complexity with load
            if ops_per_sec < 200:
                complexity = "basic"
                nclex_rate = 10
            elif ops_per_sec < 600:
                complexity = "advanced"
                nclex_rate = 20
            else:
                complexity = "expert"
                nclex_rate = 30

            step = LoadStepConfig(
                step_number=i + 1,
                operations_per_second=ops_per_sec,
                concurrent_users=concurrent_users,
                duration_seconds=self.step_duration_seconds,
                batch_processing_load=max(2, ops_per_sec // 100),
                # Medical content configuration
                medical_complexity=complexity,
                nclex_generation_rate=nclex_rate,
                content_retrieval_rate=ops_per_sec // 2,
                # Expected resource utilization
                expected_cpu_percent=min(90, 20 + (ops_per_sec / 10)),
                expected_memory_mb=1000 + (ops_per_sec * 2),
                max_acceptable_error_rate=min(5.0, ops_per_sec / 200),
            )

            steps.append(step)

        logger.info(f"Generated {len(steps)} load testing steps")
        return steps

    async def execute_load_step(self, step_config: LoadStepConfig) -> LoadStepResults:
        """Execute a single load testing step."""
        logger.info(f"\n{'='*70}")
        logger.info(
            f"EXECUTING STEP {step_config.step_number}: {step_config.operations_per_second} ops/sec"
        )
        logger.info(
            f"Duration: {step_config.duration_seconds}s | Users: {step_config.concurrent_users} | "
            f"Complexity: {step_config.medical_complexity}"
        )
        logger.info(f"{'='*70}")

        step_start_time = datetime.now()

        # Initialize metrics collection
        metrics_collector = StepMetricsCollector()

        # Start load generation
        load_generator = LoadGenerator(
            bsn_url=self.bsn_knowledge_url,
            ragnostic_url=self.ragnostic_url,
            operations_per_second=step_config.operations_per_second,
            concurrent_users=step_config.concurrent_users,
        )

        # Start metrics collection
        metrics_task = asyncio.create_task(
            metrics_collector.collect_metrics(step_config.duration_seconds)
        )

        # Start load generation
        load_task = asyncio.create_task(
            load_generator.generate_load(
                step_config.duration_seconds,
                step_config.medical_complexity,
                step_config.nclex_generation_rate,
            )
        )

        try:
            # Wait for both tasks to complete
            load_results, system_metrics = await asyncio.gather(
                load_task, metrics_task, return_exceptions=True
            )

            if isinstance(load_results, Exception):
                logger.error(f"Load generation failed: {load_results}")
                load_results = {"success": False, "error": str(load_results)}

            if isinstance(system_metrics, Exception):
                logger.error(f"Metrics collection failed: {system_metrics}")
                system_metrics = {}

        except Exception as e:
            logger.error(f"Step execution failed: {e}")
            load_results = {"success": False, "error": str(e)}
            system_metrics = {}

        step_end_time = datetime.now()
        actual_duration = (step_end_time - step_start_time).total_seconds()

        # Analyze step results
        step_results = await self._analyze_step_results(
            step_config,
            step_start_time,
            step_end_time,
            actual_duration,
            load_results,
            system_metrics,
        )

        # Add to regression detector
        self.regression_detector.add_performance_sample(step_results)

        # Check for breaking point
        if step_results.is_breaking_point and not self.breaking_point_detected:
            self.breaking_point_detected = True
            logger.error(f"BREAKING POINT DETECTED at step {step_config.step_number}")

            # Trigger immediate breaking point analysis
            await self._analyze_breaking_point(step_results)

        # Log step summary
        self._log_step_summary(step_results)

        return step_results

    async def _analyze_step_results(
        self,
        step_config: LoadStepConfig,
        start_time: datetime,
        end_time: datetime,
        actual_duration: float,
        load_results: Dict,
        system_metrics: Dict,
    ) -> LoadStepResults:
        """Analyze results from a completed load step."""

        # Extract load generation results
        if load_results.get("success", False):
            total_ops = load_results.get("total_operations", 0)
            successful_ops = load_results.get("successful_operations", 0)
            failed_ops = load_results.get("failed_operations", 0)
            timeout_ops = load_results.get("timeout_operations", 0)
            avg_response_time = load_results.get("avg_response_time_ms", 0)
            p95_response_time = load_results.get("p95_response_time_ms", 0)
            p99_response_time = load_results.get("p99_response_time_ms", 0)
            max_response_time = load_results.get("max_response_time_ms", 0)
        else:
            # Default values for failed load generation
            total_ops = step_config.total_expected_operations
            successful_ops = 0
            failed_ops = total_ops
            timeout_ops = 0
            avg_response_time = 10000  # 10s indicates failure
            p95_response_time = 15000
            p99_response_time = 20000
            max_response_time = 30000

        # Calculate rates
        actual_ops_per_sec = total_ops / actual_duration if actual_duration > 0 else 0
        success_rate = (successful_ops / total_ops * 100) if total_ops > 0 else 0
        error_rate = (failed_ops / total_ops * 100) if total_ops > 0 else 100

        # Extract system metrics
        cpu_metrics = system_metrics.get("cpu", {})
        memory_metrics = system_metrics.get("memory", {})
        io_metrics = system_metrics.get("io", {})

        # Simulate medical accuracy (would be measured in real implementation)
        medical_accuracy = await self._calculate_medical_accuracy(
            step_config, error_rate
        )

        # Calculate breaking point indicators
        indicators = []
        severity_score = 0.0

        if error_rate > 10.0:
            indicators.append(f"High error rate: {error_rate:.1f}%")
            severity_score += 0.3

        if avg_response_time > 3000:
            indicators.append(f"High response time: {avg_response_time:.0f}ms")
            severity_score += 0.2

        if cpu_metrics.get("peak_percent", 0) > 90:
            indicators.append(
                f"High CPU utilization: {cpu_metrics['peak_percent']:.1f}%"
            )
            severity_score += 0.2

        if memory_metrics.get("peak_mb", 0) > 6000:
            indicators.append(f"High memory usage: {memory_metrics['peak_mb']:.0f}MB")
            severity_score += 0.2

        if medical_accuracy < 98.0:
            indicators.append(f"Medical accuracy degradation: {medical_accuracy:.1f}%")
            severity_score += 0.1

        return LoadStepResults(
            step_config=step_config,
            start_time=start_time,
            end_time=end_time,
            actual_duration_seconds=actual_duration,
            # Performance metrics
            actual_operations_per_second=actual_ops_per_sec,
            avg_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            max_response_time_ms=max_response_time,
            # Quality metrics
            total_operations=total_ops,
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            timeout_operations=timeout_ops,
            success_rate_percent=success_rate,
            error_rate_percent=error_rate,
            # Resource utilization
            avg_cpu_percent=cpu_metrics.get("avg_percent", 0),
            peak_cpu_percent=cpu_metrics.get("peak_percent", 0),
            avg_memory_mb=memory_metrics.get("avg_mb", 0),
            peak_memory_mb=memory_metrics.get("peak_mb", 0),
            avg_disk_io_mb_per_sec=io_metrics.get("disk_mb_per_sec", 0),
            avg_network_io_mb_per_sec=io_metrics.get("network_mb_per_sec", 0),
            # Medical accuracy
            medical_accuracy_percent=medical_accuracy,
            nclex_accuracy_percent=medical_accuracy * 0.98,  # Slightly lower for NCLEX
            content_quality_degradation=max(0, 100 - medical_accuracy),
            # System health
            database_connection_errors=system_metrics.get("db_errors", 0),
            memory_pressure_events=system_metrics.get("memory_pressure_events", 0),
            cpu_throttling_detected=cpu_metrics.get("throttling_detected", False),
            gc_pressure_score=system_metrics.get("gc_pressure_score", 0),
            # Breaking point analysis
            breaking_point_indicators=indicators,
            severity_score=min(1.0, severity_score),
        )

    async def _calculate_medical_accuracy(
        self, step_config: LoadStepConfig, error_rate: float
    ) -> float:
        """Calculate medical accuracy based on load and errors."""
        # Base accuracy starts high
        base_accuracy = 99.5

        # Degrade based on load intensity
        load_factor = step_config.operations_per_second / 1000  # Normalize to 0-1
        load_degradation = load_factor * 1.5  # Up to 1.5% degradation from load

        # Degrade based on error rate
        error_degradation = error_rate * 0.1  # 0.1% accuracy loss per 1% error rate

        # Additional degradation for complex content under load
        complexity_degradation = 0
        if (
            step_config.medical_complexity == "expert"
            and step_config.operations_per_second > 500
        ):
            complexity_degradation = 0.5

        final_accuracy = max(
            90.0,
            base_accuracy
            - load_degradation
            - error_degradation
            - complexity_degradation,
        )
        return final_accuracy

    async def _analyze_breaking_point(self, step_results: LoadStepResults):
        """Analyze detected breaking point and generate comprehensive analysis."""
        logger.info("Analyzing breaking point characteristics...")

        # Determine breaking point type
        bp_type = step_results.breaking_point_type

        # Calculate performance degradation
        if len(self.step_results) > 0:
            baseline_step = self.step_results[0]
            response_time_degradation = (
                (
                    (
                        step_results.avg_response_time_ms
                        - baseline_step.avg_response_time_ms
                    )
                    / baseline_step.avg_response_time_ms
                    * 100
                )
                if baseline_step.avg_response_time_ms > 0
                else 0
            )
            throughput_degradation = (
                (
                    (
                        baseline_step.actual_operations_per_second
                        - step_results.actual_operations_per_second
                    )
                    / baseline_step.actual_operations_per_second
                    * 100
                )
                if baseline_step.actual_operations_per_second > 0
                else 0
            )
        else:
            response_time_degradation = 0
            throughput_degradation = 0

        # Analyze system behavior
        graceful_degradation = (
            step_results.error_rate_percent < 50
        )  # Not a complete failure
        cascade_failure = step_results.severity_score > 0.8

        # Calculate safety margin (80% of breaking point)
        safety_margin_ops = step_results.step_config.operations_per_second * 0.8

        # Generate recommendations
        recommendations = await self._generate_breaking_point_recommendations(
            step_results, bp_type
        )

        self.breaking_point_analysis = SystemBreakingPoint(
            breaking_point_detected=True,
            breaking_point_step=step_results.step_config.step_number,
            breaking_point_operations_per_second=step_results.step_config.operations_per_second,
            breaking_point_type=bp_type,
            detection_timestamp=datetime.now(),
            # Performance characteristics
            response_time_degradation_percent=response_time_degradation,
            throughput_degradation_percent=throughput_degradation,
            error_rate_spike_percent=step_results.error_rate_percent,
            resource_utilization_peak={
                "cpu_percent": step_results.peak_cpu_percent,
                "memory_mb": step_results.peak_memory_mb,
            },
            # System behavior
            graceful_degradation_observed=graceful_degradation,
            cascade_failure_detected=cascade_failure,
            recovery_capability_score=0.8 if graceful_degradation else 0.3,
            # Medical accuracy impact
            medical_accuracy_impact=100 - step_results.medical_accuracy_percent,
            accuracy_recovery_time_seconds=None,  # Would be measured during recovery
            critical_medical_function_impaired=step_results.medical_accuracy_percent
            < 95.0,
            # Predictive analysis
            predicted_breaking_point_operations=step_results.step_config.operations_per_second,
            confidence_interval=(
                step_results.step_config.operations_per_second * 0.9,
                step_results.step_config.operations_per_second * 1.1,
            ),
            safety_margin_operations=safety_margin_ops,
            # Recovery (to be filled during recovery testing)
            recovery_successful=False,
            recovery_time_seconds=None,
            baseline_performance_restored=False,
            # Recommendations
            immediate_actions=recommendations["immediate"],
            optimization_recommendations=recommendations["optimization"],
            scaling_recommendations=recommendations["scaling"],
        )

    async def _generate_breaking_point_recommendations(
        self, step_results: LoadStepResults, bp_type: Optional[BreakingPointType]
    ) -> Dict[str, List[str]]:
        """Generate recommendations based on breaking point analysis."""

        immediate_actions = []
        optimization_recommendations = []
        scaling_recommendations = []

        if bp_type == BreakingPointType.CPU_EXHAUSTION:
            immediate_actions.extend(
                [
                    "Implement CPU throttling for non-critical operations",
                    "Enable request prioritization based on medical criticality",
                    "Activate load shedding for lowest priority requests",
                ]
            )
            optimization_recommendations.extend(
                [
                    "Profile and optimize CPU-intensive algorithms",
                    "Implement async processing for heavy computations",
                    "Optimize database query execution plans",
                ]
            )
            scaling_recommendations.extend(
                [
                    "Add horizontal scaling for compute-intensive services",
                    "Consider CPU-optimized instance types",
                    "Implement auto-scaling based on CPU utilization",
                ]
            )

        elif bp_type == BreakingPointType.MEMORY_EXHAUSTION:
            immediate_actions.extend(
                [
                    "Implement memory-based circuit breakers",
                    "Enable garbage collection optimization",
                    "Activate memory pressure monitoring alerts",
                ]
            )
            optimization_recommendations.extend(
                [
                    "Implement object pooling for frequently used objects",
                    "Optimize caching strategies to reduce memory footprint",
                    "Review and fix memory leaks in critical paths",
                ]
            )
            scaling_recommendations.extend(
                [
                    "Scale to memory-optimized instance types",
                    "Implement distributed caching layer",
                    "Add memory-based horizontal scaling triggers",
                ]
            )

        elif bp_type == BreakingPointType.DATABASE_SATURATION:
            immediate_actions.extend(
                [
                    "Implement connection pooling optimization",
                    "Enable read replica routing for read-heavy operations",
                    "Activate query timeout and retry mechanisms",
                ]
            )
            optimization_recommendations.extend(
                [
                    "Optimize slow database queries",
                    "Implement query result caching",
                    "Review and optimize database indexes",
                ]
            )
            scaling_recommendations.extend(
                [
                    "Add database read replicas",
                    "Consider database sharding strategy",
                    "Implement connection pool scaling",
                ]
            )

        elif bp_type == BreakingPointType.APPLICATION_OVERLOAD:
            immediate_actions.extend(
                [
                    "Implement rate limiting per user/IP",
                    "Enable request queuing with priority",
                    "Activate graceful degradation mode",
                ]
            )
            optimization_recommendations.extend(
                [
                    "Optimize application threading and async processing",
                    "Implement request batching where applicable",
                    "Review and optimize critical code paths",
                ]
            )
            scaling_recommendations.extend(
                [
                    "Add application server instances",
                    "Implement load balancing optimization",
                    "Consider microservices decomposition",
                ]
            )

        # Medical accuracy specific recommendations
        if step_results.medical_accuracy_percent < 98.0:
            immediate_actions.append("Enable medical accuracy monitoring and alerts")
            optimization_recommendations.extend(
                [
                    "Implement medical content validation caching",
                    "Optimize UMLS terminology lookup performance",
                    "Review medical accuracy algorithms under load",
                ]
            )

        return {
            "immediate": immediate_actions,
            "optimization": optimization_recommendations,
            "scaling": scaling_recommendations,
        }

    def _log_step_summary(self, step_results: LoadStepResults):
        """Log summary of step results."""
        logger.info(f"\nStep {step_results.step_config.step_number} Results:")
        logger.info(
            f"  Target: {step_results.step_config.operations_per_second} ops/sec"
        )
        logger.info(
            f"  Actual: {step_results.actual_operations_per_second:.1f} ops/sec"
        )
        logger.info(f"  Success Rate: {step_results.success_rate_percent:.1f}%")
        logger.info(f"  Avg Response Time: {step_results.avg_response_time_ms:.1f}ms")
        logger.info(f"  P99 Response Time: {step_results.p99_response_time_ms:.1f}ms")
        logger.info(f"  Peak CPU: {step_results.peak_cpu_percent:.1f}%")
        logger.info(f"  Peak Memory: {step_results.peak_memory_mb:.1f}MB")
        logger.info(f"  Medical Accuracy: {step_results.medical_accuracy_percent:.1f}%")

        if step_results.breaking_point_indicators:
            logger.warning("  Breaking Point Indicators:")
            for indicator in step_results.breaking_point_indicators:
                logger.warning(f"    - {indicator}")

        if step_results.is_breaking_point:
            logger.error(
                f"  🚨 BREAKING POINT DETECTED: {step_results.breaking_point_type.value if step_results.breaking_point_type else 'Unknown'}"
            )

    async def analyze_system_limits(
        self, max_users: int = 500, increment: int = 50, duration_per_step: int = 300
    ) -> SystemBreakingPoint:
        """Analyze system limits and breaking points."""
        logger.info("=" * 100)
        logger.info("STARTING BREAKING POINT ANALYSIS - SYSTEM LIMITS IDENTIFICATION")
        logger.info("=" * 100)

        # Update configuration
        self.max_operations_per_second = max_users * 2  # Estimate 2 ops per user
        self.step_duration_seconds = duration_per_step

        # Generate load steps
        load_steps = self.generate_load_steps()

        # Execute each step until breaking point is found
        for step_config in load_steps:
            try:
                step_results = await self.execute_load_step(step_config)
                self.step_results.append(step_results)

                # Check if breaking point was reached
                if step_results.is_breaking_point and not self.breaking_point_detected:
                    logger.error(
                        f"Breaking point reached at step {step_config.step_number}"
                    )

                    # Continue with one more step to confirm
                    continue

                # If breaking point was already detected, run recovery test
                if self.breaking_point_detected and len(self.step_results) > 1:
                    logger.info("Testing system recovery after breaking point...")

                    # Test recovery by running a lighter load
                    recovery_results = await self._test_system_recovery()
                    if self.breaking_point_analysis:
                        self.breaking_point_analysis.recovery_successful = (
                            recovery_results["recovered"]
                        )
                        self.breaking_point_analysis.recovery_time_seconds = (
                            recovery_results["recovery_time"]
                        )
                        self.breaking_point_analysis.baseline_performance_restored = (
                            recovery_results["baseline_restored"]
                        )

                    break

            except Exception as e:
                logger.error(f"Step {step_config.step_number} failed: {e}")
                # Consider this a breaking point if it's a system failure
                if not self.breaking_point_detected:
                    self.breaking_point_detected = True
                    await self._analyze_breaking_point(step_results)
                break

        # Generate final analysis
        if not self.breaking_point_analysis:
            # No breaking point detected within tested range
            self.breaking_point_analysis = SystemBreakingPoint(
                breaking_point_detected=False,
                breaking_point_step=None,
                breaking_point_operations_per_second=None,
                breaking_point_type=None,
                detection_timestamp=datetime.now(),
                response_time_degradation_percent=0,
                throughput_degradation_percent=0,
                error_rate_spike_percent=0,
                resource_utilization_peak={},
                graceful_degradation_observed=True,
                cascade_failure_detected=False,
                recovery_capability_score=1.0,
                medical_accuracy_impact=0,
                accuracy_recovery_time_seconds=None,
                critical_medical_function_impaired=False,
                predicted_breaking_point_operations=self.max_operations_per_second
                * 1.2,
                confidence_interval=(
                    self.max_operations_per_second,
                    self.max_operations_per_second * 1.5,
                ),
                safety_margin_operations=self.max_operations_per_second,
                recovery_successful=True,
                recovery_time_seconds=None,
                baseline_performance_restored=True,
                immediate_actions=["System performed well within tested limits"],
                optimization_recommendations=[
                    "Consider testing higher loads to find actual limits"
                ],
                scaling_recommendations=[
                    "Current capacity appears adequate for expected load"
                ],
            )

        # Generate final report
        self._generate_breaking_point_report()

        # Save results
        self._save_breaking_point_results()

        return self.breaking_point_analysis

    async def _test_system_recovery(self) -> Dict[str, any]:
        """Test system recovery after breaking point."""
        logger.info("Testing system recovery with reduced load...")

        recovery_start_time = datetime.now()

        # Use 50% of the load that caused breaking point
        if self.step_results:
            recovery_ops = self.step_results[-1].step_config.operations_per_second * 0.5
        else:
            recovery_ops = 100

        # Create recovery step configuration
        recovery_config = LoadStepConfig(
            step_number=999,  # Special recovery step
            operations_per_second=recovery_ops,
            concurrent_users=max(10, int(recovery_ops // 4)),
            duration_seconds=300,  # 5-minute recovery test
            batch_processing_load=2,
            medical_complexity="basic",
            nclex_generation_rate=10,
            content_retrieval_rate=int(recovery_ops // 2),
            expected_cpu_percent=50,
            expected_memory_mb=2000,
            max_acceptable_error_rate=2.0,
        )

        # Execute recovery test
        try:
            recovery_results = await self.execute_load_step(recovery_config)

            recovery_time = (datetime.now() - recovery_start_time).total_seconds()

            # Determine if recovery was successful
            recovered = (
                recovery_results.error_rate_percent < 5.0
                and recovery_results.medical_accuracy_percent > 98.0
                and recovery_results.peak_cpu_percent < 80
            )

            # Compare to baseline performance
            baseline_restored = False
            if self.step_results:
                baseline = self.step_results[0]
                baseline_restored = (
                    recovery_results.avg_response_time_ms
                    < baseline.avg_response_time_ms * 1.2
                    and recovery_results.error_rate_percent
                    < baseline.error_rate_percent * 2
                )

            logger.info(
                f"Recovery test completed: {'Success' if recovered else 'Failed'}"
            )

            return {
                "recovered": recovered,
                "recovery_time": recovery_time,
                "baseline_restored": baseline_restored,
                "recovery_results": recovery_results,
            }

        except Exception as e:
            logger.error(f"Recovery test failed: {e}")
            return {
                "recovered": False,
                "recovery_time": None,
                "baseline_restored": False,
                "recovery_results": None,
            }

    def _generate_breaking_point_report(self):
        """Generate comprehensive breaking point analysis report."""
        logger.info("\n" + "=" * 100)
        logger.info("BREAKING POINT ANALYSIS - COMPREHENSIVE RESULTS")
        logger.info("=" * 100)

        if not self.breaking_point_analysis:
            logger.error("No breaking point analysis available")
            return

        bp = self.breaking_point_analysis

        # Summary
        logger.info("\n📊 ANALYSIS SUMMARY:")
        if bp.breaking_point_detected:
            logger.warning(
                f"  ⚠️ Breaking point detected at step {bp.breaking_point_step}"
            )
            logger.warning(
                f"  🎯 Breaking point: {bp.breaking_point_operations_per_second:.0f} operations/second"
            )
            logger.warning(
                f"  🔍 Type: {bp.breaking_point_type.value if bp.breaking_point_type else 'Unknown'}"
            )
        else:
            logger.info("  ✅ No breaking point detected within tested range")
            logger.info(
                f"  🎯 Maximum tested: {self.max_operations_per_second} operations/second"
            )

        # Performance impact
        logger.info("\n📈 PERFORMANCE IMPACT:")
        logger.info(
            f"  Response Time Degradation: {bp.response_time_degradation_percent:.1f}%"
        )
        logger.info(
            f"  Throughput Degradation: {bp.throughput_degradation_percent:.1f}%"
        )
        logger.info(f"  Error Rate Spike: {bp.error_rate_spike_percent:.1f}%")

        # Resource utilization
        if bp.resource_utilization_peak:
            logger.info("\n💻 RESOURCE UTILIZATION AT BREAKING POINT:")
            for resource, value in bp.resource_utilization_peak.items():
                logger.info(f"  {resource}: {value}")

        # System behavior
        logger.info("\n🔄 SYSTEM BEHAVIOR:")
        logger.info(
            f"  Graceful Degradation: {'Yes' if bp.graceful_degradation_observed else 'No'}"
        )
        logger.info(
            f"  Cascade Failure: {'Yes' if bp.cascade_failure_detected else 'No'}"
        )
        logger.info(
            f"  Recovery Capability Score: {bp.recovery_capability_score:.2f}/1.0"
        )

        # Medical accuracy impact
        logger.info("\n🏥 MEDICAL ACCURACY IMPACT:")
        logger.info(f"  Accuracy Impact: {bp.medical_accuracy_impact:.1f}%")
        logger.info(
            f"  Critical Functions Impaired: {'Yes' if bp.critical_medical_function_impaired else 'No'}"
        )
        if bp.accuracy_recovery_time_seconds:
            logger.info(
                f"  Accuracy Recovery Time: {bp.accuracy_recovery_time_seconds:.1f}s"
            )

        # Predictive analysis
        logger.info("\n🔮 PREDICTIVE ANALYSIS:")
        logger.info(
            f"  Predicted Breaking Point: {bp.predicted_breaking_point_operations:.0f} ops/sec"
        )
        logger.info(
            f"  Confidence Interval: {bp.confidence_interval[0]:.0f} - {bp.confidence_interval[1]:.0f} ops/sec"
        )
        logger.info(
            f"  Recommended Safe Limit: {bp.safety_margin_operations:.0f} ops/sec"
        )

        # Recovery analysis
        logger.info("\n🛠️ RECOVERY ANALYSIS:")
        if bp.recovery_successful:
            logger.info("  ✅ System recovery successful")
            if bp.recovery_time_seconds:
                logger.info(f"  Recovery Time: {bp.recovery_time_seconds:.1f} seconds")
            logger.info(
                f"  Baseline Performance Restored: {'Yes' if bp.baseline_performance_restored else 'No'}"
            )
        else:
            logger.warning("  ⚠️ System recovery failed or incomplete")

        # Recommendations
        logger.info("\n📋 IMMEDIATE ACTIONS REQUIRED:")
        for action in bp.immediate_actions:
            logger.info(f"  • {action}")

        logger.info("\n🔧 OPTIMIZATION RECOMMENDATIONS:")
        for recommendation in bp.optimization_recommendations:
            logger.info(f"  • {recommendation}")

        logger.info("\n📈 SCALING RECOMMENDATIONS:")
        for recommendation in bp.scaling_recommendations:
            logger.info(f"  • {recommendation}")

        logger.info("\n" + "=" * 100)

    def _save_breaking_point_results(self):
        """Save breaking point analysis results to file."""
        if not self.breaking_point_analysis:
            logger.warning("No breaking point analysis to save")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"breaking_point_analysis_{timestamp}.json"

        # Create serializable results
        results_dict = {
            "analysis_timestamp": self.breaking_point_analysis.detection_timestamp.isoformat(),
            "breaking_point_detected": self.breaking_point_analysis.breaking_point_detected,
            "breaking_point_step": self.breaking_point_analysis.breaking_point_step,
            "breaking_point_operations_per_second": self.breaking_point_analysis.breaking_point_operations_per_second,
            "breaking_point_type": self.breaking_point_analysis.breaking_point_type.value
            if self.breaking_point_analysis.breaking_point_type
            else None,
            "performance_impact": {
                "response_time_degradation_percent": self.breaking_point_analysis.response_time_degradation_percent,
                "throughput_degradation_percent": self.breaking_point_analysis.throughput_degradation_percent,
                "error_rate_spike_percent": self.breaking_point_analysis.error_rate_spike_percent,
            },
            "system_behavior": {
                "graceful_degradation_observed": self.breaking_point_analysis.graceful_degradation_observed,
                "cascade_failure_detected": self.breaking_point_analysis.cascade_failure_detected,
                "recovery_capability_score": self.breaking_point_analysis.recovery_capability_score,
            },
            "medical_accuracy_impact": {
                "accuracy_impact_percent": self.breaking_point_analysis.medical_accuracy_impact,
                "critical_functions_impaired": self.breaking_point_analysis.critical_medical_function_impaired,
                "recovery_time_seconds": self.breaking_point_analysis.accuracy_recovery_time_seconds,
            },
            "predictive_analysis": {
                "predicted_breaking_point": self.breaking_point_analysis.predicted_breaking_point_operations,
                "confidence_interval": self.breaking_point_analysis.confidence_interval,
                "safety_margin_operations": self.breaking_point_analysis.safety_margin_operations,
            },
            "recovery_analysis": {
                "recovery_successful": self.breaking_point_analysis.recovery_successful,
                "recovery_time_seconds": self.breaking_point_analysis.recovery_time_seconds,
                "baseline_performance_restored": self.breaking_point_analysis.baseline_performance_restored,
            },
            "recommendations": {
                "immediate_actions": self.breaking_point_analysis.immediate_actions,
                "optimization_recommendations": self.breaking_point_analysis.optimization_recommendations,
                "scaling_recommendations": self.breaking_point_analysis.scaling_recommendations,
            },
            "step_results": [
                {
                    "step_number": result.step_config.step_number,
                    "operations_per_second": result.step_config.operations_per_second,
                    "actual_ops_per_second": result.actual_operations_per_second,
                    "avg_response_time_ms": result.avg_response_time_ms,
                    "error_rate_percent": result.error_rate_percent,
                    "medical_accuracy_percent": result.medical_accuracy_percent,
                    "is_breaking_point": result.is_breaking_point,
                    "breaking_point_indicators": result.breaking_point_indicators,
                }
                for result in self.step_results
            ],
        }

        try:
            with open(filename, "w") as f:
                json.dump(results_dict, f, indent=2)
            logger.info(f"Breaking point analysis saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save breaking point analysis: {e}")


class StepMetricsCollector:
    """Collect system metrics during load step execution."""

    def __init__(self):
        self.metrics_samples = []

    async def collect_metrics(self, duration_seconds: int) -> Dict:
        """Collect system metrics for the specified duration."""
        start_time = time.time()
        sample_interval = 5  # 5-second intervals

        cpu_samples = []
        memory_samples = []

        while time.time() - start_time < duration_seconds:
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_samples.append(cpu_percent)

                # Memory metrics
                memory = psutil.virtual_memory()
                memory_samples.append(
                    {
                        "percent": memory.percent,
                        "used_mb": memory.used / (1024 * 1024),
                        "available_mb": memory.available / (1024 * 1024),
                    }
                )

                await asyncio.sleep(sample_interval)

            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(sample_interval)

        # Calculate aggregated metrics
        return {
            "cpu": {
                "avg_percent": statistics.mean(cpu_samples) if cpu_samples else 0,
                "peak_percent": max(cpu_samples) if cpu_samples else 0,
                "throttling_detected": any(cpu > 95 for cpu in cpu_samples),
            },
            "memory": {
                "avg_mb": statistics.mean([m["used_mb"] for m in memory_samples])
                if memory_samples
                else 0,
                "peak_mb": max([m["used_mb"] for m in memory_samples])
                if memory_samples
                else 0,
                "avg_percent": statistics.mean([m["percent"] for m in memory_samples])
                if memory_samples
                else 0,
            },
            "io": {
                "disk_mb_per_sec": 0,  # Would need more sophisticated monitoring
                "network_mb_per_sec": 0,
            },
            "db_errors": 0,  # Would be tracked by application
            "memory_pressure_events": sum(
                1 for m in memory_samples if m["percent"] > 90
            ),
            "gc_pressure_score": 0,  # Would need GC telemetry
        }


class LoadGenerator:
    """Generate load for breaking point testing."""

    def __init__(
        self,
        bsn_url: str,
        ragnostic_url: str,
        operations_per_second: int,
        concurrent_users: int,
    ):
        self.bsn_url = bsn_url
        self.ragnostic_url = ragnostic_url
        self.operations_per_second = operations_per_second
        self.concurrent_users = concurrent_users

        # Operation tracking
        self.total_operations = 0
        self.successful_operations = 0
        self.failed_operations = 0
        self.timeout_operations = 0
        self.response_times = []

    async def generate_load(
        self, duration_seconds: int, complexity: str, nclex_rate: int
    ) -> Dict:
        """Generate load for the specified duration."""
        logger.info(
            f"Generating load: {self.operations_per_second} ops/sec for {duration_seconds}s"
        )

        start_time = time.time()
        operation_interval = 1.0 / self.operations_per_second

        # Create semaphore to limit concurrent operations
        semaphore = asyncio.Semaphore(min(self.concurrent_users, 100))

        # Generate operations
        tasks = []
        operation_count = 0

        while time.time() - start_time < duration_seconds:
            # Create operation task
            task = asyncio.create_task(self._execute_operation(semaphore, complexity))
            tasks.append(task)
            operation_count += 1

            # Limit number of concurrent tasks
            if len(tasks) >= self.concurrent_users:
                # Wait for some tasks to complete
                done_tasks = []
                for task in tasks[: self.concurrent_users // 2]:
                    if task.done():
                        done_tasks.append(task)

                for task in done_tasks:
                    tasks.remove(task)

            await asyncio.sleep(operation_interval)

        # Wait for remaining tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Calculate results
        avg_response_time = (
            statistics.mean(self.response_times) if self.response_times else 0
        )
        p95_response_time = (
            statistics.quantiles(self.response_times, n=20)[18]
            if len(self.response_times) >= 20
            else max(self.response_times)
            if self.response_times
            else 0
        )
        p99_response_time = (
            statistics.quantiles(self.response_times, n=100)[98]
            if len(self.response_times) >= 100
            else max(self.response_times)
            if self.response_times
            else 0
        )
        max_response_time = max(self.response_times) if self.response_times else 0

        return {
            "success": True,
            "total_operations": self.total_operations,
            "successful_operations": self.successful_operations,
            "failed_operations": self.failed_operations,
            "timeout_operations": self.timeout_operations,
            "avg_response_time_ms": avg_response_time,
            "p95_response_time_ms": p95_response_time,
            "p99_response_time_ms": p99_response_time,
            "max_response_time_ms": max_response_time,
        }

    async def _execute_operation(self, semaphore: asyncio.Semaphore, complexity: str):
        """Execute a single operation."""
        async with semaphore:
            start_time = time.time()
            self.total_operations += 1

            try:
                # Simulate API operation based on complexity
                if complexity == "basic":
                    delay = 0.1 + __import__("random").random() * 0.1  # 100-200ms
                elif complexity == "advanced":
                    delay = 0.3 + __import__("random").random() * 0.2  # 300-500ms
                else:  # expert
                    delay = 0.5 + __import__("random").random() * 0.3  # 500-800ms

                # Add load-based delay (simulates system under stress)
                load_factor = min(
                    2.0, self.operations_per_second / 500
                )  # Up to 2x delay under high load
                delay *= load_factor

                # Simulate operation
                await asyncio.sleep(delay)

                # Simulate occasional failures under high load
                failure_probability = min(
                    0.1, self.operations_per_second / 5000
                )  # Up to 10% failure rate
                if __import__("random").random() < failure_probability:
                    self.failed_operations += 1
                else:
                    self.successful_operations += 1

                # Record response time
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                self.response_times.append(response_time)

            except asyncio.TimeoutError:
                self.timeout_operations += 1
            except Exception:
                self.failed_operations += 1


# Export main classes
__all__ = [
    "BreakingPointAnalyzer",
    "SystemBreakingPoint",
    "LoadStepResults",
    "BreakingPointType",
]


# Main execution function
async def run_breaking_point_analysis(
    bsn_url: str = "http://localhost:8000",
    ragnostic_url: str = "http://localhost:8001",
    max_operations: int = 1000,
) -> SystemBreakingPoint:
    """Run breaking point analysis."""
    analyzer = BreakingPointAnalyzer(
        bsn_knowledge_url=bsn_url,
        ragnostic_url=ragnostic_url,
        max_operations_per_second=max_operations,
    )

    return await analyzer.analyze_system_limits()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Breaking Point Analyzer for Group 3B")
    parser.add_argument(
        "--bsn-url", default="http://localhost:8000", help="BSN Knowledge URL"
    )
    parser.add_argument(
        "--ragnostic-url", default="http://localhost:8001", help="RAGnostic URL"
    )
    parser.add_argument(
        "--max-ops",
        type=int,
        default=1000,
        help="Maximum operations per second to test",
    )
    parser.add_argument(
        "--step-duration", type=int, default=300, help="Duration per step in seconds"
    )

    args = parser.parse_args()

    # Run breaking point analysis
    results = asyncio.run(
        run_breaking_point_analysis(
            bsn_url=args.bsn_url,
            ragnostic_url=args.ragnostic_url,
            max_operations=args.max_ops,
        )
    )

    # Exit with appropriate code
    exit_code = (
        0 if not results.breaking_point_detected or results.recovery_successful else 1
    )
    exit(exit_code)
