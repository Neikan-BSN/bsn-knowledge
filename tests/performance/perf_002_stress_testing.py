"""PERF-002: Stress Testing - Breaking Point Analysis.

Gradual load increase to identify system breaking points:
- Load progression: 50→100→200→500→1000 concurrent operations
- Resource monitoring: CPU, memory, database connections, network I/O
- Bottleneck identification and failure analysis
- Graceful degradation patterns documentation
- Breaking point identification >500 concurrent operations
"""

import asyncio
import logging
import statistics
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil
from locust.env import Environment

from breaking_point_test import StepResults
from locust_scenarios import MixedWorkloadUser
from performance_benchmarks import benchmark_manager
from ragnostic_batch_simulation import RAGnosticBatchSimulator, BATCH_SCENARIOS

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class StressTestConfiguration:
    """Configuration for stress testing scenarios."""

    load_progression: List[int]
    step_duration_seconds: int
    max_concurrent_operations: int
    breaking_point_threshold_error_rate: float
    breaking_point_threshold_response_time_ms: float
    resource_warning_cpu_percent: float
    resource_critical_cpu_percent: float
    resource_warning_memory_percent: float
    resource_critical_memory_percent: float


@dataclass
class StressTestResults:
    """Comprehensive stress testing results."""

    # Breaking Point Analysis
    breaking_point_detected: bool
    breaking_point_concurrent_operations: Optional[int]
    breaking_point_step_number: Optional[int]
    max_operations_tested: int

    # Performance Degradation
    baseline_response_time_ms: float
    peak_response_time_ms: float
    response_time_degradation_percent: float
    baseline_throughput_ops_per_sec: float
    minimum_throughput_ops_per_sec: float
    throughput_degradation_percent: float

    # Resource Utilization
    peak_cpu_utilization_percent: float
    peak_memory_utilization_percent: float
    cpu_bottleneck_detected: bool
    memory_bottleneck_detected: bool
    network_bottleneck_detected: bool
    database_bottleneck_detected: bool

    # Error Analysis
    error_rate_progression: List[float]
    failure_patterns: List[str]
    graceful_degradation_observed: bool

    # Scalability Analysis
    scalability_efficiency_score: float
    linear_scaling_deviation_percent: float

    # Recovery Analysis
    recovery_time_seconds: Optional[float]
    recovery_successful: bool

    # Test Configuration
    load_steps_executed: int
    total_test_duration_seconds: float
    configuration: StressTestConfiguration


class ComprehensiveStressTester:
    """Advanced stress testing with comprehensive bottleneck analysis."""

    def __init__(
        self,
        bsn_knowledge_url: str = "http://localhost:8000",
        ragnostic_url: str = "http://localhost:8001",
        config: Optional[StressTestConfiguration] = None,
    ):
        self.bsn_knowledge_url = bsn_knowledge_url
        self.ragnostic_url = ragnostic_url

        # Default configuration
        self.config = config or StressTestConfiguration(
            load_progression=[50, 100, 200, 300, 500, 750, 1000],
            step_duration_seconds=180,  # 3 minutes per step
            max_concurrent_operations=1000,
            breaking_point_threshold_error_rate=5.0,  # 5% error rate
            breaking_point_threshold_response_time_ms=5000,  # 5 second response time
            resource_warning_cpu_percent=70.0,
            resource_critical_cpu_percent=85.0,
            resource_warning_memory_percent=75.0,
            resource_critical_memory_percent=90.0,
        )

        self.step_results: List[StepResults] = []
        self.breaking_point_found = False
        self.breaking_point_step = None

        # Enhanced monitoring
        self.resource_monitor = EnhancedResourceMonitor()
        self.network_monitor = NetworkPerformanceMonitor()
        self.database_monitor = DatabasePerformanceMonitor()

        logger.info("Comprehensive Stress Tester initialized:")
        logger.info(f"  BSN Knowledge URL: {bsn_knowledge_url}")
        logger.info(f"  RAGnostic URL: {ragnostic_url}")
        logger.info(f"  Load progression: {self.config.load_progression}")
        logger.info(f"  Step duration: {self.config.step_duration_seconds}s")

    async def run_stress_test(self) -> StressTestResults:
        """Execute comprehensive stress testing with breaking point analysis."""
        logger.info("=" * 80)
        logger.info("STARTING PERF-002: STRESS TESTING - BREAKING POINT ANALYSIS")
        logger.info("=" * 80)

        start_time = time.time()

        # Start monitoring systems
        self.resource_monitor.start_monitoring()
        self.network_monitor.start_monitoring()
        self.database_monitor.start_monitoring()

        try:
            # Execute stress testing steps
            for step_num, concurrent_ops in enumerate(self.config.load_progression, 1):
                logger.info(f"\n{'='*60}")
                logger.info(
                    f"STRESS TEST STEP {step_num}: {concurrent_ops} concurrent operations"
                )
                logger.info(f"{'='*60}")

                step_result = await self._execute_stress_step(
                    step_number=step_num,
                    concurrent_operations=concurrent_ops,
                    duration_seconds=self.config.step_duration_seconds,
                )

                self.step_results.append(step_result)

                # Check for breaking point
                if self._is_breaking_point(step_result):
                    self.breaking_point_found = True
                    self.breaking_point_step = step_num
                    logger.error(
                        f"⚠️ BREAKING POINT DETECTED at {concurrent_ops} concurrent operations"
                    )

                    # Execute recovery analysis
                    recovery_result = await self._analyze_recovery_patterns(step_result)
                    step_result.recovery_analysis = recovery_result

                    # Stop testing after confirming breaking point
                    if step_num < len(self.config.load_progression):
                        logger.info("Stopping stress test - breaking point confirmed")
                    break

                # Brief pause between steps
                logger.info(
                    f"Step {step_num} completed. Waiting 30 seconds before next step..."
                )
                await asyncio.sleep(30)

        finally:
            # Stop monitoring
            self.resource_monitor.stop_monitoring()
            self.network_monitor.stop_monitoring()
            self.database_monitor.stop_monitoring()

        total_duration = time.time() - start_time

        # Analyze comprehensive results
        results = await self._analyze_stress_test_results(total_duration)

        # Generate detailed report
        self._generate_stress_test_report(results)

        # Record performance benchmarks
        self._record_stress_test_metrics(results)

        return results

    async def _execute_stress_step(
        self, step_number: int, concurrent_operations: int, duration_seconds: int
    ) -> StepResults:
        """Execute a single stress testing step with comprehensive monitoring."""

        # Calculate user distribution (70% API users, 30% batch operations)
        api_users = int(concurrent_operations * 0.7)
        batch_operations = max(1, int(concurrent_operations * 0.3))

        logger.info(
            f"Executing step with {api_users} API users + {batch_operations} batch operations"
        )

        # Start resource snapshot
        resource_snapshot_start = self.resource_monitor.take_snapshot()

        try:
            # Run combined load
            api_task = asyncio.create_task(
                self._run_api_stress_load(api_users, duration_seconds)
            )
            batch_task = asyncio.create_task(
                self._run_batch_stress_load(batch_operations, duration_seconds)
            )

            # Wait for both to complete
            api_results, batch_results = await asyncio.gather(api_task, batch_task)

            # Take end resource snapshot
            resource_snapshot_end = self.resource_monitor.take_snapshot()

            # Compile step results
            step_result = self._compile_step_results(
                step_number=step_number,
                concurrent_operations=concurrent_operations,
                api_results=api_results,
                batch_results=batch_results,
                resource_start=resource_snapshot_start,
                resource_end=resource_snapshot_end,
                duration_seconds=duration_seconds,
            )

            # Log step summary
            self._log_step_summary(step_result)

            return step_result

        except Exception as e:
            logger.error(f"Step {step_number} failed with error: {str(e)}")
            # Return failed step result
            return self._create_failed_step_result(
                step_number, concurrent_operations, str(e)
            )

    async def _run_api_stress_load(
        self, user_count: int, duration_seconds: int
    ) -> Dict:
        """Run API stress load using mixed workload users."""
        env = Environment(user_classes=[MixedWorkloadUser], host=self.bsn_knowledge_url)

        runner = env.create_local_runner()

        # Start with aggressive spawn rate for stress testing
        spawn_rate = min(20, user_count // 2)  # Spawn quickly to stress the system
        runner.start(user_count, spawn_rate=spawn_rate)

        # Run for specified duration
        await asyncio.sleep(duration_seconds)

        # Stop and collect stats
        runner.quit()
        stats = env.stats.total

        return {
            "user_count": user_count,
            "total_requests": stats.num_requests,
            "total_failures": stats.num_failures,
            "avg_response_time_ms": stats.avg_response_time,
            "p95_response_time_ms": stats.get_response_time_percentile(0.95),
            "p99_response_time_ms": stats.get_response_time_percentile(0.99),
            "requests_per_second": stats.total_rps,
            "error_rate_percent": (stats.num_failures / max(1, stats.num_requests))
            * 100,
            "success_rate_percent": (
                (stats.num_requests - stats.num_failures) / max(1, stats.num_requests)
            )
            * 100,
        }

    async def _run_batch_stress_load(
        self, batch_count: int, duration_seconds: int
    ) -> Dict:
        """Run batch processing stress load."""
        simulator = RAGnosticBatchSimulator(
            base_url=self.ragnostic_url, max_concurrent_jobs=batch_count
        )

        try:
            # Create aggressive batch scenarios
            batch_scenarios = []
            for i in range(batch_count):
                scenario = {
                    "job_type": BATCH_SCENARIOS[i % len(BATCH_SCENARIOS)]["job_type"],
                    "document_count": 200,  # Smaller batches for higher concurrency
                    "priority": "high" if i % 3 == 0 else "normal",
                }
                batch_scenarios.append(scenario)

            # Run batch simulation
            await simulator.run_concurrent_batch_simulation(
                batch_scenarios, duration_seconds=duration_seconds
            )

            metrics = simulator.performance_metrics
            return {
                "batch_count": batch_count,
                "jobs_submitted": metrics["jobs_submitted"],
                "jobs_completed": metrics["jobs_completed"],
                "jobs_failed": metrics["jobs_failed"],
                "documents_processed": metrics["total_documents_processed"],
                "total_processing_time": metrics["total_processing_time"],
                "average_processing_time": metrics["average_processing_time"],
                "success_rate_percent": (
                    metrics["jobs_completed"] / max(1, metrics["jobs_submitted"])
                )
                * 100,
                "peak_concurrent_jobs": metrics["peak_concurrent_jobs"],
            }

        finally:
            await simulator.close()

    def _compile_step_results(
        self,
        step_number: int,
        concurrent_operations: int,
        api_results: Dict,
        batch_results: Dict,
        resource_start: Dict,
        resource_end: Dict,
        duration_seconds: int,
    ) -> StepResults:
        """Compile comprehensive results for a stress testing step."""

        # Calculate resource deltas
        cpu_delta = resource_end["cpu_percent"] - resource_start["cpu_percent"]
        memory_delta = resource_end["memory_percent"] - resource_start["memory_percent"]

        # Combined performance metrics
        total_operations = (
            api_results["total_requests"] + batch_results["documents_processed"]
        )
        combined_error_rate = (
            (api_results["total_failures"] + batch_results["jobs_failed"])
            / max(1, total_operations)
        ) * 100

        # Identify bottlenecks
        bottlenecks = self._identify_bottlenecks(
            resource_end, api_results, batch_results
        )

        return StepResults(
            step_number=step_number,
            concurrent_operations=concurrent_operations,
            duration_seconds=duration_seconds,
            # API Performance
            api_avg_response_time_ms=api_results["avg_response_time_ms"],
            api_p95_response_time_ms=api_results["p95_response_time_ms"],
            api_p99_response_time_ms=api_results["p99_response_time_ms"],
            api_requests_per_second=api_results["requests_per_second"],
            api_error_rate_percent=api_results["error_rate_percent"],
            # Batch Performance
            batch_jobs_completed=batch_results["jobs_completed"],
            batch_success_rate_percent=batch_results["success_rate_percent"],
            batch_avg_processing_time=batch_results["average_processing_time"],
            # Resource Utilization
            cpu_utilization_percent=resource_end["cpu_percent"],
            memory_utilization_percent=resource_end["memory_percent"],
            cpu_delta=cpu_delta,
            memory_delta=memory_delta,
            # Combined Metrics
            total_operations=total_operations,
            combined_error_rate_percent=combined_error_rate,
            operations_per_second=total_operations / duration_seconds,
            # Bottleneck Analysis
            bottlenecks_detected=bottlenecks,
            # Breaking Point Indicators
            breaking_point_indicators=self._identify_breaking_point_indicators(
                api_results, batch_results, resource_end, combined_error_rate
            ),
        )

    def _identify_bottlenecks(
        self, resource_stats: Dict, api_results: Dict, batch_results: Dict
    ) -> List[str]:
        """Identify system bottlenecks based on metrics."""
        bottlenecks = []

        # CPU bottleneck
        if resource_stats["cpu_percent"] > self.config.resource_critical_cpu_percent:
            bottlenecks.append(f"CPU_CRITICAL_{resource_stats['cpu_percent']:.1f}%")
        elif resource_stats["cpu_percent"] > self.config.resource_warning_cpu_percent:
            bottlenecks.append(f"CPU_WARNING_{resource_stats['cpu_percent']:.1f}%")

        # Memory bottleneck
        if (
            resource_stats["memory_percent"]
            > self.config.resource_critical_memory_percent
        ):
            bottlenecks.append(
                f"MEMORY_CRITICAL_{resource_stats['memory_percent']:.1f}%"
            )
        elif (
            resource_stats["memory_percent"]
            > self.config.resource_warning_memory_percent
        ):
            bottlenecks.append(
                f"MEMORY_WARNING_{resource_stats['memory_percent']:.1f}%"
            )

        # API Response time bottleneck
        if api_results["avg_response_time_ms"] > 2000:  # 2 second threshold
            bottlenecks.append(
                f"API_RESPONSE_TIME_{api_results['avg_response_time_ms']:.0f}ms"
            )

        # Error rate bottleneck
        if api_results["error_rate_percent"] > 1.0:
            bottlenecks.append(
                f"API_ERROR_RATE_{api_results['error_rate_percent']:.1f}%"
            )

        # Batch processing bottleneck
        if batch_results["success_rate_percent"] < 95.0:
            bottlenecks.append(
                f"BATCH_SUCCESS_RATE_{batch_results['success_rate_percent']:.1f}%"
            )

        return bottlenecks

    def _identify_breaking_point_indicators(
        self,
        api_results: Dict,
        batch_results: Dict,
        resource_stats: Dict,
        combined_error_rate: float,
    ) -> List[str]:
        """Identify indicators that suggest system is at breaking point."""
        indicators = []

        # High error rates
        if combined_error_rate > self.config.breaking_point_threshold_error_rate:
            indicators.append(f"HIGH_ERROR_RATE_{combined_error_rate:.1f}%")

        # Excessive response times
        if (
            api_results["avg_response_time_ms"]
            > self.config.breaking_point_threshold_response_time_ms
        ):
            indicators.append(
                f"EXCESSIVE_RESPONSE_TIME_{api_results['avg_response_time_ms']:.0f}ms"
            )

        # Resource exhaustion
        if resource_stats["cpu_percent"] > 95:
            indicators.append(f"CPU_EXHAUSTION_{resource_stats['cpu_percent']:.1f}%")

        if resource_stats["memory_percent"] > 95:
            indicators.append(
                f"MEMORY_EXHAUSTION_{resource_stats['memory_percent']:.1f}%"
            )

        # Low success rates
        if api_results["success_rate_percent"] < 80:
            indicators.append(
                f"LOW_API_SUCCESS_RATE_{api_results['success_rate_percent']:.1f}%"
            )

        if batch_results["success_rate_percent"] < 70:
            indicators.append(
                f"LOW_BATCH_SUCCESS_RATE_{batch_results['success_rate_percent']:.1f}%"
            )

        return indicators

    def _is_breaking_point(self, step_result: StepResults) -> bool:
        """Determine if step result indicates a breaking point."""
        return len(step_result.breaking_point_indicators) > 0

    async def _analyze_recovery_patterns(
        self, breaking_point_step: StepResults
    ) -> Dict:
        """Analyze system recovery patterns after breaking point."""
        logger.info("Analyzing system recovery patterns...")

        recovery_start_time = time.time()

        # Reduce load to 50% of breaking point
        recovery_operations = max(10, breaking_point_step.concurrent_operations // 2)

        logger.info(f"Testing recovery with {recovery_operations} operations...")

        try:
            recovery_result = await self._execute_stress_step(
                step_number=999,  # Special step number for recovery
                concurrent_operations=recovery_operations,
                duration_seconds=120,  # 2 minute recovery test
            )

            recovery_time = time.time() - recovery_start_time

            # Analyze recovery success
            recovery_successful = (
                recovery_result.combined_error_rate_percent < 1.0
                and recovery_result.api_avg_response_time_ms < 1000
                and len(recovery_result.breaking_point_indicators) == 0
            )

            return {
                "recovery_attempted": True,
                "recovery_time_seconds": recovery_time,
                "recovery_successful": recovery_successful,
                "recovery_operations": recovery_operations,
                "recovery_error_rate": recovery_result.combined_error_rate_percent,
                "recovery_response_time": recovery_result.api_avg_response_time_ms,
                "recovery_indicators": recovery_result.breaking_point_indicators,
            }

        except Exception as e:
            logger.error(f"Recovery analysis failed: {str(e)}")
            return {
                "recovery_attempted": True,
                "recovery_time_seconds": time.time() - recovery_start_time,
                "recovery_successful": False,
                "recovery_error": str(e),
            }

    async def _analyze_stress_test_results(
        self, total_duration: float
    ) -> StressTestResults:
        """Analyze comprehensive stress test results."""
        if not self.step_results:
            raise ValueError("No step results available for analysis")

        # Breaking point analysis
        breaking_point_step_result = None
        if self.breaking_point_found:
            breaking_point_step_result = self.step_results[self.breaking_point_step - 1]

        # Performance degradation analysis
        baseline_step = self.step_results[0]
        final_step = self.step_results[-1]

        response_time_degradation = (
            (
                final_step.api_avg_response_time_ms
                - baseline_step.api_avg_response_time_ms
            )
            / baseline_step.api_avg_response_time_ms
            * 100
        )

        throughput_degradation = (
            (baseline_step.operations_per_second - final_step.operations_per_second)
            / baseline_step.operations_per_second
            * 100
        )

        # Resource utilization analysis
        peak_cpu = max(step.cpu_utilization_percent for step in self.step_results)
        peak_memory = max(step.memory_utilization_percent for step in self.step_results)

        # Error rate progression
        error_rate_progression = [
            step.combined_error_rate_percent for step in self.step_results
        ]

        # Scalability efficiency
        scalability_efficiency = self._calculate_scalability_efficiency()

        # Recovery analysis
        recovery_time = None
        recovery_successful = False
        if breaking_point_step_result and hasattr(
            breaking_point_step_result, "recovery_analysis"
        ):
            recovery_analysis = breaking_point_step_result.recovery_analysis
            recovery_time = recovery_analysis.get("recovery_time_seconds")
            recovery_successful = recovery_analysis.get("recovery_successful", False)

        return StressTestResults(
            # Breaking Point Analysis
            breaking_point_detected=self.breaking_point_found,
            breaking_point_concurrent_operations=breaking_point_step_result.concurrent_operations
            if breaking_point_step_result
            else None,
            breaking_point_step_number=self.breaking_point_step,
            max_operations_tested=max(
                step.concurrent_operations for step in self.step_results
            ),
            # Performance Degradation
            baseline_response_time_ms=baseline_step.api_avg_response_time_ms,
            peak_response_time_ms=max(
                step.api_avg_response_time_ms for step in self.step_results
            ),
            response_time_degradation_percent=response_time_degradation,
            baseline_throughput_ops_per_sec=baseline_step.operations_per_second,
            minimum_throughput_ops_per_sec=min(
                step.operations_per_second for step in self.step_results
            ),
            throughput_degradation_percent=throughput_degradation,
            # Resource Utilization
            peak_cpu_utilization_percent=peak_cpu,
            peak_memory_utilization_percent=peak_memory,
            cpu_bottleneck_detected=peak_cpu
            > self.config.resource_critical_cpu_percent,
            memory_bottleneck_detected=peak_memory
            > self.config.resource_critical_memory_percent,
            network_bottleneck_detected=False,  # Would need network monitoring
            database_bottleneck_detected=False,  # Would need database monitoring
            # Error Analysis
            error_rate_progression=error_rate_progression,
            failure_patterns=self._analyze_failure_patterns(),
            graceful_degradation_observed=self._analyze_graceful_degradation(),
            # Scalability Analysis
            scalability_efficiency_score=scalability_efficiency,
            linear_scaling_deviation_percent=self._calculate_linear_scaling_deviation(),
            # Recovery Analysis
            recovery_time_seconds=recovery_time,
            recovery_successful=recovery_successful,
            # Test Configuration
            load_steps_executed=len(self.step_results),
            total_test_duration_seconds=total_duration,
            configuration=self.config,
        )

    def _calculate_scalability_efficiency(self) -> float:
        """Calculate how efficiently the system scales with load."""
        if len(self.step_results) < 2:
            return 0.0

        # Calculate throughput per unit of load
        baseline = self.step_results[0]
        baseline_efficiency = (
            baseline.operations_per_second / baseline.concurrent_operations
        )

        efficiencies = []
        for step in self.step_results:
            efficiency = step.operations_per_second / step.concurrent_operations
            normalized_efficiency = efficiency / baseline_efficiency
            efficiencies.append(normalized_efficiency)

        return statistics.mean(efficiencies)

    def _calculate_linear_scaling_deviation(self) -> float:
        """Calculate deviation from perfect linear scaling."""
        if len(self.step_results) < 2:
            return 0.0

        # Perfect linear scaling would maintain constant throughput per operation
        baseline = self.step_results[0]
        expected_throughput_per_op = (
            baseline.operations_per_second / baseline.concurrent_operations
        )

        deviations = []
        for step in self.step_results:
            actual_throughput_per_op = (
                step.operations_per_second / step.concurrent_operations
            )
            deviation = (
                abs(actual_throughput_per_op - expected_throughput_per_op)
                / expected_throughput_per_op
                * 100
            )
            deviations.append(deviation)

        return statistics.mean(deviations)

    def _analyze_failure_patterns(self) -> List[str]:
        """Analyze patterns in system failures."""
        patterns = []

        # Check for escalating error rates
        error_rates = [step.combined_error_rate_percent for step in self.step_results]
        if len(error_rates) >= 3:
            trend = error_rates[-1] - error_rates[0]
            if trend > 5.0:
                patterns.append("ESCALATING_ERROR_RATES")

        # Check for resource exhaustion patterns
        cpu_trend = [step.cpu_utilization_percent for step in self.step_results]
        if len(cpu_trend) >= 2 and cpu_trend[-1] > 90:
            patterns.append("CPU_EXHAUSTION_PATTERN")

        # Check for cascading failures
        breaking_point_indicators = []
        for step in self.step_results:
            breaking_point_indicators.extend(step.breaking_point_indicators)

        if len(set(breaking_point_indicators)) > 3:
            patterns.append("CASCADING_FAILURES")

        return patterns

    def _analyze_graceful_degradation(self) -> bool:
        """Analyze if system degrades gracefully under stress."""
        # Graceful degradation means:
        # 1. Response times increase gradually, not suddenly
        # 2. Error rates increase gradually
        # 3. System doesn't crash completely

        response_times = [step.api_avg_response_time_ms for step in self.step_results]
        error_rates = [step.combined_error_rate_percent for step in self.step_results]

        # Check for sudden spikes (non-graceful)
        response_time_spikes = 0
        for i in range(1, len(response_times)):
            if response_times[i] > response_times[i - 1] * 3:  # 3x increase
                response_time_spikes += 1

        error_rate_spikes = 0
        for i in range(1, len(error_rates)):
            if error_rates[i] > error_rates[i - 1] + 10:  # 10% sudden increase
                error_rate_spikes += 1

        # Graceful if no sudden spikes and system doesn't completely fail
        return (
            response_time_spikes <= 1
            and error_rate_spikes <= 1
            and max(error_rates) < 50
        )

    def _log_step_summary(self, step_result: StepResults):
        """Log summary of step results."""
        logger.info(f"\nStep {step_result.step_number} Results:")
        logger.info(f"  Concurrent Operations: {step_result.concurrent_operations}")
        logger.info(
            f"  API Avg Response Time: {step_result.api_avg_response_time_ms:.1f}ms"
        )
        logger.info(
            f"  API P95 Response Time: {step_result.api_p95_response_time_ms:.1f}ms"
        )
        logger.info(
            f"  Combined Error Rate: {step_result.combined_error_rate_percent:.2f}%"
        )
        logger.info(f"  Operations per Second: {step_result.operations_per_second:.1f}")
        logger.info(f"  CPU Utilization: {step_result.cpu_utilization_percent:.1f}%")
        logger.info(
            f"  Memory Utilization: {step_result.memory_utilization_percent:.1f}%"
        )

        if step_result.bottlenecks_detected:
            logger.warning(
                f"  Bottlenecks: {', '.join(step_result.bottlenecks_detected)}"
            )

        if step_result.breaking_point_indicators:
            logger.error(
                f"  Breaking Point Indicators: {', '.join(step_result.breaking_point_indicators)}"
            )

    def _create_failed_step_result(
        self, step_number: int, concurrent_operations: int, error_message: str
    ) -> StepResults:
        """Create a failed step result."""
        return StepResults(
            step_number=step_number,
            concurrent_operations=concurrent_operations,
            duration_seconds=0,
            api_avg_response_time_ms=0,
            api_p95_response_time_ms=0,
            api_p99_response_time_ms=0,
            api_requests_per_second=0,
            api_error_rate_percent=100,
            batch_jobs_completed=0,
            batch_success_rate_percent=0,
            batch_avg_processing_time=0,
            cpu_utilization_percent=0,
            memory_utilization_percent=0,
            cpu_delta=0,
            memory_delta=0,
            total_operations=0,
            combined_error_rate_percent=100,
            operations_per_second=0,
            bottlenecks_detected=["SYSTEM_FAILURE"],
            breaking_point_indicators=[f"STEP_FAILURE_{error_message}"],
        )

    def _generate_stress_test_report(self, results: StressTestResults):
        """Generate comprehensive stress test report."""
        logger.info("\n" + "=" * 80)
        logger.info("PERF-002 STRESS TESTING RESULTS - BREAKING POINT ANALYSIS")
        logger.info("=" * 80)

        # Test Summary
        logger.info("\nTest Summary:")
        logger.info(f"  Load Steps Executed: {results.load_steps_executed}")
        logger.info(f"  Maximum Operations Tested: {results.max_operations_tested}")
        logger.info(
            f"  Total Test Duration: {results.total_test_duration_seconds:.1f} seconds"
        )

        # Breaking Point Analysis
        logger.info("\nBreaking Point Analysis:")
        if results.breaking_point_detected:
            logger.warning(
                f"  ⚠️ Breaking Point Detected: {results.breaking_point_concurrent_operations} concurrent operations"
            )
            logger.warning(
                f"  Breaking Point Step: {results.breaking_point_step_number}"
            )
        else:
            logger.info(
                f"  ✅ No breaking point detected up to {results.max_operations_tested} operations"
            )

        # Performance Degradation
        logger.info("\nPerformance Degradation:")
        logger.info(
            f"  Baseline Response Time: {results.baseline_response_time_ms:.1f}ms"
        )
        logger.info(f"  Peak Response Time: {results.peak_response_time_ms:.1f}ms")
        logger.info(
            f"  Response Time Degradation: {results.response_time_degradation_percent:.1f}%"
        )
        logger.info(
            f"  Baseline Throughput: {results.baseline_throughput_ops_per_sec:.1f} ops/sec"
        )
        logger.info(
            f"  Minimum Throughput: {results.minimum_throughput_ops_per_sec:.1f} ops/sec"
        )
        logger.info(
            f"  Throughput Degradation: {results.throughput_degradation_percent:.1f}%"
        )

        # Resource Utilization
        logger.info("\nResource Utilization:")
        logger.info(f"  Peak CPU: {results.peak_cpu_utilization_percent:.1f}%")
        logger.info(f"  Peak Memory: {results.peak_memory_utilization_percent:.1f}%")
        logger.info(f"  CPU Bottleneck Detected: {results.cpu_bottleneck_detected}")
        logger.info(
            f"  Memory Bottleneck Detected: {results.memory_bottleneck_detected}"
        )

        # Scalability Analysis
        logger.info("\nScalability Analysis:")
        logger.info(
            f"  Scalability Efficiency Score: {results.scalability_efficiency_score:.2f}"
        )
        logger.info(
            f"  Linear Scaling Deviation: {results.linear_scaling_deviation_percent:.1f}%"
        )
        logger.info(
            f"  Graceful Degradation Observed: {results.graceful_degradation_observed}"
        )

        # Error Analysis
        logger.info("\nError Analysis:")
        logger.info(
            f"  Error Rate Progression: {[f'{rate:.1f}%' for rate in results.error_rate_progression]}"
        )
        if results.failure_patterns:
            logger.info(f"  Failure Patterns: {', '.join(results.failure_patterns)}")

        # Recovery Analysis
        if results.recovery_time_seconds:
            logger.info("\nRecovery Analysis:")
            logger.info(f"  Recovery Time: {results.recovery_time_seconds:.1f} seconds")
            logger.info(f"  Recovery Successful: {results.recovery_successful}")

        logger.info("\n" + "=" * 80)

    def _record_stress_test_metrics(self, results: StressTestResults):
        """Record stress test metrics in benchmark manager."""
        # Record breaking point metrics
        if results.breaking_point_detected:
            benchmark_manager.record_measurement(
                "stress_testing",
                "breaking_point_operations",
                float(results.breaking_point_concurrent_operations),
                " ops",
                context={"test_type": "stress", "breaking_point": True},
            )

        # Record peak resource utilization
        benchmark_manager.record_measurement(
            "resource_utilization",
            "stress_peak_cpu",
            results.peak_cpu_utilization_percent,
            "%",
            context={"test_type": "stress"},
        )

        benchmark_manager.record_measurement(
            "resource_utilization",
            "stress_peak_memory",
            results.peak_memory_utilization_percent,
            "%",
            context={"test_type": "stress"},
        )


# Enhanced monitoring classes
class EnhancedResourceMonitor:
    """Enhanced resource monitoring with detailed metrics."""

    def __init__(self):
        self.monitoring = False
        self.cpu_samples = []
        self.memory_samples = []
        self.disk_io_samples = []
        self.network_io_samples = []
        self.monitor_thread = None

    def start_monitoring(self):
        """Start enhanced resource monitoring."""
        self.monitoring = True
        self.cpu_samples = []
        self.memory_samples = []
        self.disk_io_samples = []
        self.network_io_samples = []

        import threading

        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()
        logger.info("Enhanced resource monitoring started")

    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Enhanced resource monitoring stopped")

    def _monitor_loop(self):
        """Enhanced monitoring loop."""
        while self.monitoring:
            try:
                # CPU and Memory
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()

                # Disk I/O
                disk_io = psutil.disk_io_counters()

                # Network I/O
                network_io = psutil.net_io_counters()

                self.cpu_samples.append(cpu_percent)
                self.memory_samples.append(memory.percent)

                if disk_io:
                    self.disk_io_samples.append(
                        {
                            "read_bytes": disk_io.read_bytes,
                            "write_bytes": disk_io.write_bytes,
                            "read_count": disk_io.read_count,
                            "write_count": disk_io.write_count,
                        }
                    )

                if network_io:
                    self.network_io_samples.append(
                        {
                            "bytes_sent": network_io.bytes_sent,
                            "bytes_recv": network_io.bytes_recv,
                            "packets_sent": network_io.packets_sent,
                            "packets_recv": network_io.packets_recv,
                        }
                    )

                time.sleep(1.0)
            except Exception as e:
                logger.error(f"Error in enhanced resource monitoring: {str(e)}")
                break

    def take_snapshot(self) -> Dict:
        """Take a snapshot of current resource utilization."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1.0)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_usage_percent": disk.percent,
                "timestamp": time.time(),
            }
        except Exception as e:
            logger.error(f"Error taking resource snapshot: {str(e)}")
            return {"cpu_percent": 0, "memory_percent": 0, "timestamp": time.time()}


class NetworkPerformanceMonitor:
    """Network performance monitoring."""

    def __init__(self):
        self.monitoring = False
        self.baseline_network_stats = None

    def start_monitoring(self):
        """Start network monitoring."""
        self.monitoring = True
        self.baseline_network_stats = psutil.net_io_counters()
        logger.info("Network performance monitoring started")

    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring = False
        logger.info("Network performance monitoring stopped")


class DatabasePerformanceMonitor:
    """Database performance monitoring."""

    def __init__(self):
        self.monitoring = False

    def start_monitoring(self):
        """Start database monitoring."""
        self.monitoring = True
        logger.info("Database performance monitoring started")

    def stop_monitoring(self):
        """Stop database monitoring."""
        self.monitoring = False
        logger.info("Database performance monitoring stopped")


# Enhanced StepResults class
class StepResults:
    """Enhanced results for stress testing steps."""

    def __init__(
        self,
        step_number: int,
        concurrent_operations: int,
        duration_seconds: int,
        api_avg_response_time_ms: float,
        api_p95_response_time_ms: float,
        api_p99_response_time_ms: float,
        api_requests_per_second: float,
        api_error_rate_percent: float,
        batch_jobs_completed: int,
        batch_success_rate_percent: float,
        batch_avg_processing_time: float,
        cpu_utilization_percent: float,
        memory_utilization_percent: float,
        cpu_delta: float,
        memory_delta: float,
        total_operations: int,
        combined_error_rate_percent: float,
        operations_per_second: float,
        bottlenecks_detected: List[str],
        breaking_point_indicators: List[str],
    ):
        self.step_number = step_number
        self.concurrent_operations = concurrent_operations
        self.duration_seconds = duration_seconds
        self.api_avg_response_time_ms = api_avg_response_time_ms
        self.api_p95_response_time_ms = api_p95_response_time_ms
        self.api_p99_response_time_ms = api_p99_response_time_ms
        self.api_requests_per_second = api_requests_per_second
        self.api_error_rate_percent = api_error_rate_percent
        self.batch_jobs_completed = batch_jobs_completed
        self.batch_success_rate_percent = batch_success_rate_percent
        self.batch_avg_processing_time = batch_avg_processing_time
        self.cpu_utilization_percent = cpu_utilization_percent
        self.memory_utilization_percent = memory_utilization_percent
        self.cpu_delta = cpu_delta
        self.memory_delta = memory_delta
        self.total_operations = total_operations
        self.combined_error_rate_percent = combined_error_rate_percent
        self.operations_per_second = operations_per_second
        self.bottlenecks_detected = bottlenecks_detected
        self.breaking_point_indicators = breaking_point_indicators


# Main execution
async def run_perf_002_stress_test(
    bsn_url: str = "http://localhost:8000",
    ragnostic_url: str = "http://localhost:8001",
    load_progression: List[int] = None,
    step_duration: int = 180,
) -> StressTestResults:
    """Run PERF-002 stress testing with breaking point analysis."""

    config = StressTestConfiguration(
        load_progression=load_progression or [50, 100, 200, 300, 500, 750, 1000],
        step_duration_seconds=step_duration,
        max_concurrent_operations=1000,
        breaking_point_threshold_error_rate=5.0,
        breaking_point_threshold_response_time_ms=5000,
        resource_warning_cpu_percent=70.0,
        resource_critical_cpu_percent=85.0,
        resource_warning_memory_percent=75.0,
        resource_critical_memory_percent=90.0,
    )

    tester = ComprehensiveStressTester(
        bsn_knowledge_url=bsn_url, ragnostic_url=ragnostic_url, config=config
    )

    return await tester.run_stress_test()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PERF-002: Stress Testing - Breaking Point Analysis"
    )
    parser.add_argument(
        "--bsn-url", default="http://localhost:8000", help="BSN Knowledge URL"
    )
    parser.add_argument(
        "--ragnostic-url", default="http://localhost:8001", help="RAGnostic URL"
    )
    parser.add_argument(
        "--step-duration", type=int, default=180, help="Duration per step in seconds"
    )
    parser.add_argument(
        "--load-progression",
        nargs="+",
        type=int,
        default=[50, 100, 200, 300, 500, 750, 1000],
        help="Load progression steps",
    )

    args = parser.parse_args()

    # Run the test
    results = asyncio.run(
        run_perf_002_stress_test(
            bsn_url=args.bsn_url,
            ragnostic_url=args.ragnostic_url,
            load_progression=args.load_progression,
            step_duration=args.step_duration,
        )
    )

    # Exit with appropriate code
    exit_code = 0 if results.breaking_point_detected else 1
    exit(exit_code)
