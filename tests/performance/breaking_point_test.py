"""Breaking Point Analysis for BSN Knowledge System.

Gradual load increase testing to identify system breaking points and
performance degradation patterns under increasing stress.
"""

import argparse
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

import psutil
from locust.env import Environment
from locust.user import HttpUser, task, between

from performance_benchmarks import benchmark_manager, record_resource_usage

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class LoadStep:
    """Represents a single load testing step."""

    user_count: int
    duration_seconds: int
    batch_jobs: int
    step_number: int
    timestamp: datetime = None


@dataclass
class StepResults:
    """Results from a single load testing step."""

    step: LoadStep
    avg_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_second: float
    error_rate: float
    avg_cpu_percent: float
    avg_memory_percent: float
    peak_cpu_percent: float
    peak_memory_percent: float
    success_rate: float
    total_requests: int
    failed_requests: int
    breaking_point_indicators: List[str]

    @property
    def is_breaking_point(self) -> bool:
        """Determine if this step represents a breaking point."""
        return (
            self.error_rate > 5.0  # >5% error rate
            or self.avg_response_time > 5.0  # >5s average response time
            or self.success_rate < 80.0  # <80% success rate
            or self.peak_cpu_percent > 95.0  # >95% CPU utilization
            or self.peak_memory_percent > 95.0  # >95% memory utilization
        )


class BreakingPointUser(HttpUser):
    """Simplified user for breaking point analysis."""

    wait_time = between(1, 3)  # Faster interactions for stress testing

    def on_start(self):
        """Authenticate user on start."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_user", "password": "test_password"},
        )

        if response.status_code == 200:
            self.auth_token = response.json()["access_token"]
            self.auth_headers = {"Authorization": f"Bearer {self.auth_token}"}
        else:
            self.auth_headers = {}

    @task(40)
    def health_check(self):
        """Basic health check."""
        self.client.get("/health")

    @task(30)
    def authenticated_request(self):
        """Authenticated API request."""
        self.client.get("/api/v1/auth/me", headers=self.auth_headers)

    @task(20)
    def content_generation(self):
        """Content generation request."""
        self.client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "nursing_fundamentals",
                "difficulty": "medium",
                "question_count": 5,
            },
            headers=self.auth_headers,
        )

    @task(10)
    def analytics_query(self):
        """Analytics query."""
        self.client.get("/api/v1/analytics/class/overview", headers=self.auth_headers)


class BreakingPointAnalyzer:
    """Analyzes system breaking points through gradual load increase."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        max_users: int = 300,
        increment: int = 25,
        duration_per_step: int = 180,
        monitor_resources: bool = True,
    ):
        self.base_url = base_url
        self.max_users = max_users
        self.increment = increment
        self.duration_per_step = duration_per_step
        self.monitor_resources = monitor_resources

        self.test_results: List[StepResults] = []
        self.breaking_point_found = False
        self.breaking_point_step: Optional[int] = None

        logger.info("Breaking Point Analyzer initialized:")
        logger.info(f"  Base URL: {base_url}")
        logger.info(f"  Max Users: {max_users}")
        logger.info(f"  Increment: {increment}")
        logger.info(f"  Duration per step: {duration_per_step}s")
        logger.info(f"  Resource monitoring: {monitor_resources}")

    def generate_load_steps(self) -> List[LoadStep]:
        """Generate load testing steps with gradual increase."""
        steps = []
        step_number = 1

        for user_count in range(self.increment, self.max_users + 1, self.increment):
            # Increase batch jobs proportionally
            batch_jobs = max(1, user_count // 15)  # 1 batch job per 15 users

            step = LoadStep(
                user_count=user_count,
                duration_seconds=self.duration_per_step,
                batch_jobs=batch_jobs,
                step_number=step_number,
                timestamp=datetime.now(),
            )
            steps.append(step)
            step_number += 1

        return steps

    def run_load_step(self, step: LoadStep) -> StepResults:
        """Execute a single load testing step."""
        logger.info(f"\n{'='*60}")
        logger.info(f"EXECUTING STEP {step.step_number}: {step.user_count} users")
        logger.info(
            f"Duration: {step.duration_seconds}s, Batch jobs: {step.batch_jobs}"
        )
        logger.info(f"{'='*60}")

        # Resource monitoring setup
        resource_monitor = ResourceMonitor() if self.monitor_resources else None
        if resource_monitor:
            resource_monitor.start_monitoring()

        # Set up Locust environment
        env = Environment(user_classes=[BreakingPointUser])
        env.create_local_runner()

        # Start load test
        env.runner.start(step.user_count, spawn_rate=min(10, step.user_count))

        # Run for specified duration
        start_time = time.time()
        while time.time() - start_time < step.duration_seconds:
            time.sleep(1)

            # Check for early termination conditions
            current_stats = env.stats.total
            if current_stats.num_requests > 0:
                current_error_rate = (
                    current_stats.num_failures / current_stats.num_requests
                ) * 100
                if current_error_rate > 50:  # >50% error rate - abort step
                    logger.warning(
                        f"Aborting step due to high error rate: {current_error_rate:.1f}%"
                    )
                    break

        # Stop load test
        env.runner.quit()

        # Stop resource monitoring
        if resource_monitor:
            resource_monitor.stop_monitoring()
            resource_stats = resource_monitor.get_stats()
        else:
            resource_stats = {
                "avg_cpu_percent": 0,
                "avg_memory_percent": 0,
                "peak_cpu_percent": 0,
                "peak_memory_percent": 0,
            }

        # Collect results
        stats = env.stats.total

        # Calculate metrics
        total_requests = stats.num_requests
        failed_requests = stats.num_failures
        success_rate = (
            (total_requests - failed_requests) / max(1, total_requests)
        ) * 100
        error_rate = (failed_requests / max(1, total_requests)) * 100
        requests_per_second = (
            total_requests / step.duration_seconds if step.duration_seconds > 0 else 0
        )

        # Identify breaking point indicators
        breaking_point_indicators = []
        if error_rate > 5.0:
            breaking_point_indicators.append(f"High error rate: {error_rate:.1f}%")
        if stats.avg_response_time > 5000:  # >5s
            breaking_point_indicators.append(
                f"High response time: {stats.avg_response_time:.0f}ms"
            )
        if success_rate < 80.0:
            breaking_point_indicators.append(f"Low success rate: {success_rate:.1f}%")
        if resource_stats["peak_cpu_percent"] > 90:
            breaking_point_indicators.append(
                f"High CPU utilization: {resource_stats['peak_cpu_percent']:.1f}%"
            )
        if resource_stats["peak_memory_percent"] > 90:
            breaking_point_indicators.append(
                f"High memory utilization: {resource_stats['peak_memory_percent']:.1f}%"
            )

        # Create results
        results = StepResults(
            step=step,
            avg_response_time=stats.avg_response_time / 1000,  # Convert to seconds
            p95_response_time=stats.get_response_time_percentile(0.95) / 1000,
            p99_response_time=stats.get_response_time_percentile(0.99) / 1000,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            avg_cpu_percent=resource_stats["avg_cpu_percent"],
            avg_memory_percent=resource_stats["avg_memory_percent"],
            peak_cpu_percent=resource_stats["peak_cpu_percent"],
            peak_memory_percent=resource_stats["peak_memory_percent"],
            success_rate=success_rate,
            total_requests=total_requests,
            failed_requests=failed_requests,
            breaking_point_indicators=breaking_point_indicators,
        )

        # Log step results
        self._log_step_results(results)

        # Record performance benchmarks
        benchmark_manager.record_measurement(
            "throughput_performance",
            "concurrent_users",
            step.user_count,
            " users",
            context={"step": step.step_number, "breaking_point_test": True},
        )

        record_resource_usage(
            resource_stats["avg_cpu_percent"],
            resource_stats["avg_memory_percent"],
            50.0,  # Assume 50% DB connection usage for breaking point tests
        )

        return results

    def _log_step_results(self, results: StepResults):
        """Log results from a completed step."""
        logger.info(f"\nStep {results.step.step_number} Results:")
        logger.info(f"  Users: {results.step.user_count}")
        logger.info(f"  Total Requests: {results.total_requests}")
        logger.info(f"  Success Rate: {results.success_rate:.1f}%")
        logger.info(f"  Error Rate: {results.error_rate:.1f}%")
        logger.info(f"  Avg Response Time: {results.avg_response_time:.3f}s")
        logger.info(f"  P95 Response Time: {results.p95_response_time:.3f}s")
        logger.info(f"  P99 Response Time: {results.p99_response_time:.3f}s")
        logger.info(f"  Requests/sec: {results.requests_per_second:.1f}")
        logger.info(f"  Avg CPU: {results.avg_cpu_percent:.1f}%")
        logger.info(f"  Peak CPU: {results.peak_cpu_percent:.1f}%")
        logger.info(f"  Avg Memory: {results.avg_memory_percent:.1f}%")
        logger.info(f"  Peak Memory: {results.peak_memory_percent:.1f}%")

        if results.breaking_point_indicators:
            logger.warning("  Breaking Point Indicators:")
            for indicator in results.breaking_point_indicators:
                logger.warning(f"    - {indicator}")

        if results.is_breaking_point:
            logger.error(
                f"  ⚠️  BREAKING POINT DETECTED at {results.step.user_count} users"
            )

    def analyze_breaking_points(self) -> Dict:
        """Analyze all test results to identify breaking points and patterns."""
        logger.info(f"\n{'='*80}")
        logger.info("BREAKING POINT ANALYSIS")
        logger.info(f"{'='*80}")

        analysis = {
            "test_summary": {
                "total_steps": len(self.test_results),
                "max_users_tested": max(r.step.user_count for r in self.test_results)
                if self.test_results
                else 0,
                "breaking_point_detected": self.breaking_point_found,
                "breaking_point_step": self.breaking_point_step,
                "breaking_point_users": None,
            },
            "performance_degradation": {},
            "resource_utilization": {},
            "recommendations": [],
        }

        if not self.test_results:
            logger.warning("No test results available for analysis")
            return analysis

        # Find breaking point
        breaking_point_result = None
        for result in self.test_results:
            if result.is_breaking_point:
                breaking_point_result = result
                analysis["test_summary"]["breaking_point_users"] = (
                    result.step.user_count
                )
                break

        # Performance degradation analysis
        baseline_result = self.test_results[0]
        final_result = self.test_results[-1]

        response_time_degradation = (
            (final_result.avg_response_time - baseline_result.avg_response_time)
            / baseline_result.avg_response_time
            * 100
        )

        throughput_change = (
            (final_result.requests_per_second - baseline_result.requests_per_second)
            / baseline_result.requests_per_second
            * 100
        )

        analysis["performance_degradation"] = {
            "response_time_increase_percent": response_time_degradation,
            "throughput_change_percent": throughput_change,
            "error_rate_at_max_load": final_result.error_rate,
            "scalability_efficiency": self._calculate_scalability_efficiency(),
        }

        # Resource utilization analysis
        max_cpu = max(r.peak_cpu_percent for r in self.test_results)
        max_memory = max(r.peak_memory_percent for r in self.test_results)

        analysis["resource_utilization"] = {
            "peak_cpu_utilization": max_cpu,
            "peak_memory_utilization": max_memory,
            "cpu_bottleneck": max_cpu > 85,
            "memory_bottleneck": max_memory > 85,
            "resource_efficiency": self._calculate_resource_efficiency(),
        }

        # Generate recommendations
        recommendations = []

        if breaking_point_result:
            recommendations.append(
                f"System breaking point: {breaking_point_result.step.user_count} concurrent users"
            )

            if "High CPU utilization" in str(
                breaking_point_result.breaking_point_indicators
            ):
                recommendations.append(
                    "CPU optimization required - consider profiling and optimizing CPU-intensive operations"
                )

            if "High memory utilization" in str(
                breaking_point_result.breaking_point_indicators
            ):
                recommendations.append(
                    "Memory optimization required - check for memory leaks and optimize memory usage"
                )

            if "High error rate" in str(
                breaking_point_result.breaking_point_indicators
            ):
                recommendations.append(
                    "Error handling improvement needed - investigate root causes of failures"
                )

            if "High response time" in str(
                breaking_point_result.breaking_point_indicators
            ):
                recommendations.append(
                    "Response time optimization required - optimize database queries and external API calls"
                )

        if response_time_degradation > 200:  # >200% increase
            recommendations.append(
                "Significant response time degradation detected - implement performance optimizations"
            )

        if throughput_change < -50:  # >50% decrease
            recommendations.append(
                "Poor throughput scaling - investigate bottlenecks in request processing"
            )

        if max_cpu > 85:
            recommendations.append(
                "High CPU utilization detected - consider horizontal scaling or CPU optimization"
            )

        if max_memory > 85:
            recommendations.append(
                "High memory utilization detected - optimize memory usage or increase available memory"
            )

        if not recommendations:
            recommendations.append(
                "System performed well under tested load - consider testing higher loads or optimizing for better efficiency"
            )

        analysis["recommendations"] = recommendations

        # Log analysis results
        self._log_analysis_results(analysis)

        return analysis

    def _calculate_scalability_efficiency(self) -> float:
        """Calculate how efficiently the system scales with increased load."""
        if len(self.test_results) < 2:
            return 0.0

        # Perfect linear scaling would maintain constant throughput per user
        baseline = self.test_results[0]
        baseline_efficiency = baseline.requests_per_second / baseline.step.user_count

        efficiencies = []
        for result in self.test_results:
            efficiency = result.requests_per_second / result.step.user_count
            efficiencies.append(
                efficiency / baseline_efficiency
            )  # Normalized to baseline

        return sum(efficiencies) / len(efficiencies)

    def _calculate_resource_efficiency(self) -> Dict[str, float]:
        """Calculate resource utilization efficiency."""
        if not self.test_results:
            return {"cpu_efficiency": 0.0, "memory_efficiency": 0.0}

        # Calculate requests per CPU/Memory percent
        cpu_efficiencies = []
        memory_efficiencies = []

        for result in self.test_results:
            if result.avg_cpu_percent > 0:
                cpu_efficiency = result.requests_per_second / result.avg_cpu_percent
                cpu_efficiencies.append(cpu_efficiency)

            if result.avg_memory_percent > 0:
                memory_efficiency = (
                    result.requests_per_second / result.avg_memory_percent
                )
                memory_efficiencies.append(memory_efficiency)

        return {
            "cpu_efficiency": sum(cpu_efficiencies) / len(cpu_efficiencies)
            if cpu_efficiencies
            else 0.0,
            "memory_efficiency": sum(memory_efficiencies) / len(memory_efficiencies)
            if memory_efficiencies
            else 0.0,
        }

    def _log_analysis_results(self, analysis: Dict):
        """Log the complete analysis results."""
        logger.info("\nBREAKING POINT ANALYSIS RESULTS:")
        logger.info(
            f"  Total steps executed: {analysis['test_summary']['total_steps']}"
        )
        logger.info(
            f"  Maximum users tested: {analysis['test_summary']['max_users_tested']}"
        )

        if analysis["test_summary"]["breaking_point_detected"]:
            logger.warning(
                f"  Breaking point detected: {analysis['test_summary']['breaking_point_users']} users"
            )
        else:
            logger.info("  No breaking point detected within tested range")

        logger.info("\nPerformance Degradation:")
        logger.info(
            f"  Response time increase: {analysis['performance_degradation']['response_time_increase_percent']:.1f}%"
        )
        logger.info(
            f"  Throughput change: {analysis['performance_degradation']['throughput_change_percent']:.1f}%"
        )
        logger.info(
            f"  Final error rate: {analysis['performance_degradation']['error_rate_at_max_load']:.2f}%"
        )
        logger.info(
            f"  Scalability efficiency: {analysis['performance_degradation']['scalability_efficiency']:.2f}"
        )

        logger.info("\nResource Utilization:")
        logger.info(
            f"  Peak CPU: {analysis['resource_utilization']['peak_cpu_utilization']:.1f}%"
        )
        logger.info(
            f"  Peak Memory: {analysis['resource_utilization']['peak_memory_utilization']:.1f}%"
        )
        logger.info(
            f"  CPU bottleneck: {analysis['resource_utilization']['cpu_bottleneck']}"
        )
        logger.info(
            f"  Memory bottleneck: {analysis['resource_utilization']['memory_bottleneck']}"
        )

        logger.info("\nRecommendations:")
        for i, rec in enumerate(analysis["recommendations"], 1):
            logger.info(f"  {i}. {rec}")

    def run_complete_analysis(self) -> Dict:
        """Run complete breaking point analysis."""
        logger.info("Starting Breaking Point Analysis")

        # Generate load steps
        load_steps = self.generate_load_steps()
        logger.info(f"Generated {len(load_steps)} load testing steps")

        # Execute each step
        for step in load_steps:
            try:
                result = self.run_load_step(step)
                self.test_results.append(result)

                # Check if breaking point is reached
                if result.is_breaking_point and not self.breaking_point_found:
                    self.breaking_point_found = True
                    self.breaking_point_step = step.step_number
                    logger.error(
                        f"Breaking point detected at step {step.step_number} ({step.user_count} users)"
                    )

                    # Continue for one more step to confirm
                    continue

                # If we already found breaking point, stop after confirmation step
                if (
                    self.breaking_point_found
                    and step.step_number > self.breaking_point_step + 1
                ):
                    logger.info("Breaking point confirmed, stopping analysis")
                    break

            except Exception as e:
                logger.error(f"Failed to execute step {step.step_number}: {str(e)}")
                break

        # Analyze results
        analysis = self.analyze_breaking_points()

        # Save results to file
        self._save_results_to_file(analysis)

        return analysis

    def _save_results_to_file(self, analysis: Dict):
        """Save analysis results to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"breaking_point_analysis_{timestamp}.json"

        # Prepare serializable data
        serializable_results = {
            "analysis": analysis,
            "detailed_results": [
                {
                    "step_number": result.step.step_number,
                    "user_count": result.step.user_count,
                    "duration_seconds": result.step.duration_seconds,
                    "batch_jobs": result.step.batch_jobs,
                    "avg_response_time": result.avg_response_time,
                    "p95_response_time": result.p95_response_time,
                    "p99_response_time": result.p99_response_time,
                    "requests_per_second": result.requests_per_second,
                    "error_rate": result.error_rate,
                    "success_rate": result.success_rate,
                    "total_requests": result.total_requests,
                    "failed_requests": result.failed_requests,
                    "avg_cpu_percent": result.avg_cpu_percent,
                    "avg_memory_percent": result.avg_memory_percent,
                    "peak_cpu_percent": result.peak_cpu_percent,
                    "peak_memory_percent": result.peak_memory_percent,
                    "is_breaking_point": result.is_breaking_point,
                    "breaking_point_indicators": result.breaking_point_indicators,
                }
                for result in self.test_results
            ],
        }

        try:
            with open(filename, "w") as f:
                json.dump(serializable_results, f, indent=2)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save results to file: {str(e)}")


class ResourceMonitor:
    """Monitor system resources during load testing."""

    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.monitoring = False
        self.cpu_samples = []
        self.memory_samples = []
        self.monitor_thread = None

    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.cpu_samples = []
        self.memory_samples = []

        import threading

        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                memory_percent = psutil.virtual_memory().percent

                self.cpu_samples.append(cpu_percent)
                self.memory_samples.append(memory_percent)

                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Error in resource monitoring: {str(e)}")
                break

    def get_stats(self) -> Dict[str, float]:
        """Get resource utilization statistics."""
        if not self.cpu_samples or not self.memory_samples:
            return {
                "avg_cpu_percent": 0,
                "avg_memory_percent": 0,
                "peak_cpu_percent": 0,
                "peak_memory_percent": 0,
            }

        return {
            "avg_cpu_percent": sum(self.cpu_samples) / len(self.cpu_samples),
            "avg_memory_percent": sum(self.memory_samples) / len(self.memory_samples),
            "peak_cpu_percent": max(self.cpu_samples),
            "peak_memory_percent": max(self.memory_samples),
        }


def main():
    """Main function for running breaking point analysis."""
    parser = argparse.ArgumentParser(
        description="Breaking Point Analysis for BSN Knowledge System"
    )
    parser.add_argument(
        "--host", default="http://localhost:8000", help="Target host URL"
    )
    parser.add_argument(
        "--max-users", type=int, default=300, help="Maximum number of users to test"
    )
    parser.add_argument(
        "--increment", type=int, default=25, help="User increment per step"
    )
    parser.add_argument(
        "--duration-per-step",
        type=int,
        default=180,
        help="Duration of each step in seconds",
    )
    parser.add_argument(
        "--monitor-resources", action="store_true", help="Enable resource monitoring"
    )
    parser.add_argument(
        "--output-file", help="Output file for results (default: auto-generated)"
    )

    args = parser.parse_args()

    # Create analyzer
    analyzer = BreakingPointAnalyzer(
        base_url=args.host,
        max_users=args.max_users,
        increment=args.increment,
        duration_per_step=args.duration_per_step,
        monitor_resources=args.monitor_resources,
    )

    # Run analysis
    try:
        results = analyzer.run_complete_analysis()

        logger.info(f"\n{'='*80}")
        logger.info("BREAKING POINT ANALYSIS COMPLETED SUCCESSFULLY")
        logger.info(f"{'='*80}")

        if results["test_summary"]["breaking_point_detected"]:
            logger.warning(
                f"Breaking point detected at {results['test_summary']['breaking_point_users']} concurrent users"
            )
        else:
            logger.info(
                f"No breaking point detected up to {results['test_summary']['max_users_tested']} concurrent users"
            )

        return 0

    except KeyboardInterrupt:
        logger.info("\nBreaking point analysis interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Breaking point analysis failed: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())
