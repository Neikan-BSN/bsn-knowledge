"""Performance Benchmarks and Baseline Management.

Defines and tracks performance baselines for:
- API response times
- Database query performance
- RAGnostic integration latency
- Concurrent user handling
- Resource utilization thresholds
"""

import json
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PerformanceThreshold:
    """Defines a performance threshold with tolerance levels."""

    metric_name: str
    baseline_value: float
    unit: str
    tolerance_warning: float  # % above baseline that triggers warning
    tolerance_critical: float  # % above baseline that triggers critical alert
    description: str = ""

    def check_performance(self, actual_value: float) -> tuple[str, str]:
        """Check actual performance against thresholds.

        Returns:
            tuple: (status, message) where status is 'good', 'warning', or 'critical'
        """
        if actual_value <= self.baseline_value * (1 + self.tolerance_warning / 100):
            return (
                "good",
                f"{self.metric_name} within acceptable range: {actual_value:.3f}{self.unit}",
            )
        elif actual_value <= self.baseline_value * (1 + self.tolerance_critical / 100):
            return (
                "warning",
                f"{self.metric_name} exceeded warning threshold: {actual_value:.3f}{self.unit} (baseline: {self.baseline_value:.3f}{self.unit})",
            )
        else:
            return (
                "critical",
                f"{self.metric_name} exceeded critical threshold: {actual_value:.3f}{self.unit} (baseline: {self.baseline_value:.3f}{self.unit})",
            )


@dataclass
class PerformanceMetric:
    """Represents a single performance measurement."""

    timestamp: datetime
    metric_name: str
    value: float
    unit: str
    context: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


@dataclass
class PerformanceBenchmark:
    """Complete performance benchmark with historical data."""

    benchmark_name: str
    description: str
    thresholds: dict[str, PerformanceThreshold]
    baseline_established_at: datetime
    measurements: list[PerformanceMetric] = field(default_factory=list)

    def add_measurement(self, metric: PerformanceMetric):
        """Add a new performance measurement."""
        self.measurements.append(metric)

        # Keep only last 1000 measurements to prevent memory issues
        if len(self.measurements) > 1000:
            self.measurements = self.measurements[-1000:]

    def get_recent_stats(self, metric_name: str, hours: int = 24) -> dict[str, float]:
        """Get statistics for recent measurements."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_measurements = [
            m
            for m in self.measurements
            if m.metric_name == metric_name and m.timestamp >= cutoff_time
        ]

        if not recent_measurements:
            return {}

        values = [m.value for m in recent_measurements]
        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "p95": statistics.quantiles(values, n=20)[18]
            if len(values) >= 20
            else max(values),
            "p99": statistics.quantiles(values, n=100)[98]
            if len(values) >= 100
            else max(values),
        }


class PerformanceBenchmarkManager:
    """Manages performance benchmarks and thresholds."""

    def __init__(self, benchmark_file: str | None = None):
        self.benchmark_file = Path(benchmark_file or "performance_benchmarks.json")
        self.benchmarks: dict[str, PerformanceBenchmark] = {}
        self.load_benchmarks()

        # Initialize default BSN Knowledge benchmarks
        self._initialize_default_benchmarks()

    def _initialize_default_benchmarks(self):
        """Initialize default performance benchmarks for BSN Knowledge."""

        # API Response Time Benchmarks
        api_thresholds = {
            "health_check": PerformanceThreshold(
                metric_name="Health Check Response Time",
                baseline_value=0.050,  # 50ms baseline
                unit="s",
                tolerance_warning=100,  # 100ms warning
                tolerance_critical=300,  # 150ms critical
                description="Health endpoint response time",
            ),
            "authentication": PerformanceThreshold(
                metric_name="Authentication Response Time",
                baseline_value=0.200,  # 200ms baseline
                unit="s",
                tolerance_warning=150,  # 500ms warning
                tolerance_critical=400,  # 1000ms critical
                description="User authentication response time",
            ),
            "nclex_generation": PerformanceThreshold(
                metric_name="NCLEX Question Generation Time",
                baseline_value=2.000,  # 2s baseline
                unit="s",
                tolerance_warning=50,  # 3s warning
                tolerance_critical=150,  # 5s critical
                description="NCLEX question generation via RAGnostic",
            ),
            "study_guide_creation": PerformanceThreshold(
                metric_name="Study Guide Creation Time",
                baseline_value=1.500,  # 1.5s baseline
                unit="s",
                tolerance_warning=67,  # 2.5s warning
                tolerance_critical=133,  # 3.5s critical
                description="Study guide generation response time",
            ),
            "analytics_query": PerformanceThreshold(
                metric_name="Analytics Query Response Time",
                baseline_value=0.300,  # 300ms baseline
                unit="s",
                tolerance_warning=100,  # 600ms warning
                tolerance_critical=233,  # 1000ms critical
                description="Student analytics query response time",
            ),
        }

        self.benchmarks["api_performance"] = PerformanceBenchmark(
            benchmark_name="API Performance",
            description="BSN Knowledge API endpoint response times",
            thresholds=api_thresholds,
            baseline_established_at=datetime.now(),
        )

        # Throughput Benchmarks
        throughput_thresholds = {
            "concurrent_users": PerformanceThreshold(
                metric_name="Concurrent User Capacity",
                baseline_value=100.0,  # 100 concurrent users baseline
                unit=" users",
                tolerance_warning=-20,  # 80 users warning (negative because lower is worse)
                tolerance_critical=-50,  # 50 users critical
                description="Maximum concurrent authenticated users",
            ),
            "requests_per_second": PerformanceThreshold(
                metric_name="Request Throughput",
                baseline_value=50.0,  # 50 RPS baseline
                unit=" req/s",
                tolerance_warning=-30,  # 35 RPS warning
                tolerance_critical=-50,  # 25 RPS critical
                description="Sustained request throughput capacity",
            ),
            "ragnostic_batch_jobs": PerformanceThreshold(
                metric_name="RAGnostic Concurrent Jobs",
                baseline_value=10.0,  # 10 concurrent jobs baseline
                unit=" jobs",
                tolerance_warning=-30,  # 7 jobs warning
                tolerance_critical=-50,  # 5 jobs critical
                description="Concurrent RAGnostic batch processing jobs",
            ),
        }

        self.benchmarks["throughput_performance"] = PerformanceBenchmark(
            benchmark_name="Throughput Performance",
            description="System throughput and capacity benchmarks",
            thresholds=throughput_thresholds,
            baseline_established_at=datetime.now(),
        )

        # Resource Utilization Benchmarks
        resource_thresholds = {
            "cpu_utilization": PerformanceThreshold(
                metric_name="CPU Utilization",
                baseline_value=60.0,  # 60% baseline
                unit="%",
                tolerance_warning=17,  # 70% warning
                tolerance_critical=33,  # 80% critical
                description="Average CPU utilization under load",
            ),
            "memory_usage": PerformanceThreshold(
                metric_name="Memory Usage",
                baseline_value=70.0,  # 70% baseline
                unit="%",
                tolerance_warning=14,  # 80% warning
                tolerance_critical=29,  # 90% critical
                description="Memory utilization percentage",
            ),
            "database_connections": PerformanceThreshold(
                metric_name="Database Connection Usage",
                baseline_value=60.0,  # 60% of pool baseline
                unit="%",
                tolerance_warning=17,  # 70% warning
                tolerance_critical=33,  # 80% critical
                description="Database connection pool utilization",
            ),
        }

        self.benchmarks["resource_utilization"] = PerformanceBenchmark(
            benchmark_name="Resource Utilization",
            description="System resource utilization benchmarks",
            thresholds=resource_thresholds,
            baseline_established_at=datetime.now(),
        )

        # Error Rate Benchmarks
        error_thresholds = {
            "api_error_rate": PerformanceThreshold(
                metric_name="API Error Rate",
                baseline_value=0.1,  # 0.1% baseline
                unit="%",
                tolerance_warning=400,  # 0.5% warning
                tolerance_critical=900,  # 1.0% critical
                description="API endpoint error rate percentage",
            ),
            "ragnostic_failure_rate": PerformanceThreshold(
                metric_name="RAGnostic Integration Failure Rate",
                baseline_value=2.0,  # 2% baseline
                unit="%",
                tolerance_warning=150,  # 5% warning
                tolerance_critical=400,  # 10% critical
                description="RAGnostic service integration failure rate",
            ),
            "database_error_rate": PerformanceThreshold(
                metric_name="Database Error Rate",
                baseline_value=0.05,  # 0.05% baseline
                unit="%",
                tolerance_warning=600,  # 0.35% warning
                tolerance_critical=1900,  # 1.0% critical
                description="Database operation error rate",
            ),
        }

        self.benchmarks["error_rates"] = PerformanceBenchmark(
            benchmark_name="Error Rates",
            description="System error rate benchmarks",
            thresholds=error_thresholds,
            baseline_established_at=datetime.now(),
        )

        logger.info(
            f"Initialized {len(self.benchmarks)} performance benchmark categories"
        )

    def record_measurement(
        self,
        benchmark_name: str,
        metric_name: str,
        value: float,
        unit: str,
        context: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ):
        """Record a performance measurement."""
        if benchmark_name not in self.benchmarks:
            logger.warning(
                f"Benchmark '{benchmark_name}' not found. Creating new benchmark."
            )
            self.benchmarks[benchmark_name] = PerformanceBenchmark(
                benchmark_name=benchmark_name,
                description=f"Auto-created benchmark for {benchmark_name}",
                thresholds={},
                baseline_established_at=datetime.now(),
            )

        metric = PerformanceMetric(
            timestamp=datetime.now(),
            metric_name=metric_name,
            value=value,
            unit=unit,
            context=context or {},
            tags=tags or [],
        )

        self.benchmarks[benchmark_name].add_measurement(metric)

        # Check against thresholds if they exist
        benchmark = self.benchmarks[benchmark_name]
        if metric_name in benchmark.thresholds:
            threshold = benchmark.thresholds[metric_name]
            status, message = threshold.check_performance(value)

            if status == "warning":
                logger.warning(f"PERFORMANCE WARNING: {message}")
            elif status == "critical":
                logger.error(f"PERFORMANCE CRITICAL: {message}")
            else:
                logger.debug(f"Performance OK: {message}")

    def get_benchmark_status(self, benchmark_name: str) -> dict[str, Any]:
        """Get current status of all metrics in a benchmark."""
        if benchmark_name not in self.benchmarks:
            return {"error": f"Benchmark '{benchmark_name}' not found"}

        benchmark = self.benchmarks[benchmark_name]
        status = {
            "benchmark_name": benchmark_name,
            "description": benchmark.description,
            "baseline_established_at": benchmark.baseline_established_at.isoformat(),
            "metrics": {},
        }

        for threshold_name, threshold in benchmark.thresholds.items():
            recent_stats = benchmark.get_recent_stats(threshold_name, hours=1)

            metric_status = {
                "threshold": {
                    "baseline": threshold.baseline_value,
                    "warning_threshold": threshold.baseline_value
                    * (1 + threshold.tolerance_warning / 100),
                    "critical_threshold": threshold.baseline_value
                    * (1 + threshold.tolerance_critical / 100),
                    "unit": threshold.unit,
                    "description": threshold.description,
                },
                "recent_stats": recent_stats,
            }

            # Check current status if we have recent data
            if recent_stats:
                current_value = recent_stats["mean"]
                check_status, message = threshold.check_performance(current_value)
                metric_status["current_status"] = check_status
                metric_status["status_message"] = message

            status["metrics"][threshold_name] = metric_status

        return status

    def generate_performance_report(self) -> dict[str, Any]:
        """Generate comprehensive performance report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "report_type": "comprehensive_performance_analysis",
            "system_info": self._get_system_info(),
            "benchmarks": {},
        }

        overall_status = "good"
        critical_issues = []
        warning_issues = []

        for benchmark_name in self.benchmarks:
            benchmark_status = self.get_benchmark_status(benchmark_name)
            report["benchmarks"][benchmark_name] = benchmark_status

            # Analyze overall system health
            for metric_name, metric_data in benchmark_status.get("metrics", {}).items():
                current_status = metric_data.get("current_status")
                if current_status == "critical":
                    overall_status = "critical"
                    critical_issues.append(
                        metric_data.get(
                            "status_message", f"Critical issue in {metric_name}"
                        )
                    )
                elif current_status == "warning" and overall_status != "critical":
                    overall_status = "warning"
                    warning_issues.append(
                        metric_data.get("status_message", f"Warning in {metric_name}")
                    )

        report["overall_status"] = overall_status
        report["critical_issues"] = critical_issues
        report["warning_issues"] = warning_issues
        report["recommendations"] = self._generate_recommendations(
            critical_issues, warning_issues
        )

        return report

    def _get_system_info(self) -> dict[str, Any]:
        """Get current system information."""
        return {
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total_gb": psutil.virtual_memory().total / (1024**3),
            "memory_available_gb": psutil.virtual_memory().available / (1024**3),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage("/").percent,
            "load_average": psutil.getloadavg()
            if hasattr(psutil, "getloadavg")
            else None,
        }

    def _generate_recommendations(
        self, critical_issues: list[str], warning_issues: list[str]
    ) -> list[str]:
        """Generate performance improvement recommendations."""
        recommendations = []

        if critical_issues:
            recommendations.append(
                "🔴 IMMEDIATE ACTION REQUIRED: Critical performance issues detected"
            )

            if any("CPU" in issue for issue in critical_issues):
                recommendations.append(
                    "• Scale up CPU resources or optimize CPU-intensive operations"
                )

            if any("Memory" in issue for issue in critical_issues):
                recommendations.append(
                    "• Investigate memory leaks and consider scaling up memory resources"
                )

            if any("Response Time" in issue for issue in critical_issues):
                recommendations.append(
                    "• Review database queries and external service integrations for optimization"
                )

            if any("RAGnostic" in issue for issue in critical_issues):
                recommendations.append(
                    "• Check RAGnostic service health and consider scaling or optimization"
                )

        if warning_issues:
            recommendations.append(
                "🟡 MONITORING REQUIRED: Performance warnings detected"
            )

            if any("Error Rate" in issue for issue in warning_issues):
                recommendations.append(
                    "• Review error logs and implement additional error handling"
                )

            if any("Throughput" in issue for issue in warning_issues):
                recommendations.append(
                    "• Consider implementing caching or optimizing request handling"
                )

        if not critical_issues and not warning_issues:
            recommendations.append(
                "✅ All performance metrics within acceptable ranges"
            )
            recommendations.append(
                "• Continue monitoring and consider establishing new baselines if performance has improved"
            )

        return recommendations

    def save_benchmarks(self):
        """Save benchmarks to file."""
        try:
            # Convert to serializable format
            serializable_benchmarks = {}
            for name, benchmark in self.benchmarks.items():
                serializable_benchmarks[name] = {
                    "benchmark_name": benchmark.benchmark_name,
                    "description": benchmark.description,
                    "baseline_established_at": benchmark.baseline_established_at.isoformat(),
                    "thresholds": {
                        threshold_name: {
                            "metric_name": threshold.metric_name,
                            "baseline_value": threshold.baseline_value,
                            "unit": threshold.unit,
                            "tolerance_warning": threshold.tolerance_warning,
                            "tolerance_critical": threshold.tolerance_critical,
                            "description": threshold.description,
                        }
                        for threshold_name, threshold in benchmark.thresholds.items()
                    },
                    "recent_measurements": [
                        {
                            "timestamp": measurement.timestamp.isoformat(),
                            "metric_name": measurement.metric_name,
                            "value": measurement.value,
                            "unit": measurement.unit,
                            "context": measurement.context,
                            "tags": measurement.tags,
                        }
                        for measurement in benchmark.measurements[
                            -100:
                        ]  # Save last 100 measurements
                    ],
                }

            with open(self.benchmark_file, "w") as f:
                json.dump(serializable_benchmarks, f, indent=2)

            logger.info(f"Saved benchmarks to {self.benchmark_file}")

        except Exception as e:
            logger.error(f"Failed to save benchmarks: {str(e)}")

    def load_benchmarks(self):
        """Load benchmarks from file."""
        if not self.benchmark_file.exists():
            logger.info(f"No existing benchmark file found at {self.benchmark_file}")
            return

        try:
            with open(self.benchmark_file) as f:
                data = json.load(f)

            for name, benchmark_data in data.items():
                # Reconstruct thresholds
                thresholds = {}
                for threshold_name, threshold_data in benchmark_data[
                    "thresholds"
                ].items():
                    thresholds[threshold_name] = PerformanceThreshold(**threshold_data)

                # Reconstruct benchmark
                benchmark = PerformanceBenchmark(
                    benchmark_name=benchmark_data["benchmark_name"],
                    description=benchmark_data["description"],
                    thresholds=thresholds,
                    baseline_established_at=datetime.fromisoformat(
                        benchmark_data["baseline_established_at"]
                    ),
                )

                # Reconstruct measurements
                for measurement_data in benchmark_data.get("recent_measurements", []):
                    measurement = PerformanceMetric(
                        timestamp=datetime.fromisoformat(measurement_data["timestamp"]),
                        metric_name=measurement_data["metric_name"],
                        value=measurement_data["value"],
                        unit=measurement_data["unit"],
                        context=measurement_data["context"],
                        tags=measurement_data["tags"],
                    )
                    benchmark.add_measurement(measurement)

                self.benchmarks[name] = benchmark

            logger.info(
                f"Loaded {len(self.benchmarks)} benchmarks from {self.benchmark_file}"
            )

        except Exception as e:
            logger.error(f"Failed to load benchmarks: {str(e)}")


# Global benchmark manager instance
benchmark_manager = PerformanceBenchmarkManager()


# Convenience functions for easy integration
def record_api_response_time(
    endpoint: str, response_time: float, status_code: int = 200
):
    """Record API response time measurement."""
    metric_name = endpoint.replace("/", "_").replace("-", "_")
    benchmark_manager.record_measurement(
        "api_performance",
        metric_name,
        response_time,
        "s",
        context={"endpoint": endpoint, "status_code": status_code},
        tags=["api", "response_time"],
    )


def record_concurrent_users(user_count: int):
    """Record concurrent user count."""
    benchmark_manager.record_measurement(
        "throughput_performance",
        "concurrent_users",
        user_count,
        " users",
        tags=["throughput", "concurrency"],
    )


def record_resource_usage(
    cpu_percent: float, memory_percent: float, db_connection_percent: float
):
    """Record system resource usage."""
    benchmark_manager.record_measurement(
        "resource_utilization",
        "cpu_utilization",
        cpu_percent,
        "%",
        tags=["resource", "cpu"],
    )
    benchmark_manager.record_measurement(
        "resource_utilization",
        "memory_usage",
        memory_percent,
        "%",
        tags=["resource", "memory"],
    )
    benchmark_manager.record_measurement(
        "resource_utilization",
        "database_connections",
        db_connection_percent,
        "%",
        tags=["resource", "database"],
    )


def record_error_rate(error_type: str, error_rate: float):
    """Record error rate measurement."""
    benchmark_manager.record_measurement(
        "error_rates", error_type, error_rate, "%", tags=["error_rate", error_type]
    )


def get_performance_report() -> dict[str, Any]:
    """Get comprehensive performance report."""
    return benchmark_manager.generate_performance_report()


def save_performance_data():
    """Save performance data to disk."""
    benchmark_manager.save_benchmarks()


# Example usage and testing
if __name__ == "__main__":
    # Example of recording performance measurements
    record_api_response_time("/health", 0.045)
    record_api_response_time("/api/v1/auth/login", 0.180)
    record_api_response_time("/api/v1/nclex/generate", 2.100)

    record_concurrent_users(85)
    record_resource_usage(65.0, 72.0, 45.0)
    record_error_rate("api_error_rate", 0.08)

    # Generate and print performance report
    report = get_performance_report()
    print(json.dumps(report, indent=2))

    # Save data
    save_performance_data()
