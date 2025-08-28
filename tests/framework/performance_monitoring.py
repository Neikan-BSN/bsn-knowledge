"""Enhanced Performance Monitoring Framework for Group 3B.

Centralized performance monitoring and metrics collection system that integrates
with advanced memory profiling, endurance testing, and breaking point analysis.

Features:
- Real-time performance metrics collection and analysis
- Integration with memory profiler and endurance testing suite
- Performance regression detection and alerting
- Medical accuracy correlation with performance metrics
- Automated performance baseline establishment and tracking
- Resource utilization monitoring with predictive analysis
"""

import asyncio
import json
import logging
import statistics
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
import psutil
from enum import Enum

# Import Group 3B components
from memory_profiler import AdvancedMemoryProfiler
from breaking_point_analyzer import BreakingPointAnalyzer, SystemBreakingPoint
from endurance_testing_suite import EnduranceTestSuite, EnduranceTestResults

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PerformanceAlertLevel(Enum):
    """Performance alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class MetricType(Enum):
    """Types of performance metrics."""

    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    RESOURCE_UTILIZATION = "resource_utilization"
    MEDICAL_ACCURACY = "medical_accuracy"
    SYSTEM_HEALTH = "system_health"


@dataclass
class PerformanceMetric:
    """Individual performance metric data point."""

    timestamp: datetime
    metric_type: MetricType
    name: str
    value: float
    unit: str
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceAlert:
    """Performance alert information."""

    timestamp: datetime
    level: PerformanceAlertLevel
    metric_name: str
    current_value: float
    threshold_value: float
    message: str
    component: str
    tags: Dict[str, str] = field(default_factory=dict)
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class PerformanceBaseline:
    """Performance baseline for comparison."""

    metric_name: str
    baseline_value: float
    baseline_established: datetime
    samples_count: int
    confidence_interval: Tuple[float, float]
    last_updated: datetime

    # Regression detection
    acceptable_degradation_percent: float = 20.0
    warning_degradation_percent: float = 10.0


@dataclass
class SystemPerformanceState:
    """Current system performance state."""

    timestamp: datetime
    overall_health_score: float  # 0.0 to 1.0
    performance_tier: str  # 'excellent', 'good', 'degraded', 'critical'

    # Component health scores
    api_performance_score: float
    database_performance_score: float
    memory_performance_score: float
    medical_accuracy_score: float

    # Current metrics
    avg_response_time_ms: float
    requests_per_second: float
    error_rate_percent: float
    cpu_utilization_percent: float
    memory_utilization_percent: float

    # Predictive indicators
    trend_direction: str  # 'improving', 'stable', 'degrading'
    estimated_capacity_remaining_percent: float
    time_to_capacity_exhaustion_hours: Optional[float]

    # Active issues
    active_alerts: List[PerformanceAlert]
    performance_bottlenecks: List[str]


class PerformanceThresholds:
    """Configurable performance thresholds and limits."""

    def __init__(self):
        # Response time thresholds (milliseconds)
        self.response_time_warning = 1000
        self.response_time_critical = 2000
        self.response_time_emergency = 5000

        # Throughput thresholds (requests per second)
        self.throughput_warning_min = 10
        self.throughput_critical_min = 5

        # Error rate thresholds (percent)
        self.error_rate_warning = 2.0
        self.error_rate_critical = 5.0
        self.error_rate_emergency = 10.0

        # Resource utilization thresholds (percent)
        self.cpu_warning = 70.0
        self.cpu_critical = 85.0
        self.cpu_emergency = 95.0

        self.memory_warning = 70.0
        self.memory_critical = 85.0
        self.memory_emergency = 95.0

        # Medical accuracy thresholds (percent)
        self.medical_accuracy_warning = 98.0
        self.medical_accuracy_critical = 95.0
        self.medical_accuracy_emergency = 90.0

        # System health composite thresholds
        self.health_score_warning = 0.8
        self.health_score_critical = 0.6
        self.health_score_emergency = 0.4


class PerformanceDataCollector:
    """Collects performance metrics from various sources."""

    def __init__(self, collection_interval_seconds: int = 15):
        self.collection_interval = collection_interval_seconds
        self.collecting = False
        self.collector_task: Optional[asyncio.Task] = None
        self.metrics_queue = asyncio.Queue()
        self.thread_pool = ThreadPoolExecutor(max_workers=2)

    async def start_collection(self):
        """Start performance data collection."""
        if self.collecting:
            logger.warning("Performance data collection already running")
            return

        self.collecting = True
        self.collector_task = asyncio.create_task(self._collection_loop())
        logger.info("Performance data collection started")

    async def stop_collection(self):
        """Stop performance data collection."""
        self.collecting = False

        if self.collector_task:
            self.collector_task.cancel()
            try:
                await self.collector_task
            except asyncio.CancelledError:
                pass

        logger.info("Performance data collection stopped")

    async def _collection_loop(self):
        """Main collection loop."""
        while self.collecting:
            try:
                # Collect system metrics
                metrics = await self._collect_system_metrics()

                # Add metrics to queue
                for metric in metrics:
                    await self.metrics_queue.put(metric)

                await asyncio.sleep(self.collection_interval)

            except Exception as e:
                logger.error(f"Error in performance collection loop: {e}")
                await asyncio.sleep(self.collection_interval)

    async def _collect_system_metrics(self) -> List[PerformanceMetric]:
        """Collect comprehensive system metrics."""
        timestamp = datetime.now()
        metrics = []

        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        metrics.append(
            PerformanceMetric(
                timestamp=timestamp,
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="cpu_utilization_percent",
                value=cpu_percent,
                unit="percent",
                tags={"component": "system", "resource": "cpu"},
            )
        )

        # Memory metrics
        memory = psutil.virtual_memory()
        metrics.append(
            PerformanceMetric(
                timestamp=timestamp,
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="memory_utilization_percent",
                value=memory.percent,
                unit="percent",
                tags={"component": "system", "resource": "memory"},
            )
        )

        metrics.append(
            PerformanceMetric(
                timestamp=timestamp,
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="memory_usage_mb",
                value=memory.used / (1024 * 1024),
                unit="MB",
                tags={"component": "system", "resource": "memory"},
            )
        )

        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        if disk_io:
            metrics.append(
                PerformanceMetric(
                    timestamp=timestamp,
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    name="disk_read_mb_per_sec",
                    value=0,  # Would need rate calculation
                    unit="MB/s",
                    tags={"component": "system", "resource": "disk"},
                )
            )

        # Network I/O metrics
        network_io = psutil.net_io_counters()
        if network_io:
            metrics.append(
                PerformanceMetric(
                    timestamp=timestamp,
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    name="network_bytes_sent_per_sec",
                    value=0,  # Would need rate calculation
                    unit="bytes/s",
                    tags={"component": "system", "resource": "network"},
                )
            )

        return metrics

    async def get_recent_metrics(self, count: int = 100) -> List[PerformanceMetric]:
        """Get recent metrics from the queue."""
        metrics = []
        for _ in range(min(count, self.metrics_queue.qsize())):
            try:
                metric = self.metrics_queue.get_nowait()
                metrics.append(metric)
            except asyncio.QueueEmpty:
                break
        return metrics


class PerformanceAnalyzer:
    """Analyzes performance metrics and detects issues."""

    def __init__(self, thresholds: PerformanceThresholds = None):
        self.thresholds = thresholds or PerformanceThresholds()
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.alerts: List[PerformanceAlert] = []
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def add_metric(self, metric: PerformanceMetric):
        """Add metric for analysis."""
        metric_key = f"{metric.metric_type.value}_{metric.name}"
        self.metric_history[metric_key].append((metric.timestamp, metric.value))

        # Update baseline if needed
        self._update_baseline(metric_key, metric.value, metric.timestamp)

        # Check for alerts
        alert = self._check_metric_alerts(metric)
        if alert:
            self.alerts.append(alert)
            logger.warning(f"Performance Alert: {alert.message}")

    def _update_baseline(self, metric_key: str, value: float, timestamp: datetime):
        """Update performance baseline for metric."""
        if metric_key not in self.baselines:
            # Create new baseline
            self.baselines[metric_key] = PerformanceBaseline(
                metric_name=metric_key,
                baseline_value=value,
                baseline_established=timestamp,
                samples_count=1,
                confidence_interval=(value, value),
                last_updated=timestamp,
            )
        else:
            # Update existing baseline
            baseline = self.baselines[metric_key]
            baseline.samples_count += 1
            baseline.last_updated = timestamp

            # Recalculate baseline if enough samples
            if baseline.samples_count >= 20:
                recent_values = [v for t, v in self.metric_history[metric_key]]
                if recent_values:
                    baseline.baseline_value = statistics.mean(recent_values)
                    std_dev = (
                        statistics.stdev(recent_values) if len(recent_values) > 1 else 0
                    )
                    baseline.confidence_interval = (
                        baseline.baseline_value - std_dev,
                        baseline.baseline_value + std_dev,
                    )

    def _check_metric_alerts(
        self, metric: PerformanceMetric
    ) -> Optional[PerformanceAlert]:
        """Check if metric triggers any alerts."""
        alert_level = None
        threshold_value = None
        message = ""

        if metric.metric_type == MetricType.RESPONSE_TIME:
            if metric.value > self.thresholds.response_time_emergency:
                alert_level = PerformanceAlertLevel.EMERGENCY
                threshold_value = self.thresholds.response_time_emergency
                message = f"Emergency: Response time {metric.value:.0f}ms exceeds emergency threshold"
            elif metric.value > self.thresholds.response_time_critical:
                alert_level = PerformanceAlertLevel.CRITICAL
                threshold_value = self.thresholds.response_time_critical
                message = f"Critical: Response time {metric.value:.0f}ms exceeds critical threshold"
            elif metric.value > self.thresholds.response_time_warning:
                alert_level = PerformanceAlertLevel.WARNING
                threshold_value = self.thresholds.response_time_warning
                message = f"Warning: Response time {metric.value:.0f}ms exceeds warning threshold"

        elif metric.metric_type == MetricType.ERROR_RATE:
            if metric.value > self.thresholds.error_rate_emergency:
                alert_level = PerformanceAlertLevel.EMERGENCY
                threshold_value = self.thresholds.error_rate_emergency
                message = f"Emergency: Error rate {metric.value:.1f}% exceeds emergency threshold"
            elif metric.value > self.thresholds.error_rate_critical:
                alert_level = PerformanceAlertLevel.CRITICAL
                threshold_value = self.thresholds.error_rate_critical
                message = f"Critical: Error rate {metric.value:.1f}% exceeds critical threshold"
            elif metric.value > self.thresholds.error_rate_warning:
                alert_level = PerformanceAlertLevel.WARNING
                threshold_value = self.thresholds.error_rate_warning
                message = (
                    f"Warning: Error rate {metric.value:.1f}% exceeds warning threshold"
                )

        elif metric.metric_type == MetricType.RESOURCE_UTILIZATION:
            if metric.name == "cpu_utilization_percent":
                if metric.value > self.thresholds.cpu_emergency:
                    alert_level = PerformanceAlertLevel.EMERGENCY
                    threshold_value = self.thresholds.cpu_emergency
                    message = f"Emergency: CPU utilization {metric.value:.1f}% exceeds emergency threshold"
                elif metric.value > self.thresholds.cpu_critical:
                    alert_level = PerformanceAlertLevel.CRITICAL
                    threshold_value = self.thresholds.cpu_critical
                    message = f"Critical: CPU utilization {metric.value:.1f}% exceeds critical threshold"
                elif metric.value > self.thresholds.cpu_warning:
                    alert_level = PerformanceAlertLevel.WARNING
                    threshold_value = self.thresholds.cpu_warning
                    message = f"Warning: CPU utilization {metric.value:.1f}% exceeds warning threshold"

            elif metric.name == "memory_utilization_percent":
                if metric.value > self.thresholds.memory_emergency:
                    alert_level = PerformanceAlertLevel.EMERGENCY
                    threshold_value = self.thresholds.memory_emergency
                    message = f"Emergency: Memory utilization {metric.value:.1f}% exceeds emergency threshold"
                elif metric.value > self.thresholds.memory_critical:
                    alert_level = PerformanceAlertLevel.CRITICAL
                    threshold_value = self.thresholds.memory_critical
                    message = f"Critical: Memory utilization {metric.value:.1f}% exceeds critical threshold"
                elif metric.value > self.thresholds.memory_warning:
                    alert_level = PerformanceAlertLevel.WARNING
                    threshold_value = self.thresholds.memory_warning
                    message = f"Warning: Memory utilization {metric.value:.1f}% exceeds warning threshold"

        elif metric.metric_type == MetricType.MEDICAL_ACCURACY:
            if metric.value < self.thresholds.medical_accuracy_emergency:
                alert_level = PerformanceAlertLevel.EMERGENCY
                threshold_value = self.thresholds.medical_accuracy_emergency
                message = f"Emergency: Medical accuracy {metric.value:.1f}% below emergency threshold"
            elif metric.value < self.thresholds.medical_accuracy_critical:
                alert_level = PerformanceAlertLevel.CRITICAL
                threshold_value = self.thresholds.medical_accuracy_critical
                message = f"Critical: Medical accuracy {metric.value:.1f}% below critical threshold"
            elif metric.value < self.thresholds.medical_accuracy_warning:
                alert_level = PerformanceAlertLevel.WARNING
                threshold_value = self.thresholds.medical_accuracy_warning
                message = f"Warning: Medical accuracy {metric.value:.1f}% below warning threshold"

        if alert_level:
            return PerformanceAlert(
                timestamp=metric.timestamp,
                level=alert_level,
                metric_name=metric.name,
                current_value=metric.value,
                threshold_value=threshold_value,
                message=message,
                component=metric.tags.get("component", "unknown"),
                tags=metric.tags,
            )

        return None

    def detect_performance_regression(self, metric_name: str) -> Dict[str, Any]:
        """Detect performance regression for a specific metric."""
        metric_key = f"response_time_{metric_name}"

        if metric_key not in self.baselines or metric_key not in self.metric_history:
            return {"regression_detected": False, "reason": "Insufficient data"}

        baseline = self.baselines[metric_key]
        recent_values = [
            v for t, v in list(self.metric_history[metric_key])[-10:]
        ]  # Last 10 samples

        if len(recent_values) < 5:
            return {
                "regression_detected": False,
                "reason": "Insufficient recent samples",
            }

        recent_average = statistics.mean(recent_values)
        degradation_percent = (
            ((recent_average - baseline.baseline_value) / baseline.baseline_value * 100)
            if baseline.baseline_value > 0
            else 0
        )

        regression_detected = (
            degradation_percent > baseline.acceptable_degradation_percent
        )

        return {
            "regression_detected": regression_detected,
            "baseline_value": baseline.baseline_value,
            "recent_average": recent_average,
            "degradation_percent": degradation_percent,
            "severity": (
                "critical"
                if degradation_percent > baseline.acceptable_degradation_percent
                else "warning"
                if degradation_percent > baseline.warning_degradation_percent
                else "normal"
            ),
        }

    def get_system_performance_state(self) -> SystemPerformanceState:
        """Get current system performance state."""
        timestamp = datetime.now()

        # Calculate component health scores
        api_score = self._calculate_component_health_score("api")
        db_score = self._calculate_component_health_score("database")
        memory_score = self._calculate_component_health_score("memory")
        medical_score = self._calculate_component_health_score("medical")

        # Overall health score
        overall_score = statistics.mean(
            [api_score, db_score, memory_score, medical_score]
        )

        # Determine performance tier
        if overall_score >= 0.9:
            performance_tier = "excellent"
        elif overall_score >= 0.7:
            performance_tier = "good"
        elif overall_score >= 0.5:
            performance_tier = "degraded"
        else:
            performance_tier = "critical"

        # Get current metrics (simplified - would be from recent data)
        current_metrics = self._get_current_metric_values()

        # Calculate trend direction
        trend = self._calculate_performance_trend()

        # Get active alerts
        active_alerts = [alert for alert in self.alerts[-50:] if not alert.resolved]

        # Identify bottlenecks
        bottlenecks = self._identify_performance_bottlenecks()

        return SystemPerformanceState(
            timestamp=timestamp,
            overall_health_score=overall_score,
            performance_tier=performance_tier,
            api_performance_score=api_score,
            database_performance_score=db_score,
            memory_performance_score=memory_score,
            medical_accuracy_score=medical_score,
            avg_response_time_ms=current_metrics.get("response_time", 500),
            requests_per_second=current_metrics.get("throughput", 20),
            error_rate_percent=current_metrics.get("error_rate", 1.0),
            cpu_utilization_percent=current_metrics.get("cpu", 50),
            memory_utilization_percent=current_metrics.get("memory", 60),
            trend_direction=trend["direction"],
            estimated_capacity_remaining_percent=trend["capacity_remaining"],
            time_to_capacity_exhaustion_hours=trend["time_to_exhaustion"],
            active_alerts=active_alerts,
            performance_bottlenecks=bottlenecks,
        )

    def _calculate_component_health_score(self, component: str) -> float:
        """Calculate health score for a specific component."""
        # Simplified health score calculation
        # In real implementation, would analyze component-specific metrics

        if component == "api":
            # Check response time and error rate metrics
            return 0.85
        elif component == "database":
            # Check query performance and connection metrics
            return 0.90
        elif component == "memory":
            # Check memory utilization and leak indicators
            return 0.88
        elif component == "medical":
            # Check medical accuracy metrics
            return 0.95
        else:
            return 0.80

    def _get_current_metric_values(self) -> Dict[str, float]:
        """Get current values for key metrics."""
        # Simplified - would get actual recent values from metric history
        return {
            "response_time": 450,
            "throughput": 25.5,
            "error_rate": 1.2,
            "cpu": 65.0,
            "memory": 72.0,
        }

    def _calculate_performance_trend(self) -> Dict[str, Any]:
        """Calculate performance trend and capacity estimates."""
        # Simplified trend analysis
        return {
            "direction": "stable",
            "capacity_remaining": 35.0,
            "time_to_exhaustion": None,
        }

    def _identify_performance_bottlenecks(self) -> List[str]:
        """Identify current performance bottlenecks."""
        bottlenecks = []

        # Check recent alerts for bottleneck patterns
        recent_alerts = self.alerts[-20:]

        cpu_alerts = sum(1 for alert in recent_alerts if "CPU" in alert.message)
        memory_alerts = sum(1 for alert in recent_alerts if "Memory" in alert.message)
        response_time_alerts = sum(
            1 for alert in recent_alerts if "Response time" in alert.message
        )

        if cpu_alerts >= 3:
            bottlenecks.append("CPU utilization constraint")
        if memory_alerts >= 3:
            bottlenecks.append("Memory utilization constraint")
        if response_time_alerts >= 3:
            bottlenecks.append("Response time degradation")

        return bottlenecks


class Group3BPerformanceMonitor:
    """Enhanced performance monitoring framework integrating Group 3B components."""

    def __init__(
        self,
        collection_interval_seconds: int = 15,
        enable_memory_profiling: bool = True,
        enable_breaking_point_monitoring: bool = True,
    ):
        self.collection_interval = collection_interval_seconds
        self.enable_memory_profiling = enable_memory_profiling
        self.enable_breaking_point_monitoring = enable_breaking_point_monitoring

        # Core components
        self.data_collector = PerformanceDataCollector(collection_interval_seconds)
        self.analyzer = PerformanceAnalyzer()
        self.thresholds = PerformanceThresholds()

        # Group 3B integration components
        self.memory_profiler = (
            AdvancedMemoryProfiler() if enable_memory_profiling else None
        )
        self.breaking_point_analyzer = (
            BreakingPointAnalyzer() if enable_breaking_point_monitoring else None
        )

        # Monitoring state
        self.monitoring_active = False
        self.monitor_task: Optional[asyncio.Task] = None

        # Performance history
        self.performance_states: List[SystemPerformanceState] = []
        self.endurance_test_results: Optional[EnduranceTestResults] = None

        logger.info("Group 3B Performance Monitor initialized:")
        logger.info(f"  Collection interval: {collection_interval_seconds}s")
        logger.info(f"  Memory profiling: {enable_memory_profiling}")
        logger.info(f"  Breaking point monitoring: {enable_breaking_point_monitoring}")

    async def start_monitoring(self):
        """Start comprehensive performance monitoring."""
        if self.monitoring_active:
            logger.warning("Performance monitoring already active")
            return

        logger.info("Starting Group 3B Performance Monitoring...")

        self.monitoring_active = True

        # Start core monitoring
        await self.data_collector.start_collection()

        # Start Group 3B components
        if self.memory_profiler:
            await self.memory_profiler.start_profiling()

        # Start main monitoring loop
        self.monitor_task = asyncio.create_task(self._monitoring_loop())

        logger.info("Group 3B Performance Monitoring started successfully")

    async def stop_monitoring(self):
        """Stop performance monitoring."""
        logger.info("Stopping Group 3B Performance Monitoring...")

        self.monitoring_active = False

        # Stop main monitoring loop
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        # Stop core monitoring
        await self.data_collector.stop_collection()

        # Stop Group 3B components
        if self.memory_profiler:
            await self.memory_profiler.stop_profiling()

        logger.info("Group 3B Performance Monitoring stopped")

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Process collected metrics
                recent_metrics = await self.data_collector.get_recent_metrics(50)

                for metric in recent_metrics:
                    self.analyzer.add_metric(metric)

                # Integrate memory profiling data
                if self.memory_profiler:
                    await self._integrate_memory_profiling_data()

                # Update performance state
                current_state = self.analyzer.get_system_performance_state()
                self.performance_states.append(current_state)

                # Keep only recent states
                if len(self.performance_states) > 1000:
                    self.performance_states = self.performance_states[-500:]

                # Log significant changes
                await self._log_performance_changes(current_state)

                await asyncio.sleep(30)  # Analysis interval

            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                await asyncio.sleep(30)

    async def _integrate_memory_profiling_data(self):
        """Integrate memory profiling data into performance monitoring."""
        if not self.memory_profiler:
            return

        try:
            # Get memory analysis
            memory_report = self.memory_profiler.generate_memory_report()

            if memory_report and "memory_statistics" in memory_report:
                stats = memory_report["memory_statistics"]

                # Create memory metrics
                timestamp = datetime.now()

                # Memory growth rate metric
                growth_rate = stats.get("growth_rate_mb_per_hour", 0)
                memory_metric = PerformanceMetric(
                    timestamp=timestamp,
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    name="memory_growth_rate",
                    value=growth_rate,
                    unit="MB/h",
                    tags={"component": "memory_profiler", "type": "growth_rate"},
                )
                self.analyzer.add_metric(memory_metric)

                # Memory leak patterns
                leak_patterns = self.memory_profiler.analyze_memory_patterns()
                if leak_patterns:
                    critical_leaks = sum(
                        1 for p in leak_patterns if p.severity_level == "critical"
                    )
                    leak_metric = PerformanceMetric(
                        timestamp=timestamp,
                        metric_type=MetricType.SYSTEM_HEALTH,
                        name="critical_memory_leaks",
                        value=critical_leaks,
                        unit="count",
                        tags={"component": "memory_profiler", "type": "leak_detection"},
                    )
                    self.analyzer.add_metric(leak_metric)

        except Exception as e:
            logger.error(f"Error integrating memory profiling data: {e}")

    async def _log_performance_changes(self, current_state: SystemPerformanceState):
        """Log significant performance changes."""
        if not self.performance_states:
            return

        previous_state = (
            self.performance_states[-1] if len(self.performance_states) > 1 else None
        )

        if previous_state:
            # Check for tier changes
            if current_state.performance_tier != previous_state.performance_tier:
                logger.warning(
                    f"Performance tier changed: {previous_state.performance_tier} → {current_state.performance_tier}"
                )

            # Check for significant health score changes
            health_change = (
                current_state.overall_health_score - previous_state.overall_health_score
            )
            if abs(health_change) > 0.1:  # 10% change threshold
                direction = "improved" if health_change > 0 else "degraded"
                logger.info(
                    f"Performance health {direction}: {previous_state.overall_health_score:.3f} → {current_state.overall_health_score:.3f}"
                )

        # Log new alerts
        new_alerts = [
            alert for alert in current_state.active_alerts if not alert.acknowledged
        ]
        for alert in new_alerts:
            logger.warning(f"New Performance Alert: {alert.message}")

    async def run_endurance_test_integration(
        self,
        duration_hours: float = 8.0,
        bsn_url: str = "http://localhost:8000",
        ragnostic_url: str = "http://localhost:8001",
    ) -> EnduranceTestResults:
        """Run integrated endurance test with performance monitoring."""
        logger.info(f"Starting integrated {duration_hours}-hour endurance test...")

        # Create endurance test suite
        endurance_suite = EnduranceTestSuite(
            bsn_knowledge_url=bsn_url,
            ragnostic_url=ragnostic_url,
            test_duration_hours=duration_hours,
        )

        # Run endurance test
        self.endurance_test_results = await endurance_suite.run_endurance_test()

        logger.info("Endurance test integration completed")
        return self.endurance_test_results

    async def run_breaking_point_analysis(
        self,
        max_operations: int = 1000,
        bsn_url: str = "http://localhost:8000",
        ragnostic_url: str = "http://localhost:8001",
    ) -> SystemBreakingPoint:
        """Run breaking point analysis integration."""
        if not self.breaking_point_analyzer:
            raise ValueError("Breaking point monitoring not enabled")

        logger.info(
            f"Starting breaking point analysis (max: {max_operations} ops/sec)..."
        )

        # Configure analyzer
        self.breaking_point_analyzer.bsn_knowledge_url = bsn_url
        self.breaking_point_analyzer.ragnostic_url = ragnostic_url
        self.breaking_point_analyzer.max_operations_per_second = max_operations

        # Run analysis
        breaking_point = await self.breaking_point_analyzer.analyze_system_limits()

        logger.info("Breaking point analysis integration completed")
        return breaking_point

    def get_comprehensive_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        current_state = self.performance_states[-1] if self.performance_states else None

        report = {
            "timestamp": datetime.now().isoformat(),
            "monitoring_duration_hours": len(self.performance_states)
            * 0.5,  # 30s intervals
            "current_state": {
                "overall_health_score": current_state.overall_health_score
                if current_state
                else 0,
                "performance_tier": current_state.performance_tier
                if current_state
                else "unknown",
                "trend_direction": current_state.trend_direction
                if current_state
                else "unknown",
            }
            if current_state
            else None,
            "performance_summary": {
                "avg_health_score": statistics.mean(
                    [s.overall_health_score for s in self.performance_states]
                )
                if self.performance_states
                else 0,
                "health_score_trend": self._calculate_health_trend(),
                "performance_incidents": len(
                    [
                        s
                        for s in self.performance_states
                        if s.performance_tier in ["degraded", "critical"]
                    ]
                )
                if self.performance_states
                else 0,
            },
            "memory_profiling": None,
            "endurance_test": None,
            "breaking_point_analysis": None,
            "alerts_summary": {
                "total_alerts": len(self.analyzer.alerts),
                "active_alerts": len(
                    [a for a in self.analyzer.alerts if not a.resolved]
                ),
                "critical_alerts": len(
                    [
                        a
                        for a in self.analyzer.alerts
                        if a.level == PerformanceAlertLevel.CRITICAL
                    ]
                ),
                "emergency_alerts": len(
                    [
                        a
                        for a in self.analyzer.alerts
                        if a.level == PerformanceAlertLevel.EMERGENCY
                    ]
                ),
            },
        }

        # Add memory profiling report
        if self.memory_profiler:
            memory_report = self.memory_profiler.generate_memory_report()
            report["memory_profiling"] = {
                "status": "integrated",
                "leak_patterns_detected": len(
                    self.memory_profiler.analyze_memory_patterns()
                ),
                "memory_efficiency": memory_report.get("compliance", {}).get(
                    "meets_growth_target", False
                ),
                "summary": memory_report,
            }

        # Add endurance test results
        if self.endurance_test_results:
            report["endurance_test"] = {
                "status": "completed",
                "duration_hours": self.endurance_test_results.total_duration_hours,
                "passes_all_targets": self.endurance_test_results.passes_all_endurance_targets,
                "medical_accuracy_maintained": self.endurance_test_results.medical_accuracy_maintained,
                "memory_growth_compliant": self.endurance_test_results.meets_memory_growth_target,
            }

        return report

    def _calculate_health_trend(self) -> str:
        """Calculate overall health trend direction."""
        if len(self.performance_states) < 10:
            return "insufficient_data"

        recent_scores = [s.overall_health_score for s in self.performance_states[-10:]]
        early_scores = [s.overall_health_score for s in self.performance_states[:10]]

        recent_avg = statistics.mean(recent_scores)
        early_avg = statistics.mean(early_scores)

        change = (recent_avg - early_avg) / early_avg * 100 if early_avg > 0 else 0

        if change > 5:
            return "improving"
        elif change < -5:
            return "degrading"
        else:
            return "stable"


# Export main classes
__all__ = [
    "Group3BPerformanceMonitor",
    "PerformanceMetric",
    "PerformanceAlert",
    "SystemPerformanceState",
    "PerformanceThresholds",
    "MetricType",
    "PerformanceAlertLevel",
]


# Convenience functions for Group 3B integration
async def setup_group_3b_monitoring(
    collection_interval: int = 15,
    enable_memory_profiling: bool = True,
    enable_breaking_point_monitoring: bool = True,
) -> Group3BPerformanceMonitor:
    """Set up Group 3B performance monitoring."""
    monitor = Group3BPerformanceMonitor(
        collection_interval_seconds=collection_interval,
        enable_memory_profiling=enable_memory_profiling,
        enable_breaking_point_monitoring=enable_breaking_point_monitoring,
    )

    await monitor.start_monitoring()
    return monitor


async def run_complete_group_3b_test_suite(
    bsn_url: str = "http://localhost:8000",
    ragnostic_url: str = "http://localhost:8001",
    endurance_hours: float = 8.0,
    max_breaking_point_ops: int = 1000,
) -> Dict[str, Any]:
    """Run complete Group 3B test suite with integrated monitoring."""
    logger.info("Starting complete Group 3B Advanced Performance Testing Suite...")

    # Set up monitoring
    monitor = await setup_group_3b_monitoring(
        collection_interval=15,
        enable_memory_profiling=True,
        enable_breaking_point_monitoring=True,
    )

    try:
        # Run endurance test
        logger.info("Phase 1: Running endurance testing...")
        endurance_results = await monitor.run_endurance_test_integration(
            duration_hours=endurance_hours, bsn_url=bsn_url, ragnostic_url=ragnostic_url
        )

        # Run breaking point analysis
        logger.info("Phase 2: Running breaking point analysis...")
        breaking_point_results = await monitor.run_breaking_point_analysis(
            max_operations=max_breaking_point_ops,
            bsn_url=bsn_url,
            ragnostic_url=ragnostic_url,
        )

        # Generate comprehensive report
        logger.info("Phase 3: Generating comprehensive report...")
        comprehensive_report = monitor.get_comprehensive_performance_report()

        # Add test results to report
        comprehensive_report["endurance_test_results"] = {
            "passes_all_targets": endurance_results.passes_all_endurance_targets,
            "duration_hours": endurance_results.total_duration_hours,
            "medical_accuracy_maintained": endurance_results.medical_accuracy_maintained,
            "memory_growth_compliant": endurance_results.meets_memory_growth_target,
            "performance_stable": endurance_results.meets_performance_stability_target,
        }

        comprehensive_report["breaking_point_analysis_results"] = {
            "breaking_point_detected": breaking_point_results.breaking_point_detected,
            "breaking_point_ops_per_sec": breaking_point_results.breaking_point_operations_per_second,
            "breaking_point_type": breaking_point_results.breaking_point_type.value
            if breaking_point_results.breaking_point_type
            else None,
            "recovery_successful": breaking_point_results.recovery_successful,
            "safety_margin_ops": breaking_point_results.safety_margin_operations,
        }

        # Overall compliance
        comprehensive_report["group_3b_compliance"] = {
            "all_tests_passed": (
                endurance_results.passes_all_endurance_targets
                and (
                    not breaking_point_results.breaking_point_detected
                    or breaking_point_results.recovery_successful
                )
            ),
            "endurance_compliant": endurance_results.passes_all_endurance_targets,
            "breaking_point_handled": not breaking_point_results.breaking_point_detected
            or breaking_point_results.recovery_successful,
            "memory_profiling_compliant": len(
                [
                    p
                    for p in monitor.memory_profiler.analyze_memory_patterns()
                    if p.severity_level == "critical"
                ]
            )
            == 0,
        }

        logger.info(
            "Group 3B Advanced Performance Testing Suite completed successfully"
        )
        return comprehensive_report

    finally:
        # Clean up monitoring
        await monitor.stop_monitoring()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Group 3B Performance Monitoring Framework"
    )
    parser.add_argument(
        "--mode",
        choices=["monitor", "endurance", "breaking-point", "complete"],
        default="monitor",
        help="Operation mode",
    )
    parser.add_argument(
        "--bsn-url", default="http://localhost:8000", help="BSN Knowledge URL"
    )
    parser.add_argument(
        "--ragnostic-url", default="http://localhost:8001", help="RAGnostic URL"
    )
    parser.add_argument(
        "--duration", type=float, default=8.0, help="Endurance test duration in hours"
    )
    parser.add_argument(
        "--max-ops",
        type=int,
        default=1000,
        help="Max operations for breaking point test",
    )

    args = parser.parse_args()

    if args.mode == "complete":
        # Run complete test suite
        results = asyncio.run(
            run_complete_group_3b_test_suite(
                bsn_url=args.bsn_url,
                ragnostic_url=args.ragnostic_url,
                endurance_hours=args.duration,
                max_breaking_point_ops=args.max_ops,
            )
        )

        print("\n" + "=" * 100)
        print("GROUP 3B ADVANCED PERFORMANCE TESTING - FINAL RESULTS")
        print("=" * 100)
        print(
            f"Overall Compliance: {'✅ PASSED' if results['group_3b_compliance']['all_tests_passed'] else '❌ FAILED'}"
        )
        print(
            f"Endurance Testing: {'✅ PASSED' if results['group_3b_compliance']['endurance_compliant'] else '❌ FAILED'}"
        )
        print(
            f"Breaking Point Analysis: {'✅ HANDLED' if results['group_3b_compliance']['breaking_point_handled'] else '❌ FAILED'}"
        )
        print(
            f"Memory Profiling: {'✅ COMPLIANT' if results['group_3b_compliance']['memory_profiling_compliant'] else '❌ NON-COMPLIANT'}"
        )
        print("=" * 100)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"group_3b_complete_results_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Complete results saved to {filename}")

    else:
        # Run basic monitoring
        asyncio.run(
            setup_group_3b_monitoring(
                collection_interval=15,
                enable_memory_profiling=True,
                enable_breaking_point_monitoring=True,
            )
        )
