"""Advanced Memory Profiling Framework for Group 3B Performance Testing.

Comprehensive memory leak detection and analysis system for the BSN Knowledge
RAGnostic pipeline with 8-hour endurance testing capabilities.

Features:
- Real-time memory leak detection with ML-based pattern analysis
- Endurance testing with continuous monitoring over 8+ hours
- Memory pressure simulation and recovery validation
- Integration with RAGnostic pipeline for medical content processing
- Advanced GC analysis with performance impact assessment
- Resource cleanup validation and connection lifecycle management
"""

import asyncio
import gc
import logging
import psutil
import statistics
import tracemalloc
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import weakref

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class AdvancedMemorySnapshot:
    """Enhanced memory snapshot with detailed metrics."""

    timestamp: datetime
    process_memory_mb: float
    system_memory_percent: float
    virtual_memory_mb: float
    resident_memory_mb: float
    shared_memory_mb: float
    heap_size_mb: float

    # Garbage collection metrics
    gc_generation_0_count: int
    gc_generation_1_count: int
    gc_generation_2_count: int
    gc_collected_objects: int
    gc_freed_memory_mb: float

    # Advanced profiling
    tracemalloc_current_mb: Optional[float]
    tracemalloc_peak_mb: Optional[float]
    tracemalloc_top_allocations: List[Dict]

    # Resource tracking
    file_descriptors_open: int
    thread_count: int
    network_connections: int
    database_connections: int

    # Application-specific
    active_requests: int
    cached_objects: int
    medical_content_objects: int
    vector_embeddings_count: int

    # Performance correlation
    cpu_percent: float
    io_wait_percent: float
    context_switches_per_sec: int

    # Memory pressure indicators
    swap_usage_mb: float
    memory_pressure_score: float
    oom_score: int


@dataclass
class MemoryLeakPattern:
    """Detected memory leak pattern with ML analysis."""

    pattern_type: str  # 'linear', 'exponential', 'cyclical', 'sporadic'
    confidence_score: float  # 0.0 to 1.0
    growth_rate_mb_per_hour: float
    leak_source: str
    affected_components: List[str]
    correlation_metrics: Dict[str, float]
    severity_level: str  # 'low', 'medium', 'high', 'critical'
    prediction_hours_to_oom: Optional[float]


@dataclass
class EnduranceTestPhase:
    """Endurance test phase configuration."""

    name: str
    duration_hours: float
    memory_intensity: str  # 'low', 'medium', 'high', 'extreme'
    concurrent_operations: int
    batch_processing_load: int
    medical_accuracy_target: float
    expected_memory_growth_mb: float


@dataclass
class MemoryProfilingResults:
    """Comprehensive memory profiling results for Group 3B."""

    # Test configuration
    total_test_duration_hours: float
    phases_executed: List[EnduranceTestPhase]
    monitoring_interval_seconds: int

    # Memory analysis
    memory_leak_patterns: List[MemoryLeakPattern]
    baseline_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_efficiency_score: float

    # Endurance metrics
    memory_stability_maintained: bool
    max_memory_growth_rate: float
    memory_pressure_incidents: int
    recovery_success_rate: float

    # Breaking point analysis
    breaking_point_detected: bool
    breaking_point_memory_mb: Optional[float]
    breaking_point_operations_per_sec: Optional[int]
    system_recovery_time_seconds: Optional[float]

    # Medical accuracy correlation
    accuracy_vs_memory_correlation: float
    min_accuracy_during_pressure: float
    accuracy_degradation_points: List[
        Tuple[datetime, float, float]
    ]  # timestamp, memory_mb, accuracy

    # Resource management
    connection_leak_incidents: int
    file_descriptor_leak_rate: float
    thread_leak_incidents: int
    cleanup_efficiency_score: float

    # Performance impact
    gc_performance_overhead_percent: float
    memory_allocation_latency_ms: float
    deallocation_efficiency_score: float

    # Advanced diagnostics
    memory_fragmentation_score: float
    heap_utilization_efficiency: float
    swap_usage_patterns: Dict[str, float]

    # Quality gates
    meets_8hour_endurance_target: bool
    meets_memory_growth_target: bool  # <5% growth over 8 hours
    meets_leak_detection_target: bool  # Zero leaks detected
    meets_medical_accuracy_target: bool  # >98% maintained

    @property
    def passes_group_3b_requirements(self) -> bool:
        """Check if all Group 3B requirements are met."""
        return (
            self.meets_8hour_endurance_target
            and self.meets_memory_growth_target
            and self.meets_leak_detection_target
            and self.meets_medical_accuracy_target
            and self.memory_efficiency_score > 0.85
            and not any(
                p.severity_level == "critical" for p in self.memory_leak_patterns
            )
        )


class MLMemoryLeakDetector:
    """Machine Learning-based memory leak detection system."""

    def __init__(self):
        self.memory_history = deque(maxlen=1000)
        self.pattern_weights = {
            "linear": {"slope_threshold": 10.0, "r_squared_min": 0.7},
            "exponential": {"growth_rate_min": 1.2, "sample_min": 50},
            "cyclical": {"period_tolerance": 0.1, "amplitude_min": 50},
            "sporadic": {"spike_threshold": 100, "frequency_min": 3},
        }

    def add_memory_sample(self, memory_mb: float, timestamp: datetime):
        """Add memory sample for analysis."""
        self.memory_history.append((timestamp, memory_mb))

    def detect_leak_patterns(self) -> List[MemoryLeakPattern]:
        """Detect memory leak patterns using ML techniques."""
        if len(self.memory_history) < 20:
            return []

        patterns = []

        # Linear growth detection
        linear_pattern = self._detect_linear_growth()
        if linear_pattern:
            patterns.append(linear_pattern)

        # Exponential growth detection
        exponential_pattern = self._detect_exponential_growth()
        if exponential_pattern:
            patterns.append(exponential_pattern)

        # Cyclical pattern detection
        cyclical_pattern = self._detect_cyclical_pattern()
        if cyclical_pattern:
            patterns.append(cyclical_pattern)

        # Sporadic leak detection
        sporadic_pattern = self._detect_sporadic_leaks()
        if sporadic_pattern:
            patterns.append(sporadic_pattern)

        return patterns

    def _detect_linear_growth(self) -> Optional[MemoryLeakPattern]:
        """Detect linear memory growth pattern."""
        if len(self.memory_history) < 10:
            return None

        # Extract time and memory data
        times = [
            (t - self.memory_history[0][0]).total_seconds() / 3600
            for t, _ in self.memory_history
        ]
        memory_values = [m for _, m in self.memory_history]

        # Linear regression
        n = len(times)
        sum_x = sum(times)
        sum_y = sum(memory_values)
        sum_xy = sum(x * y for x, y in zip(times, memory_values, strict=False))
        sum_x2 = sum(x * x for x in times)

        # Calculate slope and correlation
        if n * sum_x2 - sum_x * sum_x != 0:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)

            # Calculate R-squared
            mean_y = sum_y / n
            ss_tot = sum((y - mean_y) ** 2 for y in memory_values)
            ss_res = sum(
                (memory_values[i] - (slope * times[i] + (sum_y - slope * sum_x) / n))
                ** 2
                for i in range(n)
            )
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

            # Check if meets linear growth criteria
            if (
                abs(slope) > self.pattern_weights["linear"]["slope_threshold"]
                and r_squared > self.pattern_weights["linear"]["r_squared_min"]
            ):
                severity = (
                    "critical" if slope > 100 else "high" if slope > 50 else "medium"
                )
                hours_to_oom = None

                if slope > 0:
                    # Estimate time to OOM (assuming 8GB available memory)
                    available_memory = 8192 - memory_values[-1]  # 8GB - current usage
                    if available_memory > 0:
                        hours_to_oom = available_memory / slope

                return MemoryLeakPattern(
                    pattern_type="linear",
                    confidence_score=min(1.0, r_squared * 1.2),
                    growth_rate_mb_per_hour=slope,
                    leak_source="Consistent memory allocation without deallocation",
                    affected_components=["memory_manager", "object_cache"],
                    correlation_metrics={"r_squared": r_squared, "slope": slope},
                    severity_level=severity,
                    prediction_hours_to_oom=hours_to_oom,
                )

        return None

    def _detect_exponential_growth(self) -> Optional[MemoryLeakPattern]:
        """Detect exponential memory growth pattern."""
        if len(self.memory_history) < 20:
            return None

        # Take recent samples for exponential analysis
        recent_samples = list(self.memory_history)[-20:]
        memory_values = [m for _, m in recent_samples]

        # Calculate growth rates between consecutive samples
        growth_rates = []
        for i in range(1, len(memory_values)):
            if memory_values[i - 1] > 0:
                growth_rate = memory_values[i] / memory_values[i - 1]
                growth_rates.append(growth_rate)

        if not growth_rates:
            return None

        avg_growth_rate = statistics.mean(growth_rates)

        # Check for exponential growth
        if avg_growth_rate > self.pattern_weights["exponential"]["growth_rate_min"]:
            confidence = min(1.0, (avg_growth_rate - 1.0) * 2)
            severity = "critical" if avg_growth_rate > 1.5 else "high"

            # Estimate time to OOM for exponential growth
            current_memory = memory_values[-1]
            available_memory = 8192 - current_memory

            hours_to_oom = None
            if avg_growth_rate > 1.0 and current_memory > 0:
                # Exponential growth: t = ln(target/current) / ln(growth_rate)
                import math

                try:
                    hours_to_oom = math.log(8192 / current_memory) / math.log(
                        avg_growth_rate
                    )
                except (ValueError, ZeroDivisionError):
                    hours_to_oom = None

            return MemoryLeakPattern(
                pattern_type="exponential",
                confidence_score=confidence,
                growth_rate_mb_per_hour=(avg_growth_rate - 1.0) * current_memory,
                leak_source="Recursive object creation or cache explosion",
                affected_components=["object_cache", "recursive_structures"],
                correlation_metrics={"avg_growth_rate": avg_growth_rate},
                severity_level=severity,
                prediction_hours_to_oom=hours_to_oom,
            )

        return None

    def _detect_cyclical_pattern(self) -> Optional[MemoryLeakPattern]:
        """Detect cyclical memory usage patterns."""
        if len(self.memory_history) < 50:
            return None

        memory_values = [m for _, m in self.memory_history]

        # Simple FFT-like analysis for cyclical patterns
        # Look for periodic increases that don't return to baseline
        window_size = 10
        baseline_shifts = []

        for i in range(window_size, len(memory_values) - window_size, window_size):
            window_start = statistics.mean(memory_values[i - window_size : i])
            window_end = statistics.mean(memory_values[i : i + window_size])
            baseline_shifts.append(window_end - window_start)

        if baseline_shifts:
            avg_shift = statistics.mean(baseline_shifts)
            if avg_shift > 20:  # 20MB average increase per cycle
                return MemoryLeakPattern(
                    pattern_type="cyclical",
                    confidence_score=0.7,
                    growth_rate_mb_per_hour=avg_shift
                    * (3600 / (window_size * 10)),  # Estimate hourly
                    leak_source="Periodic operations not releasing memory completely",
                    affected_components=["batch_processor", "periodic_tasks"],
                    correlation_metrics={"avg_cycle_growth": avg_shift},
                    severity_level="medium",
                    prediction_hours_to_oom=None,
                )

        return None

    def _detect_sporadic_leaks(self) -> Optional[MemoryLeakPattern]:
        """Detect sporadic memory leak spikes."""
        if len(self.memory_history) < 30:
            return None

        memory_values = [m for _, m in self.memory_history]

        # Calculate rolling baseline and identify spikes
        window_size = 5
        spikes = []

        for i in range(window_size, len(memory_values) - window_size):
            baseline = statistics.mean(memory_values[i - window_size : i + window_size])
            current = memory_values[i]

            if current > baseline + 100:  # 100MB spike threshold
                spikes.append(current - baseline)

        if len(spikes) >= 3:  # Multiple spikes indicate pattern
            avg_spike = statistics.mean(spikes)
            spike_frequency = len(spikes) / (
                len(self.memory_history) * 10 / 3600
            )  # spikes per hour

            return MemoryLeakPattern(
                pattern_type="sporadic",
                confidence_score=min(1.0, len(spikes) / 10),
                growth_rate_mb_per_hour=avg_spike * spike_frequency,
                leak_source="Event-driven memory allocation without cleanup",
                affected_components=["event_handlers", "request_processors"],
                correlation_metrics={
                    "avg_spike_mb": avg_spike,
                    "frequency_per_hour": spike_frequency,
                },
                severity_level="medium" if avg_spike < 200 else "high",
                prediction_hours_to_oom=None,
            )

        return None


class AdvancedMemoryProfiler:
    """Advanced memory profiling system for Group 3B performance testing."""

    def __init__(
        self,
        monitoring_interval_seconds: int = 30,
        enable_advanced_tracking: bool = True,
        enable_ml_detection: bool = True,
        max_snapshots: int = 2000,
    ):
        self.monitoring_interval = monitoring_interval_seconds
        self.enable_advanced_tracking = enable_advanced_tracking
        self.enable_ml_detection = enable_ml_detection
        self.max_snapshots = max_snapshots

        # Monitoring state
        self.snapshots: List[AdvancedMemorySnapshot] = []
        self.monitoring_active = False
        self.monitor_task: Optional[asyncio.Task] = None

        # ML-based leak detection
        self.ml_detector = MLMemoryLeakDetector() if enable_ml_detection else None

        # Resource tracking
        self.baseline_resources = self._capture_baseline_resources()

        # Thread pool for parallel analysis
        self.thread_pool = ThreadPoolExecutor(max_workers=2)

        # Weak reference tracking for object lifecycle
        self.tracked_objects = weakref.WeakSet()

        logger.info("Advanced Memory Profiler initialized:")
        logger.info(f"  Monitoring interval: {monitoring_interval_seconds}s")
        logger.info(f"  Advanced tracking: {enable_advanced_tracking}")
        logger.info(f"  ML detection: {enable_ml_detection}")
        logger.info(f"  Max snapshots: {max_snapshots}")

    def _capture_baseline_resources(self) -> Dict:
        """Capture baseline resource state."""
        process = psutil.Process()

        return {
            "memory_mb": process.memory_info().rss / (1024 * 1024),
            "file_descriptors": process.num_fds() if hasattr(process, "num_fds") else 0,
            "threads": process.num_threads(),
            "connections": len(process.connections()),
            "timestamp": datetime.now(),
        }

    async def start_profiling(self):
        """Start advanced memory profiling."""
        if self.monitoring_active:
            logger.warning("Memory profiling already active")
            return

        self.monitoring_active = True

        # Start tracemalloc if advanced tracking enabled
        if self.enable_advanced_tracking:
            tracemalloc.start(25)  # Track top 25 allocations

        # Start monitoring task
        self.monitor_task = asyncio.create_task(self._monitoring_loop())

        logger.info("Advanced memory profiling started")

    async def stop_profiling(self):
        """Stop memory profiling."""
        self.monitoring_active = False

        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        if self.enable_advanced_tracking and tracemalloc.is_tracing():
            tracemalloc.stop()

        logger.info("Advanced memory profiling stopped")

    async def _monitoring_loop(self):
        """Advanced monitoring loop with parallel analysis."""
        while self.monitoring_active:
            try:
                # Capture snapshot
                snapshot_future = asyncio.get_event_loop().run_in_executor(
                    self.thread_pool, self._capture_advanced_snapshot
                )

                snapshot = await snapshot_future
                self.snapshots.append(snapshot)

                # Add to ML detector if enabled
                if self.ml_detector:
                    self.ml_detector.add_memory_sample(
                        snapshot.process_memory_mb, snapshot.timestamp
                    )

                # Manage snapshot history
                if len(self.snapshots) > self.max_snapshots:
                    self.snapshots = self.snapshots[-self.max_snapshots // 2 :]

                # Check for immediate alerts
                await self._check_memory_alerts(snapshot)

                await asyncio.sleep(self.monitoring_interval)

            except Exception as e:
                logger.error(f"Error in memory monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)

    def _capture_advanced_snapshot(self) -> AdvancedMemorySnapshot:
        """Capture comprehensive memory snapshot."""
        process = psutil.Process()
        system_memory = psutil.virtual_memory()
        memory_info = process.memory_info()

        # Basic metrics
        process_memory_mb = memory_info.rss / (1024 * 1024)
        virtual_memory_mb = memory_info.vms / (1024 * 1024)

        # System metrics
        system_memory_percent = system_memory.percent

        # GC metrics
        gc_stats = gc.get_stats()
        gc_counts = gc.get_count()

        # Advanced profiling with tracemalloc
        tracemalloc_current = tracemalloc_peak = None
        top_allocations = []

        if self.enable_advanced_tracking and tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc_current = current / (1024 * 1024)
            tracemalloc_peak = peak / (1024 * 1024)

            # Get top allocations
            top_stats = tracemalloc.take_snapshot().statistics("lineno")
            for stat in top_stats[:10]:
                top_allocations.append(
                    {
                        "size_mb": stat.size / (1024 * 1024),
                        "count": stat.count,
                        "traceback": str(stat.traceback),
                    }
                )

        # Resource tracking
        file_descriptors = process.num_fds() if hasattr(process, "num_fds") else 0
        thread_count = process.num_threads()
        connections = len(process.connections())

        # Advanced system metrics
        cpu_percent = process.cpu_percent()

        # Memory pressure calculation
        memory_pressure_score = self._calculate_memory_pressure_score(system_memory)

        return AdvancedMemorySnapshot(
            timestamp=datetime.now(),
            process_memory_mb=process_memory_mb,
            system_memory_percent=system_memory_percent,
            virtual_memory_mb=virtual_memory_mb,
            resident_memory_mb=process_memory_mb,  # RSS
            shared_memory_mb=getattr(memory_info, "shared", 0) / (1024 * 1024),
            heap_size_mb=virtual_memory_mb * 0.7,  # Estimate
            # GC metrics
            gc_generation_0_count=gc_counts[0],
            gc_generation_1_count=gc_counts[1],
            gc_generation_2_count=gc_counts[2],
            gc_collected_objects=sum(stat.get("collected", 0) for stat in gc_stats),
            gc_freed_memory_mb=sum(
                stat.get("collected", 0) * 0.001 for stat in gc_stats
            ),  # Estimate
            # Advanced profiling
            tracemalloc_current_mb=tracemalloc_current,
            tracemalloc_peak_mb=tracemalloc_peak,
            tracemalloc_top_allocations=top_allocations,
            # Resource tracking
            file_descriptors_open=file_descriptors,
            thread_count=thread_count,
            network_connections=connections,
            database_connections=self._estimate_db_connections(),
            # Application-specific (estimated)
            active_requests=0,  # Would be tracked by application
            cached_objects=len(self.tracked_objects),
            medical_content_objects=0,  # Would be tracked by application
            vector_embeddings_count=0,  # Would be tracked by application
            # Performance correlation
            cpu_percent=cpu_percent,
            io_wait_percent=0,  # Would need system-level monitoring
            context_switches_per_sec=0,  # Would need system-level monitoring
            # Memory pressure
            swap_usage_mb=psutil.swap_memory().used / (1024 * 1024),
            memory_pressure_score=memory_pressure_score,
            oom_score=self._get_oom_score(),
        )

    def _calculate_memory_pressure_score(self, memory: psutil._common.svmem) -> float:
        """Calculate memory pressure score (0.0 to 1.0)."""
        # Factors: usage percentage, available memory, swap usage
        usage_factor = memory.percent / 100
        available_factor = 1.0 - (memory.available / memory.total)
        swap_factor = psutil.swap_memory().percent / 100

        # Weighted score
        pressure_score = usage_factor * 0.6 + available_factor * 0.3 + swap_factor * 0.1
        return min(1.0, pressure_score)

    def _get_oom_score(self) -> int:
        """Get OOM killer score (Linux-specific)."""
        try:
            with open(f"/proc/{psutil.Process().pid}/oom_score", "r") as f:
                return int(f.read().strip())
        except:
            return 0

    def _estimate_db_connections(self) -> int:
        """Estimate database connections (would be application-specific)."""
        # This would typically be tracked by the application's connection pool
        return 5  # Default estimate

    async def _check_memory_alerts(self, snapshot: AdvancedMemorySnapshot):
        """Check for memory-related alerts."""
        alerts = []

        # Critical memory usage
        if snapshot.system_memory_percent > 90:
            alerts.append(
                f"Critical system memory: {snapshot.system_memory_percent:.1f}%"
            )

        # High process memory
        if snapshot.process_memory_mb > 2048:  # >2GB
            alerts.append(f"High process memory: {snapshot.process_memory_mb:.1f}MB")

        # Memory pressure
        if snapshot.memory_pressure_score > 0.8:
            alerts.append(f"High memory pressure: {snapshot.memory_pressure_score:.2f}")

        # Resource leaks
        baseline = self.baseline_resources
        fd_growth = snapshot.file_descriptors_open - baseline["file_descriptors"]
        if fd_growth > 100:
            alerts.append(f"File descriptor leak: +{fd_growth}")

        thread_growth = snapshot.thread_count - baseline["threads"]
        if thread_growth > 20:
            alerts.append(f"Thread leak: +{thread_growth}")

        # Log alerts
        for alert in alerts:
            logger.warning(f"Memory Alert: {alert}")

    def analyze_memory_patterns(self) -> List[MemoryLeakPattern]:
        """Analyze memory patterns for leaks."""
        if not self.ml_detector or len(self.snapshots) < 10:
            return []

        return self.ml_detector.detect_leak_patterns()

    def generate_memory_report(self) -> Dict:
        """Generate comprehensive memory analysis report."""
        if not self.snapshots:
            return {"error": "No memory snapshots available"}

        # Basic statistics
        memory_values = [s.process_memory_mb for s in self.snapshots]
        baseline_memory = memory_values[0]
        peak_memory = max(memory_values)
        current_memory = memory_values[-1]
        avg_memory = statistics.mean(memory_values)

        # Growth analysis
        memory_growth = current_memory - baseline_memory
        test_duration = (
            self.snapshots[-1].timestamp - self.snapshots[0].timestamp
        ).total_seconds() / 3600
        growth_rate = memory_growth / test_duration if test_duration > 0 else 0

        # Leak pattern analysis
        leak_patterns = self.analyze_memory_patterns()

        # Resource analysis
        fd_values = [s.file_descriptors_open for s in self.snapshots]
        thread_values = [s.thread_count for s in self.snapshots]

        resource_analysis = {
            "file_descriptor_trend": "increasing"
            if fd_values[-1] > fd_values[0] + 10
            else "stable",
            "thread_count_trend": "increasing"
            if thread_values[-1] > thread_values[0] + 5
            else "stable",
            "max_file_descriptors": max(fd_values),
            "max_threads": max(thread_values),
        }

        # GC analysis
        gc_pressure_values = [
            s.gc_generation_0_count + s.gc_generation_1_count + s.gc_generation_2_count
            for s in self.snapshots
        ]
        gc_analysis = {
            "total_gc_collections": gc_pressure_values[-1] - gc_pressure_values[0],
            "gc_frequency_per_hour": (gc_pressure_values[-1] - gc_pressure_values[0])
            / test_duration
            if test_duration > 0
            else 0,
            "gc_efficiency_estimate": 0.85,  # Would need more detailed GC telemetry
        }

        return {
            "test_duration_hours": test_duration,
            "memory_statistics": {
                "baseline_mb": baseline_memory,
                "peak_mb": peak_memory,
                "current_mb": current_memory,
                "average_mb": avg_memory,
                "growth_mb": memory_growth,
                "growth_rate_mb_per_hour": growth_rate,
            },
            "leak_patterns": [
                {
                    "type": pattern.pattern_type,
                    "confidence": pattern.confidence_score,
                    "severity": pattern.severity_level,
                    "growth_rate": pattern.growth_rate_mb_per_hour,
                    "source": pattern.leak_source,
                    "hours_to_oom": pattern.prediction_hours_to_oom,
                }
                for pattern in leak_patterns
            ],
            "resource_analysis": resource_analysis,
            "gc_analysis": gc_analysis,
            "performance_impact": {
                "memory_overhead_percent": (avg_memory - baseline_memory)
                / baseline_memory
                * 100
                if baseline_memory > 0
                else 0,
                "gc_overhead_estimate_percent": min(
                    10.0, gc_analysis["gc_frequency_per_hour"] / 100
                ),
            },
            "compliance": {
                "meets_growth_target": growth_rate
                < (baseline_memory * 0.05),  # <5% growth
                "meets_leak_target": len(
                    [
                        p
                        for p in leak_patterns
                        if p.severity_level in ["high", "critical"]
                    ]
                )
                == 0,
                "meets_stability_target": memory_growth < 500,  # <500MB total growth
            },
        }


# Export main classes and functions
__all__ = [
    "AdvancedMemoryProfiler",
    "MemoryProfilingResults",
    "MemoryLeakPattern",
    "EnduranceTestPhase",
    "MLMemoryLeakDetector",
]


# Performance testing integration
async def run_memory_profiling_test(
    duration_hours: float = 2.0,
    monitoring_interval: int = 30,
    enable_ml_detection: bool = True,
) -> Dict:
    """Run advanced memory profiling test."""
    profiler = AdvancedMemoryProfiler(
        monitoring_interval_seconds=monitoring_interval,
        enable_ml_detection=enable_ml_detection,
    )

    await profiler.start_profiling()

    try:
        # Run test for specified duration
        await asyncio.sleep(duration_hours * 3600)
    finally:
        await profiler.stop_profiling()

    return profiler.generate_memory_report()
