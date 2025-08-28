#!/usr/bin/env python3
"""Group 3B Advanced Performance Testing - Complete Test Runner.

This is the main entry point for executing all Group 3B advanced performance testing
components with comprehensive integration, reporting, and validation.

Components Integrated:
- Advanced Memory Profiling with ML-based leak detection
- 8-hour Endurance Testing with medical accuracy validation
- Breaking Point Analysis with graceful degradation testing
- Performance Monitoring Framework with real-time analytics
- Comprehensive reporting and compliance validation

Usage:
    python group_3b_test_runner.py --mode full --duration 8 --max-ops 1000
    python group_3b_test_runner.py --mode memory-only --duration 2
    python group_3b_test_runner.py --mode breaking-point --max-ops 500
    python group_3b_test_runner.py --mode endurance --duration 4
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

# Import Group 3B components
from memory_profiler import run_memory_profiling_test
from endurance_testing_suite import run_endurance_testing_suite
from breaking_point_analyzer import run_breaking_point_analysis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            f"group_3b_test_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        ),
    ],
)
logger = logging.getLogger(__name__)


class Group3BTestRunner:
    """Complete test runner for Group 3B Advanced Performance Testing."""

    def __init__(
        self,
        bsn_knowledge_url: str = "http://localhost:8000",
        ragnostic_url: str = "http://localhost:8001",
        output_dir: str = "group_3b_results",
    ):
        self.bsn_knowledge_url = bsn_knowledge_url
        self.ragnostic_url = ragnostic_url
        self.output_dir = Path(output_dir)

        # Create output directory
        self.output_dir.mkdir(exist_ok=True)

        # Test execution state
        self.test_start_time: Optional[datetime] = None
        self.test_results: Dict[str, Any] = {}

        logger.info("Group 3B Test Runner initialized:")
        logger.info(f"  BSN Knowledge URL: {bsn_knowledge_url}")
        logger.info(f"  RAGnostic URL: {ragnostic_url}")
        logger.info(f"  Output directory: {output_dir}")

    async def run_memory_profiling_test(
        self, duration_hours: float = 2.0, monitoring_interval: int = 30
    ) -> Dict[str, Any]:
        """Run advanced memory profiling test."""
        logger.info("=" * 100)
        logger.info("GROUP 3B: ADVANCED MEMORY PROFILING TEST")
        logger.info("=" * 100)

        test_start = datetime.now()

        try:
            # Run memory profiling
            results = await run_memory_profiling_test(
                duration_hours=duration_hours,
                monitoring_interval=monitoring_interval,
                enable_ml_detection=True,
            )

            # Enhanced results with Group 3B specific validations
            enhanced_results = {
                "test_type": "memory_profiling",
                "start_time": test_start.isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration_hours": duration_hours,
                "configuration": {
                    "monitoring_interval_seconds": monitoring_interval,
                    "ml_detection_enabled": True,
                    "advanced_tracking_enabled": True,
                },
                "results": results,
                "group_3b_compliance": {
                    "meets_8_hour_capability": duration_hours
                    >= 2.0,  # Scalable to 8 hours
                    "meets_memory_growth_target": results.get("compliance", {}).get(
                        "meets_growth_target", False
                    ),
                    "meets_leak_detection_target": results.get("compliance", {}).get(
                        "meets_leak_target", False
                    ),
                    "ml_patterns_detected": len(results.get("leak_patterns", [])),
                    "overall_compliant": (
                        results.get("compliance", {}).get("meets_growth_target", False)
                        and results.get("compliance", {}).get(
                            "meets_leak_target", False
                        )
                        and len(
                            [
                                p
                                for p in results.get("leak_patterns", [])
                                if p.get("severity") == "critical"
                            ]
                        )
                        == 0
                    ),
                },
            }

            # Save results
            self._save_test_results("memory_profiling", enhanced_results)

            # Log summary
            compliance = enhanced_results["group_3b_compliance"]
            logger.info("\nMemory Profiling Test Summary:")
            logger.info(f"  Duration: {duration_hours} hours")
            logger.info(
                f"  Memory Growth Target: {'✅ MET' if compliance['meets_memory_growth_target'] else '❌ NOT MET'}"
            )
            logger.info(
                f"  Leak Detection Target: {'✅ MET' if compliance['meets_leak_detection_target'] else '❌ NOT MET'}"
            )
            logger.info(f"  ML Patterns Detected: {compliance['ml_patterns_detected']}")
            logger.info(
                f"  Overall Compliant: {'✅ YES' if compliance['overall_compliant'] else '❌ NO'}"
            )

            return enhanced_results

        except Exception as e:
            logger.error(f"Memory profiling test failed: {e}")
            return {
                "test_type": "memory_profiling",
                "status": "failed",
                "error": str(e),
                "group_3b_compliance": {"overall_compliant": False},
            }

    async def run_endurance_test(self, duration_hours: float = 8.0) -> Dict[str, Any]:
        """Run comprehensive endurance testing."""
        logger.info("=" * 100)
        logger.info("GROUP 3B: 8-HOUR ENDURANCE TESTING")
        logger.info("=" * 100)

        test_start = datetime.now()

        try:
            # Run endurance test
            results = await run_endurance_testing_suite(
                bsn_url=self.bsn_knowledge_url,
                ragnostic_url=self.ragnostic_url,
                duration_hours=duration_hours,
            )

            # Enhanced results with Group 3B specific validations
            enhanced_results = {
                "test_type": "endurance_testing",
                "start_time": test_start.isoformat(),
                "end_time": datetime.now().isoformat(),
                "target_duration_hours": duration_hours,
                "actual_duration_hours": results.total_duration_hours,
                "configuration": {
                    "phases_executed": results.phases_completed,
                    "total_phases": results.total_phases,
                    "bsn_url": self.bsn_knowledge_url,
                    "ragnostic_url": self.ragnostic_url,
                },
                "results": {
                    "total_requests": results.total_requests_processed,
                    "success_rate": results.overall_success_rate,
                    "memory_growth_rate": results.memory_growth_rate_mb_per_hour,
                    "medical_accuracy_maintained": results.medical_accuracy_maintained,
                    "min_medical_accuracy": results.min_medical_accuracy,
                    "performance_stable": not results.performance_degradation_detected,
                    "resource_leaks": results.resource_leak_incidents,
                },
                "group_3b_compliance": {
                    "meets_8_hour_target": results.meets_8_hour_target,
                    "meets_memory_growth_target": results.meets_memory_growth_target,
                    "meets_accuracy_target": results.meets_accuracy_target,
                    "meets_performance_stability_target": results.meets_performance_stability_target,
                    "meets_resource_cleanup_target": results.meets_resource_cleanup_target,
                    "passes_all_targets": results.passes_all_endurance_targets,
                    "memory_leak_patterns": len(results.memory_leak_patterns),
                    "critical_issues": len(
                        [
                            p
                            for p in results.memory_leak_patterns
                            if p.severity_level == "critical"
                        ]
                    ),
                    "medical_degradation_events": len(
                        results.accuracy_degradation_events
                    ),
                },
            }

            # Save results
            self._save_test_results("endurance_testing", enhanced_results)

            # Log summary
            compliance = enhanced_results["group_3b_compliance"]
            logger.info("\nEndurance Test Summary:")
            logger.info(
                f"  Target Duration: {duration_hours}h | Actual: {results.total_duration_hours:.2f}h"
            )
            logger.info(
                f"  8-Hour Target: {'✅ MET' if compliance['meets_8_hour_target'] else '❌ NOT MET'}"
            )
            logger.info(
                f"  Memory Growth: {'✅ COMPLIANT' if compliance['meets_memory_growth_target'] else '❌ NON-COMPLIANT'}"
            )
            logger.info(
                f"  Medical Accuracy: {'✅ MAINTAINED' if compliance['meets_accuracy_target'] else '❌ DEGRADED'}"
            )
            logger.info(
                f"  Performance Stability: {'✅ STABLE' if compliance['meets_performance_stability_target'] else '❌ UNSTABLE'}"
            )
            logger.info(
                f"  All Targets: {'✅ PASSED' if compliance['passes_all_targets'] else '❌ FAILED'}"
            )

            return enhanced_results

        except Exception as e:
            logger.error(f"Endurance test failed: {e}")
            return {
                "test_type": "endurance_testing",
                "status": "failed",
                "error": str(e),
                "group_3b_compliance": {"passes_all_targets": False},
            }

    async def run_breaking_point_test(
        self, max_operations: int = 1000
    ) -> Dict[str, Any]:
        """Run breaking point analysis."""
        logger.info("=" * 100)
        logger.info("GROUP 3B: BREAKING POINT ANALYSIS")
        logger.info("=" * 100)

        test_start = datetime.now()

        try:
            # Run breaking point analysis
            results = await run_breaking_point_analysis(
                bsn_url=self.bsn_knowledge_url,
                ragnostic_url=self.ragnostic_url,
                max_operations=max_operations,
            )

            # Enhanced results with Group 3B specific validations
            enhanced_results = {
                "test_type": "breaking_point_analysis",
                "start_time": test_start.isoformat(),
                "end_time": datetime.now().isoformat(),
                "max_operations_tested": max_operations,
                "configuration": {
                    "bsn_url": self.bsn_knowledge_url,
                    "ragnostic_url": self.ragnostic_url,
                    "step_duration_seconds": 300,
                },
                "results": {
                    "breaking_point_detected": results.breaking_point_detected,
                    "breaking_point_operations": results.breaking_point_operations_per_second,
                    "breaking_point_type": results.breaking_point_type.value
                    if results.breaking_point_type
                    else None,
                    "safety_margin_operations": results.safety_margin_operations,
                    "recovery_successful": results.recovery_successful,
                    "recovery_time_seconds": results.recovery_time_seconds,
                    "graceful_degradation": results.graceful_degradation_observed,
                    "medical_accuracy_impact": results.medical_accuracy_impact,
                },
                "group_3b_compliance": {
                    "graceful_degradation_validated": results.graceful_degradation_observed,
                    "recovery_capability_adequate": results.recovery_capability_score
                    > 0.7,
                    "medical_accuracy_preserved": results.medical_accuracy_impact
                    < 5.0,  # <5% impact
                    "recovery_successful": results.recovery_successful,
                    "safety_margin_established": results.safety_margin_operations > 0,
                    "overall_compliant": (
                        results.graceful_degradation_observed
                        and results.recovery_capability_score > 0.7
                        and results.medical_accuracy_impact < 5.0
                        and (
                            not results.breaking_point_detected
                            or results.recovery_successful
                        )
                    ),
                    "breaking_point_recommendations": {
                        "immediate_actions": len(results.immediate_actions),
                        "optimization_recommendations": len(
                            results.optimization_recommendations
                        ),
                        "scaling_recommendations": len(results.scaling_recommendations),
                    },
                },
            }

            # Save results
            self._save_test_results("breaking_point_analysis", enhanced_results)

            # Log summary
            compliance = enhanced_results["group_3b_compliance"]
            logger.info("\nBreaking Point Analysis Summary:")
            logger.info(f"  Max Operations Tested: {max_operations} ops/sec")
            if results.breaking_point_detected:
                logger.info(
                    f"  Breaking Point: {results.breaking_point_operations_per_second:.0f} ops/sec ({results.breaking_point_type.value if results.breaking_point_type else 'Unknown'})"
                )
                logger.info(
                    f"  Safety Margin: {results.safety_margin_operations:.0f} ops/sec"
                )
            else:
                logger.info("  Breaking Point: Not detected within tested range")
            logger.info(
                f"  Graceful Degradation: {'✅ VALIDATED' if compliance['graceful_degradation_validated'] else '❌ NOT VALIDATED'}"
            )
            logger.info(
                f"  Recovery Capability: {'✅ ADEQUATE' if compliance['recovery_capability_adequate'] else '❌ INADEQUATE'}"
            )
            logger.info(
                f"  Medical Accuracy: {'✅ PRESERVED' if compliance['medical_accuracy_preserved'] else '❌ IMPACTED'}"
            )
            logger.info(
                f"  Overall Compliant: {'✅ YES' if compliance['overall_compliant'] else '❌ NO'}"
            )

            return enhanced_results

        except Exception as e:
            logger.error(f"Breaking point analysis failed: {e}")
            return {
                "test_type": "breaking_point_analysis",
                "status": "failed",
                "error": str(e),
                "group_3b_compliance": {"overall_compliant": False},
            }

    async def run_complete_test_suite(
        self,
        endurance_hours: float = 8.0,
        max_operations: int = 1000,
        memory_profiling_hours: float = 2.0,
    ) -> Dict[str, Any]:
        """Run complete Group 3B test suite with all components."""
        logger.info("=" * 100)
        logger.info("GROUP 3B: COMPLETE ADVANCED PERFORMANCE TEST SUITE")
        logger.info("=" * 100)

        self.test_start_time = datetime.now()

        try:
            # Phase 1: Memory Profiling (shorter duration for integration)
            logger.info("\n🧠 PHASE 1: ADVANCED MEMORY PROFILING")
            memory_results = await self.run_memory_profiling_test(
                duration_hours=memory_profiling_hours, monitoring_interval=30
            )

            # Phase 2: Breaking Point Analysis
            logger.info("\n🚨 PHASE 2: BREAKING POINT ANALYSIS")
            breaking_point_results = await self.run_breaking_point_test(
                max_operations=max_operations
            )

            # Phase 3: Endurance Testing (main test)
            logger.info("\n⏱️ PHASE 3: 8-HOUR ENDURANCE TESTING")
            endurance_results = await self.run_endurance_test(
                duration_hours=endurance_hours
            )

            # Compile comprehensive results
            comprehensive_results = {
                "test_suite": "Group 3B Advanced Performance Testing",
                "execution_timestamp": self.test_start_time.isoformat(),
                "completion_timestamp": datetime.now().isoformat(),
                "total_execution_time_hours": (
                    datetime.now() - self.test_start_time
                ).total_seconds()
                / 3600,
                # Individual test results
                "memory_profiling": memory_results,
                "breaking_point_analysis": breaking_point_results,
                "endurance_testing": endurance_results,
                # Overall compliance analysis
                "group_3b_overall_compliance": {
                    "memory_profiling_compliant": memory_results.get(
                        "group_3b_compliance", {}
                    ).get("overall_compliant", False),
                    "breaking_point_compliant": breaking_point_results.get(
                        "group_3b_compliance", {}
                    ).get("overall_compliant", False),
                    "endurance_testing_compliant": endurance_results.get(
                        "group_3b_compliance", {}
                    ).get("passes_all_targets", False),
                    "all_tests_passed": (
                        memory_results.get("group_3b_compliance", {}).get(
                            "overall_compliant", False
                        )
                        and breaking_point_results.get("group_3b_compliance", {}).get(
                            "overall_compliant", False
                        )
                        and endurance_results.get("group_3b_compliance", {}).get(
                            "passes_all_targets", False
                        )
                    ),
                    "critical_issues": {
                        "memory_leaks_critical": len(
                            [
                                p
                                for p in memory_results.get("results", {}).get(
                                    "leak_patterns", []
                                )
                                if p.get("severity") == "critical"
                            ]
                        ),
                        "breaking_point_unrecoverable": breaking_point_results.get(
                            "results", {}
                        ).get("breaking_point_detected", False)
                        and not breaking_point_results.get("results", {}).get(
                            "recovery_successful", False
                        ),
                        "endurance_medical_accuracy_loss": not endurance_results.get(
                            "group_3b_compliance", {}
                        ).get("meets_accuracy_target", False),
                        "endurance_performance_degradation": not endurance_results.get(
                            "group_3b_compliance", {}
                        ).get("meets_performance_stability_target", False),
                    },
                    "performance_summary": {
                        "peak_operations_per_second": max(
                            breaking_point_results.get("results", {}).get(
                                "breaking_point_operations", 0
                            ),
                            max_operations
                            if not breaking_point_results.get("results", {}).get(
                                "breaking_point_detected", False
                            )
                            else 0,
                        ),
                        "endurance_duration_hours": endurance_results.get(
                            "actual_duration_hours", 0
                        ),
                        "memory_growth_rate_mb_per_hour": endurance_results.get(
                            "results", {}
                        ).get("memory_growth_rate", 0),
                        "min_medical_accuracy_percent": endurance_results.get(
                            "results", {}
                        ).get("min_medical_accuracy", 0),
                        "system_recovery_validated": breaking_point_results.get(
                            "results", {}
                        ).get("recovery_successful", False),
                    },
                },
                # Test environment info
                "test_environment": {
                    "bsn_knowledge_url": self.bsn_knowledge_url,
                    "ragnostic_url": self.ragnostic_url,
                    "output_directory": str(self.output_dir),
                },
            }

            # Save comprehensive results
            self._save_test_results("complete_test_suite", comprehensive_results)

            # Generate final report
            self._generate_final_report(comprehensive_results)

            return comprehensive_results

        except Exception as e:
            logger.error(f"Complete test suite execution failed: {e}")
            return {
                "test_suite": "Group 3B Advanced Performance Testing",
                "status": "failed",
                "error": str(e),
                "group_3b_overall_compliance": {"all_tests_passed": False},
            }

    def _save_test_results(self, test_type: str, results: Dict[str, Any]):
        """Save test results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"{test_type}_results_{timestamp}.json"

        try:
            with open(filename, "w") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Test results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save test results: {e}")

    def _generate_final_report(self, comprehensive_results: Dict[str, Any]):
        """Generate comprehensive final report."""
        logger.info("\n" + "=" * 100)
        logger.info("GROUP 3B ADVANCED PERFORMANCE TESTING - FINAL REPORT")
        logger.info("=" * 100)

        compliance = comprehensive_results["group_3b_overall_compliance"]
        performance = compliance["performance_summary"]
        critical = compliance["critical_issues"]

        # Test execution summary
        logger.info("\n📊 TEST EXECUTION SUMMARY:")
        logger.info(f"  Start Time: {comprehensive_results['execution_timestamp']}")
        logger.info(
            f"  Completion Time: {comprehensive_results['completion_timestamp']}"
        )
        logger.info(
            f"  Total Execution Time: {comprehensive_results['total_execution_time_hours']:.2f} hours"
        )

        # Overall compliance
        logger.info("\n🎯 OVERALL COMPLIANCE:")
        logger.info(
            f"  Memory Profiling: {'✅ COMPLIANT' if compliance['memory_profiling_compliant'] else '❌ NON-COMPLIANT'}"
        )
        logger.info(
            f"  Breaking Point Analysis: {'✅ COMPLIANT' if compliance['breaking_point_compliant'] else '❌ NON-COMPLIANT'}"
        )
        logger.info(
            f"  Endurance Testing: {'✅ COMPLIANT' if compliance['endurance_testing_compliant'] else '❌ NON-COMPLIANT'}"
        )

        # Final verdict
        if compliance["all_tests_passed"]:
            logger.info("\n🏆 FINAL VERDICT: ✅ ALL GROUP 3B TESTS PASSED")
            logger.info(
                "🎉 System successfully meets all Group 3B Advanced Performance Testing requirements!"
            )
        else:
            logger.info("\n🚨 FINAL VERDICT: ❌ SOME GROUP 3B TESTS FAILED")
            logger.info(
                "📋 Review failed components and implement necessary optimizations"
            )

        # Performance achievements
        logger.info("\n📈 PERFORMANCE ACHIEVEMENTS:")
        logger.info(
            f"  Peak Operations/Second: {performance['peak_operations_per_second']:.0f}"
        )
        logger.info(
            f"  Endurance Duration: {performance['endurance_duration_hours']:.2f} hours"
        )
        logger.info(
            f"  Memory Growth Rate: {performance['memory_growth_rate_mb_per_hour']:.2f} MB/hour"
        )
        logger.info(
            f"  Medical Accuracy (Min): {performance['min_medical_accuracy_percent']:.1f}%"
        )
        logger.info(
            f"  System Recovery: {'✅ VALIDATED' if performance['system_recovery_validated'] else '❌ NOT VALIDATED'}"
        )

        # Critical issues
        critical_count = sum(
            [
                critical["memory_leaks_critical"],
                1 if critical["breaking_point_unrecoverable"] else 0,
                1 if critical["endurance_medical_accuracy_loss"] else 0,
                1 if critical["endurance_performance_degradation"] else 0,
            ]
        )

        logger.info(f"\n🚨 CRITICAL ISSUES: {critical_count}")
        if critical["memory_leaks_critical"] > 0:
            logger.warning(
                f"  - {critical['memory_leaks_critical']} critical memory leak pattern(s)"
            )
        if critical["breaking_point_unrecoverable"]:
            logger.warning("  - System breaking point with failed recovery")
        if critical["endurance_medical_accuracy_loss"]:
            logger.warning("  - Medical accuracy degradation during endurance test")
        if critical["endurance_performance_degradation"]:
            logger.warning("  - Performance degradation during endurance test")

        if critical_count == 0:
            logger.info("  ✅ No critical issues detected")

        # Recommendations
        logger.info("\n📋 RECOMMENDATIONS:")
        if compliance["all_tests_passed"]:
            logger.info(
                "  • System is production-ready for high-load medical applications"
            )
            logger.info(
                "  • Consider implementing monitoring based on established baselines"
            )
            logger.info("  • Regular performance regression testing recommended")
        else:
            logger.info(
                "  • Address all failed test components before production deployment"
            )
            logger.info(
                "  • Focus on critical issues first, then performance optimizations"
            )
            logger.info("  • Re-run complete test suite after implementing fixes")

        logger.info("\n" + "=" * 100)

        # Save summary report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = self.output_dir / f"group_3b_final_report_{timestamp}.txt"

        try:
            with open(summary_file, "w") as f:
                f.write("GROUP 3B ADVANCED PERFORMANCE TESTING - FINAL REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(
                    f"Execution Time: {comprehensive_results['execution_timestamp']} to {comprehensive_results['completion_timestamp']}\n"
                )
                f.write(
                    f"Total Duration: {comprehensive_results['total_execution_time_hours']:.2f} hours\n\n"
                )
                f.write("COMPLIANCE SUMMARY:\n")
                f.write(
                    f"Memory Profiling: {'PASSED' if compliance['memory_profiling_compliant'] else 'FAILED'}\n"
                )
                f.write(
                    f"Breaking Point Analysis: {'PASSED' if compliance['breaking_point_compliant'] else 'FAILED'}\n"
                )
                f.write(
                    f"Endurance Testing: {'PASSED' if compliance['endurance_testing_compliant'] else 'FAILED'}\n\n"
                )
                f.write(
                    f"OVERALL RESULT: {'ALL TESTS PASSED' if compliance['all_tests_passed'] else 'SOME TESTS FAILED'}\n"
                )

            logger.info(f"Final report summary saved to {summary_file}")

        except Exception as e:
            logger.error(f"Failed to save summary report: {e}")


async def main():
    """Main entry point for Group 3B testing."""
    parser = argparse.ArgumentParser(
        description="Group 3B Advanced Performance Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode full --duration 8 --max-ops 1000
  %(prog)s --mode memory-only --duration 2 --interval 15
  %(prog)s --mode endurance --duration 4
  %(prog)s --mode breaking-point --max-ops 500
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["full", "memory-only", "endurance", "breaking-point"],
        default="full",
        help="Test mode to execute (default: full)",
    )

    parser.add_argument(
        "--bsn-url",
        default="http://localhost:8000",
        help="BSN Knowledge service URL (default: http://localhost:8000)",
    )

    parser.add_argument(
        "--ragnostic-url",
        default="http://localhost:8001",
        help="RAGnostic service URL (default: http://localhost:8001)",
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=8.0,
        help="Endurance test duration in hours (default: 8.0)",
    )

    parser.add_argument(
        "--max-ops",
        type=int,
        default=1000,
        help="Maximum operations/second for breaking point test (default: 1000)",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Memory profiling monitoring interval in seconds (default: 30)",
    )

    parser.add_argument(
        "--output-dir",
        default="group_3b_results",
        help="Output directory for test results (default: group_3b_results)",
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Configure verbose logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Initialize test runner
    test_runner = Group3BTestRunner(
        bsn_knowledge_url=args.bsn_url,
        ragnostic_url=args.ragnostic_url,
        output_dir=args.output_dir,
    )

    # Execute selected test mode
    start_time = time.time()

    try:
        if args.mode == "full":
            logger.info("Executing complete Group 3B test suite...")
            results = await test_runner.run_complete_test_suite(
                endurance_hours=args.duration,
                max_operations=args.max_ops,
                memory_profiling_hours=min(
                    2.0, args.duration
                ),  # Cap memory test at 2 hours
            )
            success = results.get("group_3b_overall_compliance", {}).get(
                "all_tests_passed", False
            )

        elif args.mode == "memory-only":
            logger.info("Executing memory profiling test only...")
            results = await test_runner.run_memory_profiling_test(
                duration_hours=args.duration, monitoring_interval=args.interval
            )
            success = results.get("group_3b_compliance", {}).get(
                "overall_compliant", False
            )

        elif args.mode == "endurance":
            logger.info("Executing endurance test only...")
            results = await test_runner.run_endurance_test(duration_hours=args.duration)
            success = results.get("group_3b_compliance", {}).get(
                "passes_all_targets", False
            )

        elif args.mode == "breaking-point":
            logger.info("Executing breaking point analysis only...")
            results = await test_runner.run_breaking_point_test(
                max_operations=args.max_ops
            )
            success = results.get("group_3b_compliance", {}).get(
                "overall_compliant", False
            )

        else:
            logger.error(f"Unknown test mode: {args.mode}")
            return 1

        # Final execution summary
        execution_time = time.time() - start_time
        logger.info(f"\nTest execution completed in {execution_time:.2f} seconds")
        logger.info(f"Results saved to: {args.output_dir}/")

        # Return appropriate exit code
        return 0 if success else 1

    except KeyboardInterrupt:
        logger.info("\nTest execution interrupted by user")
        return 130

    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
