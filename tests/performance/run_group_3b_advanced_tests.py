#!/usr/bin/env python3
"""Execute Group 3B Advanced Performance Testing Suite.

This script orchestrates the execution of all Group 3B advanced performance tests:
- Database Performance Testing (PERF-006 Enhanced)
- Network Latency Analysis (PERF-008 Enhanced)
- Context7 Library Integration Testing
- Performance Target Validation

Usage:
    python run_group_3b_advanced_tests.py [--duration MINUTES] [--target-qps QPS]
"""

import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from performance.test_group_3b_advanced_performance import (
        Group3BAdvancedPerformanceTester,
    )
    from framework.performance_validator import AdvancedPerformanceValidator
except ImportError as e:
    logging.error(f"Import error: {e}")
    logging.error(
        "Make sure you're running from the correct directory and all dependencies are installed"
    )
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("group_3b_advanced_performance.log"),
    ],
)
logger = logging.getLogger(__name__)


class Group3BTestRunner:
    """Orchestrates Group 3B Advanced Performance Testing execution."""

    def __init__(self, test_duration_minutes: int = 15, target_qps: int = 500):
        self.test_duration_minutes = test_duration_minutes
        self.target_qps = target_qps
        self.tester = Group3BAdvancedPerformanceTester(test_duration_minutes)
        self.validator = AdvancedPerformanceValidator()

    async def run_complete_group_3b_test_suite(self) -> int:
        """Run complete Group 3B advanced performance test suite."""
        logger.info("=" * 80)
        logger.info("STARTING GROUP 3B ADVANCED PERFORMANCE TEST SUITE")
        logger.info("=" * 80)
        logger.info(f"Test Duration: {self.test_duration_minutes} minutes")
        logger.info(f"Target QPS: {self.target_qps}")
        logger.info(f"Started: {datetime.now().isoformat()}")

        overall_start_time = time.time()

        try:
            # Execute Group 3B Advanced Performance Tests
            logger.info("\nExecuting Group 3B Advanced Performance Tests...")
            performance_result = (
                await self.tester.run_group_3b_advanced_performance_tests()
            )

            # Validate performance results
            logger.info("\nValidating Group 3B performance results...")
            validation_result = await self._validate_performance_results(
                performance_result
            )

            # Generate comprehensive summary
            overall_end_time = time.time()
            total_duration = (overall_end_time - overall_start_time) / 60

            success = self._generate_final_report(
                performance_result, validation_result, total_duration
            )

            return 0 if success else 1

        except Exception as e:
            logger.error(f"Group 3B test suite failed with error: {str(e)}")
            logger.error("Stack trace:", exc_info=True)
            return 1

    async def _validate_performance_results(self, performance_result) -> Any:
        """Validate Group 3B performance results."""
        # Extract results for validation
        database_results = {
            "queries_per_second": performance_result.database_queries_per_second,
            "medical_accuracy_percent": performance_result.medical_data_accuracy_percent,
            "concurrent_connections_tested": performance_result.database_concurrent_connections,
            "success_rate_percent": performance_result.database_success_rate,
        }

        network_results = {
            "ragnostic_bsn_latency_ms": performance_result.ragnostic_bsn_latency_ms,
            "service_communication_p95_ms": performance_result.service_communication_p95_ms,
            "service_communication_p99_ms": performance_result.service_communication_p99_ms,
            "external_api_latency_ms": performance_result.external_api_latency_ms,
            "network_resilience_score": performance_result.network_resilience_score,
        }

        context7_results = {
            "k6_load_test_score": performance_result.k6_load_test_score,
            "prometheus_metrics_collected": performance_result.prometheus_metrics_collected,
            "jaeger_traces_analyzed": performance_result.jaeger_traces_analyzed,
            "overall_integration_score": (
                performance_result.k6_load_test_score
                + min(1.0, performance_result.prometheus_metrics_collected / 50)
                + min(1.0, performance_result.jaeger_traces_analyzed / 20)
            )
            / 3,
        }

        # Run validation
        return await self.validator.validate_group_3b_performance(
            database_results, network_results, context7_results
        )

    def _generate_final_report(
        self, performance_result, validation_result, total_duration: float
    ) -> bool:
        """Generate final Group 3B test execution report."""
        logger.info("\n" + "=" * 80)
        logger.info("GROUP 3B ADVANCED PERFORMANCE TEST SUITE - FINAL REPORT")
        logger.info("=" * 80)

        # Execution Summary
        logger.info("\nExecution Summary:")
        logger.info(f"  Total Duration: {total_duration:.1f} minutes")
        logger.info("  Test Suite: Group 3B Advanced Performance Testing")
        logger.info(f"  Execution Time: {datetime.now().isoformat()}")

        # Performance Results Summary
        logger.info("\nPerformance Results Summary:")
        logger.info(
            f"  Database QPS: {performance_result.database_queries_per_second:.1f} (Target: >500)"
        )
        logger.info(
            f"  Cross-Service Latency: {performance_result.ragnostic_bsn_latency_ms:.1f}ms (Target: <50ms)"
        )
        logger.info(
            f"  Medical Accuracy: {performance_result.medical_data_accuracy_percent:.1f}% (Target: >98%)"
        )
        logger.info(
            f"  Concurrent Users: {performance_result.concurrent_user_capacity} (Target: >150)"
        )
        logger.info(
            f"  Context7 Integration: k6={performance_result.k6_load_test_score:.2f}, Metrics={performance_result.prometheus_metrics_collected}, Traces={performance_result.jaeger_traces_analyzed}"
        )

        # Validation Results
        logger.info("\nValidation Results:")
        logger.info(
            f"  All Performance Targets Met: {'✅' if validation_result.all_performance_targets_met else '⚠️'}"
        )
        logger.info(
            f"  Medical Accuracy Preserved: {'✅' if validation_result.medical_accuracy_preserved else '⚠️'}"
        )
        logger.info(
            f"  Context7 Integration Successful: {'✅' if validation_result.context7_integration_successful else '⚠️'}"
        )

        # Issues and Recommendations
        if validation_result.critical_issues:
            logger.info("\n🚨 Critical Issues Detected:")
            for issue in validation_result.critical_issues:
                logger.warning(f"  • {issue}")

        if validation_result.warnings:
            logger.info("\n⚠️ Warnings:")
            for warning in validation_result.warnings:
                logger.info(f"  • {warning}")

        if validation_result.recommendations:
            logger.info("\n💡 Recommendations:")
            for recommendation in validation_result.recommendations:
                logger.info(f"  • {recommendation}")

        # Overall Success Determination
        success = (
            performance_result.all_targets_met
            and validation_result.all_performance_targets_met
            and validation_result.medical_accuracy_preserved
        )

        # Final Status
        if success:
            logger.info("\n🎉 GROUP 3B ADVANCED PERFORMANCE TEST SUITE - SUCCESSFUL!")
            logger.info("  • All database performance targets exceeded")
            logger.info("  • All network latency targets met")
            logger.info("  • Context7 integration fully operational")
            logger.info("  • Medical accuracy preservation maintained")
        else:
            logger.warning(
                "\n⚠️ GROUP 3B ADVANCED PERFORMANCE TEST SUITE - ATTENTION REQUIRED"
            )
            logger.warning("  • Review critical issues and warnings above")
            logger.warning("  • Address performance gaps before production deployment")
            logger.warning("  • Implement recommended optimizations")

        logger.info("\n" + "=" * 80)

        # Write summary to file
        self._write_execution_summary(
            performance_result, validation_result, success, total_duration
        )

        return success

    def _write_execution_summary(
        self, performance_result, validation_result, success: bool, duration: float
    ):
        """Write execution summary to file."""
        summary_file = Path("group_3b_execution_summary.md")

        with open(summary_file, "w") as f:
            f.write("# Group 3B Advanced Performance Testing - Execution Summary\n\n")
            f.write(
                f"**Execution Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"**Duration**: {duration:.1f} minutes\n")
            f.write(
                f"**Overall Success**: {'✅ PASSED' if success else '❌ FAILED'}\n\n"
            )

            f.write("## Performance Results\n\n")
            f.write(
                f"- **Database QPS**: {performance_result.database_queries_per_second:.1f} (Target: >500)\n"
            )
            f.write(
                f"- **Cross-Service Latency**: {performance_result.ragnostic_bsn_latency_ms:.1f}ms (Target: <50ms)\n"
            )
            f.write(
                f"- **Medical Accuracy**: {performance_result.medical_data_accuracy_percent:.1f}% (Target: >98%)\n"
            )
            f.write(
                f"- **Concurrent Users**: {performance_result.concurrent_user_capacity} (Target: >150)\n"
            )
            f.write(
                f"- **API Response P95**: {performance_result.service_communication_p95_ms:.1f}ms (Target: <200ms)\n"
            )
            f.write(
                f"- **API Response P99**: {performance_result.service_communication_p99_ms:.1f}ms (Target: <500ms)\n\n"
            )

            f.write("## Context7 Integration\n\n")
            f.write(
                f"- **k6 Load Testing**: {performance_result.k6_load_test_score:.2f} (Target: >0.7)\n"
            )
            f.write(
                f"- **Prometheus Metrics**: {performance_result.prometheus_metrics_collected} (Target: >50)\n"
            )
            f.write(
                f"- **Jaeger Traces**: {performance_result.jaeger_traces_analyzed} (Target: >20)\n\n"
            )

            f.write("## Target Compliance\n\n")
            f.write(
                f"- **Database Performance**: {'✅' if validation_result.database_qps_target_met else '❌'}\n"
            )
            f.write(
                f"- **Network Latency**: {'✅' if validation_result.cross_service_target_met else '❌'}\n"
            )
            f.write(
                f"- **Medical Accuracy**: {'✅' if validation_result.medical_accuracy_preserved else '❌'}\n"
            )
            f.write(
                f"- **Context7 Integration**: {'✅' if validation_result.context7_integration_successful else '❌'}\n\n"
            )

            if validation_result.critical_issues:
                f.write("## Critical Issues\n\n")
                for issue in validation_result.critical_issues:
                    f.write(f"- {issue}\n")
                f.write("\n")

            if validation_result.recommendations:
                f.write("## Recommendations\n\n")
                for recommendation in validation_result.recommendations:
                    f.write(f"- {recommendation}\n")

        logger.info(f"Execution summary written to {summary_file}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Execute Group 3B Advanced Performance Testing Suite"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Test duration in minutes (default: 15)",
    )
    parser.add_argument(
        "--target-qps",
        type=int,
        default=500,
        help="Target database queries per second (default: 500)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create test runner
    runner = Group3BTestRunner(
        test_duration_minutes=args.duration, target_qps=args.target_qps
    )

    # Execute test suite
    exit_code = asyncio.run(runner.run_complete_group_3b_test_suite())

    # Exit with appropriate code
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
