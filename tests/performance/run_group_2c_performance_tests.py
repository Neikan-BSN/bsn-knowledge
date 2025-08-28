#!/usr/bin/env python3
"""
Group 2C: Performance Testing Scenarios Execution Framework
E2E RAGnostic → BSN Knowledge Pipeline Performance Validation

This script executes all 8 performance test cases (PERF-001 to PERF-008)
as specified in the Group 2C testing requirements.

Test Cases:
- PERF-001: Baseline Performance Testing
- PERF-002: Stress Testing & Breaking Point Analysis
- PERF-003: Endurance Testing (8-hour)
- PERF-004: Concurrent User Load Testing
- PERF-005: Batch Processing Performance
- PERF-006: Database Performance Testing
- PERF-007: Memory Profiling & Leak Detection
- PERF-008: Network Latency Impact Analysis

Usage:
    python tests/performance/run_group_2c_performance_tests.py [options]
"""

import argparse
import asyncio
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("performance_test_execution.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class Group2CPerformanceTestSuite:
    """Comprehensive Group 2C performance testing suite executor."""

    def __init__(self, console: Console):
        self.console = console
        self.test_results = {}
        self.start_time = datetime.now()
        self.performance_dir = Path(__file__).parent

        # Performance test specifications
        self.test_cases = {
            "PERF-001": {
                "name": "Baseline Performance Testing",
                "script": "perf_001_baseline_performance.py",
                "duration": "15 minutes",
                "priority": "critical",
                "targets": {
                    "concurrent_users": ">100",
                    "api_response_p95": "<200ms",
                    "processing_time": "<2s",
                    "accuracy_preservation": ">98%",
                },
            },
            "PERF-002": {
                "name": "Stress Testing & Breaking Point Analysis",
                "script": "perf_002_stress_testing.py",
                "duration": "30 minutes",
                "priority": "critical",
                "targets": {
                    "breaking_point": ">500 ops/sec",
                    "recovery_time": "<30s",
                    "graceful_degradation": "verified",
                },
            },
            "PERF-003": {
                "name": "Endurance Testing (8-hour)",
                "script": "perf_003_endurance_testing.py",
                "duration": "8 hours",
                "priority": "high",
                "targets": {
                    "stability": "8 hours continuous",
                    "memory_leaks": "none detected",
                    "performance_degradation": "<5%",
                },
            },
            "PERF-004": {
                "name": "Concurrent User Load Testing",
                "script": "perf_004_concurrent_user_load.py",
                "duration": "25 minutes",
                "priority": "critical",
                "targets": {
                    "concurrent_users": ">150",
                    "session_management": "validated",
                    "response_distribution": "p95 <300ms",
                },
            },
            "PERF-005": {
                "name": "Batch Processing Performance",
                "script": "perf_005_batch_processing.py",
                "duration": "20 minutes",
                "priority": "high",
                "targets": {
                    "concurrent_batches": ">15",
                    "documents_per_batch": ">500",
                    "throughput": ">50 docs/min",
                },
            },
            "PERF-006": {
                "name": "Database Performance Testing",
                "script": "perf_006_database_performance.py",
                "duration": "15 minutes",
                "priority": "critical",
                "targets": {
                    "query_throughput": ">1000/min",
                    "connection_pooling": "optimized",
                    "transaction_performance": "<100ms",
                },
            },
            "PERF-007": {
                "name": "Memory Profiling & Leak Detection",
                "script": "perf_007_memory_profiling.py",
                "duration": "35 minutes",
                "priority": "high",
                "targets": {
                    "memory_usage": "<2GB under load",
                    "leak_detection": "comprehensive",
                    "gc_optimization": "validated",
                },
            },
            "PERF-008": {
                "name": "Network Latency Impact Analysis",
                "script": "perf_008_network_latency.py",
                "duration": "20 minutes",
                "priority": "medium",
                "targets": {
                    "internal_latency": "<50ms",
                    "external_api_latency": "<500ms",
                    "timeout_handling": "validated",
                },
            },
        }

    async def validate_test_environment(self) -> bool:
        """Validate that the test environment is ready for performance testing."""
        self.console.print(
            Panel(
                "[bold blue]🔍 Validating Test Environment[/bold blue]\n\n"
                + "Checking infrastructure readiness for Group 2C performance testing...",
                title="Environment Validation",
                border_style="blue",
            )
        )

        validation_checks = []

        # Check Docker services
        try:
            result = subprocess.run(
                ["docker", "compose", "ps"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                validation_checks.append(("Docker Services", "✅ Running"))
            else:
                validation_checks.append(("Docker Services", "❌ Not running"))
        except Exception as e:
            validation_checks.append(("Docker Services", f"❌ Error: {str(e)[:50]}"))

        # Check test data availability
        test_data_path = project_root / "tests" / "data" / "medical_test_corpus.json"
        if test_data_path.exists():
            validation_checks.append(("Medical Test Data", "✅ Available"))
        else:
            validation_checks.append(("Medical Test Data", "❌ Missing"))

        # Check performance baseline files
        baseline_file = self.performance_dir / "performance_benchmarks.py"
        if baseline_file.exists():
            validation_checks.append(("Performance Baselines", "✅ Configured"))
        else:
            validation_checks.append(("Performance Baselines", "❌ Missing"))

        # Check all PERF test files
        missing_tests = []
        for test_id, test_info in self.test_cases.items():
            test_file = self.performance_dir / test_info["script"]
            if not test_file.exists():
                missing_tests.append(test_id)

        if missing_tests:
            validation_checks.append(
                ("PERF Test Files", f"❌ Missing: {', '.join(missing_tests)}")
            )
        else:
            validation_checks.append(("PERF Test Files", "✅ All present"))

        # Display validation results
        table = Table(title="Environment Validation Results")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold")

        for component, status in validation_checks:
            table.add_row(component, status)

        self.console.print(table)

        # Check if environment is ready
        failed_checks = [check for check in validation_checks if "❌" in check[1]]
        if failed_checks:
            self.console.print(
                f"\n[bold red]❌ Environment validation failed: {len(failed_checks)} issues detected[/bold red]"
            )
            return False
        else:
            self.console.print(
                "\n[bold green]✅ Environment validation passed: All systems ready[/bold green]"
            )
            return True

    async def execute_test_case(self, test_id: str, test_info: Dict) -> Dict:
        """Execute a single performance test case."""
        test_script = self.performance_dir / test_info["script"]

        self.console.print(
            f"\n[bold cyan]🚀 Executing {test_id}: {test_info['name']}[/bold cyan]"
        )
        self.console.print(f"Expected Duration: {test_info['duration']}")
        self.console.print(f"Priority: {test_info['priority'].upper()}")

        start_time = datetime.now()

        try:
            # Execute the test script
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                str(test_script),
                "--automated",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=project_root,
            )

            stdout, stderr = await process.communicate()

            end_time = datetime.now()
            execution_time = end_time - start_time

            result = {
                "test_id": test_id,
                "name": test_info["name"],
                "status": "PASSED" if process.returncode == 0 else "FAILED",
                "execution_time": str(execution_time),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else "",
                "return_code": process.returncode,
                "targets": test_info["targets"],
            }

            if process.returncode == 0:
                self.console.print(
                    f"[bold green]✅ {test_id} completed successfully[/bold green]"
                )
            else:
                self.console.print(
                    f"[bold red]❌ {test_id} failed (exit code: {process.returncode})[/bold red]"
                )
                if stderr:
                    self.console.print(
                        f"[red]Error output: {stderr.decode()[:200]}...[/red]"
                    )

            return result

        except Exception as e:
            end_time = datetime.now()
            execution_time = end_time - start_time

            result = {
                "test_id": test_id,
                "name": test_info["name"],
                "status": "ERROR",
                "execution_time": str(execution_time),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "error": str(e),
                "return_code": -1,
                "targets": test_info["targets"],
            }

            self.console.print(
                f"[bold red]❌ {test_id} encountered an error: {str(e)}[/bold red]"
            )
            return result

    async def run_performance_tests(
        self, selected_tests: Optional[List[str]] = None, parallel: bool = False
    ) -> Dict:
        """Run the selected performance tests."""

        # Determine which tests to run
        if selected_tests:
            tests_to_run = {
                k: v for k, v in self.test_cases.items() if k in selected_tests
            }
        else:
            tests_to_run = self.test_cases

        self.console.print(
            Panel(
                "[bold blue]🎯 Group 2C Performance Testing Suite[/bold blue]\n\n"
                + f"Tests to execute: {len(tests_to_run)}\n"
                + f"Execution mode: {'Parallel' if parallel else 'Sequential'}\n"
                + f"Estimated duration: {self._calculate_total_duration(tests_to_run)}",
                title="Performance Test Execution Plan",
                border_style="blue",
            )
        )

        suite_results = {
            "suite_name": "Group 2C Performance Testing",
            "execution_start": self.start_time.isoformat(),
            "test_results": [],
            "summary": {},
        }

        if parallel:
            # Execute tests in parallel (for independent tests only)
            tasks = []
            for test_id, test_info in tests_to_run.items():
                if (
                    test_info["priority"] != "critical"
                ):  # Run non-critical tests in parallel
                    task = asyncio.create_task(
                        self.execute_test_case(test_id, test_info)
                    )
                    tasks.append(task)

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Parallel test execution error: {result}")
                    else:
                        suite_results["test_results"].append(result)
        else:
            # Execute tests sequentially
            for test_id, test_info in tests_to_run.items():
                result = await self.execute_test_case(test_id, test_info)
                suite_results["test_results"].append(result)

                # Add delay between tests for resource cleanup
                if test_id != list(tests_to_run.keys())[-1]:  # Not the last test
                    self.console.print(
                        "[dim]Waiting 30 seconds for resource cleanup...[/dim]"
                    )
                    await asyncio.sleep(30)

        # Calculate summary
        suite_end_time = datetime.now()
        total_duration = suite_end_time - self.start_time

        passed_tests = [
            r for r in suite_results["test_results"] if r["status"] == "PASSED"
        ]
        failed_tests = [
            r for r in suite_results["test_results"] if r["status"] == "FAILED"
        ]
        error_tests = [
            r for r in suite_results["test_results"] if r["status"] == "ERROR"
        ]

        suite_results["execution_end"] = suite_end_time.isoformat()
        suite_results["total_duration"] = str(total_duration)
        suite_results["summary"] = {
            "total_tests": len(suite_results["test_results"]),
            "passed": len(passed_tests),
            "failed": len(failed_tests),
            "errors": len(error_tests),
            "success_rate": len(passed_tests) / len(suite_results["test_results"]) * 100
            if suite_results["test_results"]
            else 0,
        }

        return suite_results

    def _calculate_total_duration(self, tests: Dict) -> str:
        """Calculate estimated total execution time."""
        duration_map = {
            "15 minutes": 15,
            "20 minutes": 20,
            "25 minutes": 25,
            "30 minutes": 30,
            "35 minutes": 35,
            "8 hours": 480,
        }

        total_minutes = sum(
            duration_map.get(test["duration"], 0) for test in tests.values()
        )

        if total_minutes >= 60:
            hours = total_minutes // 60
            minutes = total_minutes % 60
            return f"{hours}h {minutes}m"
        else:
            return f"{total_minutes}m"

    def generate_performance_report(self, results: Dict) -> None:
        """Generate comprehensive performance testing report."""

        # Display execution summary
        summary = results["summary"]
        success_rate = summary["success_rate"]

        if success_rate >= 90:
            status_color = "green"
            status_emoji = "✅"
        elif success_rate >= 70:
            status_color = "yellow"
            status_emoji = "⚠️"
        else:
            status_color = "red"
            status_emoji = "❌"

        self.console.print(
            Panel(
                f"[bold {status_color}]{status_emoji} Group 2C Performance Testing Complete[/bold {status_color}]\n\n"
                + f"Overall Success Rate: {success_rate:.1f}%\n"
                + f"Tests Passed: {summary['passed']}/{summary['total_tests']}\n"
                + f"Total Execution Time: {results['total_duration']}\n"
                + "Test Suite: E2E RAGnostic → BSN Knowledge Pipeline",
                title="Performance Testing Results Summary",
                border_style=status_color,
            )
        )

        # Detailed results table
        table = Table(title="📊 Performance Test Results Detail", show_header=True)
        table.add_column("Test ID", style="cyan", width=12)
        table.add_column("Test Name", width=35)
        table.add_column("Status", style="bold", width=10)
        table.add_column("Duration", width=12)
        table.add_column("Key Targets", width=30)

        for result in results["test_results"]:
            status_display = {
                "PASSED": "[green]✅ PASS[/green]",
                "FAILED": "[red]❌ FAIL[/red]",
                "ERROR": "[orange1]⚠️ ERROR[/orange1]",
            }.get(result["status"], result["status"])

            # Format key targets
            targets = result.get("targets", {})
            key_targets = ", ".join([f"{k}: {v}" for k, v in list(targets.items())[:2]])

            table.add_row(
                result["test_id"],
                result["name"][:34],
                status_display,
                result["execution_time"].split(".")[0],  # Remove microseconds
                key_targets,
            )

        self.console.print(table)

        # Performance targets validation
        critical_tests = [
            r
            for r in results["test_results"]
            if self.test_cases.get(r["test_id"], {}).get("priority") == "critical"
        ]
        critical_passed = [r for r in critical_tests if r["status"] == "PASSED"]

        self.console.print(
            Panel(
                "[bold blue]🎯 Performance Targets Validation[/bold blue]\n\n"
                + f"Critical Tests: {len(critical_passed)}/{len(critical_tests)} passed\n"
                + f"• Baseline Performance (PERF-001): {'✅ Validated' if any(r['test_id'] == 'PERF-001' and r['status'] == 'PASSED' for r in results['test_results']) else '❌ Failed'}\n"
                + f"• Stress Testing (PERF-002): {'✅ Validated' if any(r['test_id'] == 'PERF-002' and r['status'] == 'PASSED' for r in results['test_results']) else '❌ Failed'}\n"
                + f"• Concurrent Load (PERF-004): {'✅ Validated' if any(r['test_id'] == 'PERF-004' and r['status'] == 'PASSED' for r in results['test_results']) else '❌ Failed'}\n"
                + f"• Database Performance (PERF-006): {'✅ Validated' if any(r['test_id'] == 'PERF-006' and r['status'] == 'PASSED' for r in results['test_results']) else '❌ Failed'}",
                title="Critical Performance Metrics",
                border_style="blue",
            )
        )

        # Save detailed report to file
        report_file = (
            self.performance_dir
            / f"group_2c_performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_file, "w") as f:
            json.dump(results, f, indent=2)

        self.console.print(f"\n[dim]📄 Detailed report saved to: {report_file}[/dim]")


async def main():
    """Main execution function for Group 2C performance testing."""
    parser = argparse.ArgumentParser(
        description="Group 2C: Performance Testing Scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Performance Test Cases:
  PERF-001    Baseline Performance Testing (15 min)
  PERF-002    Stress Testing & Breaking Point Analysis (30 min)
  PERF-003    Endurance Testing - 8 hour duration (8 hours)
  PERF-004    Concurrent User Load Testing (25 min)
  PERF-005    Batch Processing Performance (20 min)
  PERF-006    Database Performance Testing (15 min)
  PERF-007    Memory Profiling & Leak Detection (35 min)
  PERF-008    Network Latency Impact Analysis (20 min)

Examples:
  # Run all performance tests
  python run_group_2c_performance_tests.py

  # Run specific test cases
  python run_group_2c_performance_tests.py --tests PERF-001 PERF-002

  # Skip environment validation
  python run_group_2c_performance_tests.py --skip-validation

  # Run with detailed output
  python run_group_2c_performance_tests.py --verbose
        """,
    )

    parser.add_argument(
        "--tests",
        nargs="*",
        choices=[
            "PERF-001",
            "PERF-002",
            "PERF-003",
            "PERF-004",
            "PERF-005",
            "PERF-006",
            "PERF-007",
            "PERF-008",
        ],
        help="Specific test cases to run (default: all tests)",
    )

    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip environment validation before testing",
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run non-critical tests in parallel (experimental)",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output during test execution",
    )

    args = parser.parse_args()

    # Configure console output
    console = Console()

    # Display header
    console.print(
        Panel(
            "[bold blue]Group 2C: Performance Testing Scenarios[/bold blue]\n\n"
            + "E2E RAGnostic → BSN Knowledge Pipeline Performance Validation\n"
            + "Medical Education Platform Performance Testing Framework\n\n"
            + f"Test Execution Mode: {'Selected tests' if args.tests else 'All 8 test cases'}\n"
            + f"Environment Validation: {'Skipped' if args.skip_validation else 'Enabled'}\n"
            + f"Parallel Execution: {'Enabled' if args.parallel else 'Sequential'}",
            title="🚀 Performance Testing Suite",
            border_style="blue",
        )
    )

    # Initialize test suite
    test_suite = Group2CPerformanceTestSuite(console)

    try:
        # Validate environment (unless skipped)
        if not args.skip_validation:
            environment_ready = await test_suite.validate_test_environment()
            if not environment_ready:
                console.print(
                    "\n[bold red]❌ Environment validation failed. Please fix issues and retry.[/bold red]"
                )
                sys.exit(1)

        # Execute performance tests
        results = await test_suite.run_performance_tests(
            selected_tests=args.tests, parallel=args.parallel
        )

        # Generate comprehensive report
        test_suite.generate_performance_report(results)

        # Determine exit code based on results
        success_rate = results["summary"]["success_rate"]
        if success_rate >= 90:
            console.print(
                "\n[bold green]🎉 Group 2C Performance Testing: SUCCESS[/bold green]"
            )
            sys.exit(0)
        elif success_rate >= 70:
            console.print(
                "\n[bold yellow]⚠️ Group 2C Performance Testing: PARTIAL SUCCESS[/bold yellow]"
            )
            sys.exit(1)
        else:
            console.print(
                "\n[bold red]❌ Group 2C Performance Testing: FAILED[/bold red]"
            )
            sys.exit(2)

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]⚠️ Performance testing interrupted by user[/bold yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(
            f"\n[bold red]❌ Performance testing suite error: {str(e)}[/bold red]"
        )
        logger.exception("Performance testing suite execution error")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
