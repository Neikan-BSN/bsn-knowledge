#!/usr/bin/env python3
"""
BSN Knowledge B.7 Comprehensive Test Suite Runner

Automated test execution script for Task B.7 comprehensive testing requirements.
Runs all test categories with performance monitoring, coverage reporting, and
detailed result analysis.

Features:
- Parallel test execution with optimal resource utilization
- Real-time performance monitoring and reporting
- Comprehensive coverage analysis (>90% target)
- Security vulnerability assessment
- CI/CD integration readiness validation
- Detailed HTML and JSON reporting
- Performance benchmark validation
- Rate limiting compliance testing

Usage:
    python run_b7_test_suite.py [options]

Options:
    --quick         Run quick test suite (core tests only)
    --full          Run full comprehensive test suite (default)
    --performance   Run performance tests only
    --security      Run security tests only
    --coverage      Generate coverage report
    --html-report   Generate HTML test report
    --ci-mode       Run in CI/CD mode (minimal output)
    --benchmark     Run performance benchmarks
"""

import argparse
import concurrent.futures
import json
import logging
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Configure logging for medical platform audit trail
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class TestExecutionResult:
    """Container for test execution results."""

    category: str
    tests_run: int
    tests_passed: int
    tests_failed: int
    tests_skipped: int
    execution_time: float
    coverage_percentage: float
    exit_code: int
    output: str
    performance_metrics: dict[str, Any]


@dataclass
class ComprehensiveTestReport:
    """Container for comprehensive test suite results."""

    total_tests: int
    total_passed: int
    total_failed: int
    total_skipped: int
    total_execution_time: float
    overall_coverage: float
    categories: list[TestExecutionResult]
    performance_benchmarks: dict[str, Any]
    security_assessment: dict[str, Any]
    ci_cd_readiness: bool
    recommendations: list[str]
    generated_at: str


class B7TestSuiteRunner:
    """Comprehensive test suite runner for BSN Knowledge B.7 requirements."""

    def __init__(self, args):
        self.args = args
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        self.results_dir = self.project_root / "test_results"
        self.results_dir.mkdir(exist_ok=True)

        self.test_categories = {
            "unit": {
                "pattern": "test_comprehensive_b6_endpoints.py",
                "markers": "b6_endpoints and not performance and not security",
                "timeout": 300,
                "description": "Unit tests for B.6 API endpoints",
            },
            "integration": {
                "pattern": "test_comprehensive_b6_endpoints.py",
                "markers": "b6_endpoints and integration",
                "timeout": 600,
                "description": "Integration tests for B.6 workflows",
            },
            "performance": {
                "pattern": "test_b6_performance_benchmarks.py",
                "markers": "performance and b6_endpoints",
                "timeout": 1200,
                "description": "Performance benchmark tests",
            },
            "security": {
                "pattern": "test_b6_security_validation.py",
                "markers": "security and b6_endpoints",
                "timeout": 900,
                "description": "Security validation tests",
            },
            "validation": {
                "pattern": "test_b7_comprehensive_validation.py",
                "markers": "b7_validation",
                "timeout": 300,
                "description": "B.7 test suite validation",
            },
        }

    def run_comprehensive_suite(self) -> ComprehensiveTestReport:
        """Run the complete B.7 test suite with comprehensive reporting."""
        print("🚀 Starting BSN Knowledge B.7 Comprehensive Test Suite")
        print(f"📅 Execution started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

        start_time = time.time()
        category_results = []

        # Determine which categories to run
        categories_to_run = self._determine_test_categories()

        # Run test categories
        if self.args.parallel:
            category_results = self._run_tests_parallel(categories_to_run)
        else:
            category_results = self._run_tests_sequential(categories_to_run)

        # Generate comprehensive report
        total_execution_time = time.time() - start_time
        report = self._generate_comprehensive_report(
            category_results, total_execution_time
        )

        # Save results
        self._save_results(report)

        # Display summary
        self._display_summary(report)

        return report

    def _determine_test_categories(self) -> list[str]:
        """Determine which test categories to run based on arguments."""
        if self.args.quick:
            return ["unit", "validation"]
        elif self.args.performance:
            return ["performance"]
        elif self.args.security:
            return ["security"]
        elif self.args.full or not any(
            [self.args.quick, self.args.performance, self.args.security]
        ):
            return list(self.test_categories.keys())
        else:
            return ["unit", "integration", "validation"]

    def _run_tests_sequential(self, categories: list[str]) -> list[TestExecutionResult]:
        """Run test categories sequentially."""
        results = []

        for category in categories:
            print(f"\n📋 Running {category.upper()} tests...")
            result = self._run_test_category(category)
            results.append(result)

            # Early termination on critical failures
            if result.exit_code != 0 and category in ["unit", "security"]:
                print(f"❌ Critical failure in {category} tests. Stopping execution.")
                if not self.args.continue_on_failure:
                    break

        return results

    def _run_tests_parallel(self, categories: list[str]) -> list[TestExecutionResult]:
        """Run test categories in parallel where possible."""
        # Some tests need to run sequentially (e.g., performance tests might interfere)
        sequential_categories = ["performance"]
        parallel_categories = [
            cat for cat in categories if cat not in sequential_categories
        ]

        results = []

        # Run parallel categories
        if parallel_categories:
            print(
                f"\n🔄 Running parallel test categories: {', '.join(parallel_categories)}"
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_to_category = {
                    executor.submit(self._run_test_category, category): category
                    for category in parallel_categories
                }

                for future in concurrent.futures.as_completed(future_to_category):
                    category = future_to_category[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        print(f"❌ {category} tests failed with exception: {exc}")
                        results.append(
                            TestExecutionResult(
                                category=category,
                                tests_run=0,
                                tests_passed=0,
                                tests_failed=1,
                                tests_skipped=0,
                                execution_time=0.0,
                                coverage_percentage=0.0,
                                exit_code=1,
                                output=str(exc),
                                performance_metrics={},
                            )
                        )

        # Run sequential categories
        for category in sequential_categories:
            if category in categories:
                print(f"\n📋 Running {category.upper()} tests (sequential)...")
                result = self._run_test_category(category)
                results.append(result)

        return results

    def _run_test_category(self, category: str) -> TestExecutionResult:
        """Run a specific test category and return results."""
        config = self.test_categories[category]
        start_time = time.time()

        # Build pytest command
        cmd = self._build_pytest_command(category, config)

        # Execute tests
        print(f"  🔸 {config['description']}")
        print(f"  🔸 Command: {' '.join(cmd)}")

        try:
            # S603 fix: Validate subprocess command for medical platform security
            validated_cmd = self._validate_command_for_medical_security(cmd)
            result = subprocess.run(  # noqa: S603 # Validated subprocess call with medical platform security
                validated_cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=config["timeout"],
                check=False,  # Handle return codes explicitly
            )

            execution_time = time.time() - start_time

            # Parse test results
            test_stats = self._parse_pytest_output(result.stdout, result.stderr)

            # Get coverage if enabled
            coverage_percentage = (
                self._extract_coverage(result.stdout) if self.args.coverage else 0.0
            )

            # Extract performance metrics
            performance_metrics = self._extract_performance_metrics(
                result.stdout, category
            )

            return TestExecutionResult(
                category=category,
                tests_run=test_stats["total"],
                tests_passed=test_stats["passed"],
                tests_failed=test_stats["failed"],
                tests_skipped=test_stats["skipped"],
                execution_time=execution_time,
                coverage_percentage=coverage_percentage,
                exit_code=result.returncode,
                output=result.stdout + result.stderr,
                performance_metrics=performance_metrics,
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            print(f"  ⚠️  {category} tests timed out after {config['timeout']}s")

            return TestExecutionResult(
                category=category,
                tests_run=0,
                tests_passed=0,
                tests_failed=1,
                tests_skipped=0,
                execution_time=execution_time,
                coverage_percentage=0.0,
                exit_code=124,  # Timeout exit code
                output=f"Tests timed out after {config['timeout']} seconds",
                performance_metrics={},
            )

        except Exception as e:
            execution_time = time.time() - start_time
            print(f"  ❌ {category} tests failed with exception: {e}")

            return TestExecutionResult(
                category=category,
                tests_run=0,
                tests_passed=0,
                tests_failed=1,
                tests_skipped=0,
                execution_time=execution_time,
                coverage_percentage=0.0,
                exit_code=1,
                output=str(e),
                performance_metrics={},
            )

    def _validate_command_for_medical_security(self, cmd: list[str]) -> list[str]:
        """Validate subprocess commands for medical platform security compliance.

        Ensures only safe commands are executed in medical data processing environment.
        Critical for HIPAA compliance and audit trails.
        """
        if not cmd:
            raise ValueError("Empty command not allowed in medical platform")

        # Allowlist of safe commands for medical testing environment
        safe_commands = {
            "python",
            "pytest",
            "coverage",
            "bandit",
            "ruff",
            "mypy",
            "uv",
            "pip",
            "git",
            "echo",
            "cat",
            "ls",
            "find",
            "grep",
        }

        base_command = cmd[0].split("/")[-1]  # Get command name without path

        if base_command not in safe_commands:
            raise ValueError(
                f"Command '{base_command}' not authorized for medical platform: {cmd}"
            )

        # Additional validation for medical data processing
        dangerous_patterns = [
            "rm",
            "del",
            "format",
            "fdisk",
            "wget",
            "curl",
            "nc",
            "netcat",
        ]
        for pattern in dangerous_patterns:
            if any(pattern in arg.lower() for arg in cmd):
                raise ValueError(
                    f"Dangerous pattern '{pattern}' detected in command: {cmd}"
                )

        return cmd

    def _build_pytest_command(self, category: str, config: dict[str, Any]) -> list[str]:
        """Build pytest command for a specific test category."""
        cmd = ["python", "-m", "pytest"]

        # Add test file/pattern
        if config["pattern"]:
            test_path = self.test_dir / config["pattern"]
            if test_path.exists():
                cmd.append(str(test_path))
            else:
                cmd.append(f"tests/{config['pattern']}")

        # Add markers
        if config["markers"]:
            cmd.extend(["-m", config["markers"]])

        # Add common options
        cmd.extend(
            [
                "-v",  # Verbose output
                "--tb=short",  # Short traceback format
                "--durations=10",  # Show slowest 10 tests
            ]
        )

        # Add coverage if requested
        if self.args.coverage:
            cmd.extend(
                [
                    "--cov=src",
                    "--cov-report=term-missing",
                    "--cov-report=html:test_results/htmlcov",
                ]
            )

        # Add performance benchmarking
        if category == "performance":
            cmd.extend(
                [
                    "--benchmark-only",
                    "--benchmark-json=test_results/benchmark.json",
                ]
            )

        # CI mode adjustments
        if self.args.ci_mode:
            cmd.extend(
                [
                    "--quiet",
                    "--tb=line",
                ]
            )

        # Add HTML report
        if self.args.html_report:
            cmd.extend(
                [
                    "--html=test_results/report.html",
                    "--self-contained-html",
                ]
            )

        return cmd

    def _parse_pytest_output(self, stdout: str, stderr: str) -> dict[str, int]:
        """Parse pytest output to extract test statistics."""
        output = stdout + stderr

        stats = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "error": 0}

        # Look for pytest summary line
        summary_patterns = [
            r"(\d+) passed",
            r"(\d+) failed",
            r"(\d+) skipped",
            r"(\d+) error",
        ]

        import re

        for pattern in summary_patterns:
            matches = re.findall(pattern, output)
            if matches:
                stat_name = pattern.split()[1].rstrip(
                    "d"
                )  # Remove 'd' from 'failed', etc.
                stats[stat_name] = int(matches[-1])  # Use last match

        stats["total"] = (
            stats["passed"] + stats["failed"] + stats["skipped"] + stats["error"]
        )

        return stats

    def _extract_coverage(self, output: str) -> float:
        """Extract coverage percentage from pytest output."""
        import re

        # Look for coverage percentage
        coverage_pattern = r"TOTAL\s+\d+\s+\d+\s+(\d+)%"
        matches = re.findall(coverage_pattern, output)

        if matches:
            return float(matches[-1])

        return 0.0

    def _extract_performance_metrics(
        self, output: str, category: str
    ) -> dict[str, Any]:
        """Extract performance metrics from test output."""
        metrics = {}

        if category == "performance":
            import re

            # Extract timing information
            timing_pattern = r"test_.*?\s+(\d+\.?\d*)s"
            timings = re.findall(timing_pattern, output)

            if timings:
                timing_values = [float(t) for t in timings]
                metrics = {
                    "average_test_time": sum(timing_values) / len(timing_values),
                    "max_test_time": max(timing_values),
                    "min_test_time": min(timing_values),
                    "total_tests_timed": len(timing_values),
                }

        return metrics

    def _generate_comprehensive_report(
        self,
        category_results: list[TestExecutionResult],
        total_execution_time: float,
    ) -> ComprehensiveTestReport:
        """Generate comprehensive test report."""

        # Aggregate statistics
        total_tests = sum(r.tests_run for r in category_results)
        total_passed = sum(r.tests_passed for r in category_results)
        total_failed = sum(r.tests_failed for r in category_results)
        total_skipped = sum(r.tests_skipped for r in category_results)

        # Calculate overall coverage
        coverage_results = [
            r.coverage_percentage for r in category_results if r.coverage_percentage > 0
        ]
        overall_coverage = (
            sum(coverage_results) / len(coverage_results) if coverage_results else 0.0
        )

        # Analyze performance benchmarks
        performance_benchmarks = self._analyze_performance_benchmarks(category_results)

        # Security assessment
        security_assessment = self._analyze_security_results(category_results)

        # CI/CD readiness assessment
        ci_cd_readiness = self._assess_ci_cd_readiness(category_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            category_results, overall_coverage
        )

        return ComprehensiveTestReport(
            total_tests=total_tests,
            total_passed=total_passed,
            total_failed=total_failed,
            total_skipped=total_skipped,
            total_execution_time=total_execution_time,
            overall_coverage=overall_coverage,
            categories=category_results,
            performance_benchmarks=performance_benchmarks,
            security_assessment=security_assessment,
            ci_cd_readiness=ci_cd_readiness,
            recommendations=recommendations,
            generated_at=datetime.now().isoformat(),
        )

    def _analyze_performance_benchmarks(
        self, results: list[TestExecutionResult]
    ) -> dict[str, Any]:
        """Analyze performance benchmark results."""
        performance_results = [r for r in results if r.category == "performance"]

        if not performance_results:
            return {"status": "not_run", "benchmarks": {}}

        perf_result = performance_results[0]

        benchmarks = {
            "status": "completed" if perf_result.exit_code == 0 else "failed",
            "execution_time": perf_result.execution_time,
            "tests_run": perf_result.tests_run,
            "performance_metrics": perf_result.performance_metrics,
        }

        # Load benchmark JSON if available
        benchmark_file = self.results_dir / "benchmark.json"
        if benchmark_file.exists():
            try:
                with open(benchmark_file) as f:
                    benchmark_data = json.load(f)
                    benchmarks["detailed_benchmarks"] = benchmark_data
            except Exception as e:
                # S110 fix: Log exceptions for medical platform audit trail
                print(f"Warning: Could not load benchmark data: {e}")
                logger.warning(
                    "benchmark_load_failed", error=str(e), file=str(benchmark_file)
                )

        return benchmarks

    def _analyze_security_results(
        self, results: list[TestExecutionResult]
    ) -> dict[str, Any]:
        """Analyze security test results."""
        security_results = [r for r in results if r.category == "security"]

        if not security_results:
            return {"status": "not_run", "vulnerabilities": []}

        sec_result = security_results[0]

        assessment = {
            "status": "passed" if sec_result.exit_code == 0 else "failed",
            "tests_run": sec_result.tests_run,
            "tests_passed": sec_result.tests_passed,
            "tests_failed": sec_result.tests_failed,
            "vulnerabilities": [],
            "security_score": 0.0,
        }

        # Calculate security score
        if sec_result.tests_run > 0:
            assessment["security_score"] = (
                sec_result.tests_passed / sec_result.tests_run
            ) * 100

        # Extract vulnerability information from output
        if sec_result.tests_failed > 0:
            assessment["vulnerabilities"] = self._extract_security_failures(
                sec_result.output
            )

        return assessment

    def _extract_security_failures(self, output: str) -> list[str]:
        """Extract security test failures as potential vulnerabilities."""
        vulnerabilities = []

        # Look for failed security tests in output
        import re

        failure_pattern = r"FAILED.*test_.*security.*"
        failures = re.findall(failure_pattern, output, re.IGNORECASE)

        for failure in failures:
            vulnerabilities.append(failure.strip())

        return vulnerabilities

    def _assess_ci_cd_readiness(self, results: list[TestExecutionResult]) -> bool:
        """Assess CI/CD integration readiness."""
        validation_results = [r for r in results if r.category == "validation"]

        if not validation_results:
            return False

        validation_result = validation_results[0]
        return validation_result.exit_code == 0 and validation_result.tests_passed > 0

    def _generate_recommendations(
        self, results: list[TestExecutionResult], coverage: float
    ) -> list[str]:
        """Generate recommendations based on test results."""
        recommendations = []

        # Coverage recommendations
        if coverage < 90.0:
            recommendations.append(
                f"Increase test coverage from {coverage:.1f}% to 90%+ target"
            )

        # Performance recommendations
        perf_results = [r for r in results if r.category == "performance"]
        if perf_results and perf_results[0].tests_failed > 0:
            recommendations.append(
                "Address performance test failures - some endpoints may exceed response time requirements"
            )

        # Security recommendations
        sec_results = [r for r in results if r.category == "security"]
        if sec_results and sec_results[0].tests_failed > 0:
            recommendations.append(
                "Critical: Address security test failures before production deployment"
            )

        # General test health
        total_failed = sum(r.tests_failed for r in results)
        if total_failed > 0:
            recommendations.append(
                f"Fix {total_failed} failing tests before production deployment"
            )

        # CI/CD readiness
        if not self._assess_ci_cd_readiness(results):
            recommendations.append("Complete CI/CD integration validation")

        return recommendations

    def _save_results(self, report: ComprehensiveTestReport):
        """Save test results to files."""
        # Save JSON report
        json_file = self.results_dir / "b7_test_report.json"
        with open(json_file, "w") as f:
            json.dump(asdict(report), f, indent=2, default=str)

        # Save summary report
        summary_file = self.results_dir / "b7_test_summary.txt"
        with open(summary_file, "w") as f:
            self._write_text_summary(f, report)

        print("\n📄 Results saved to:")
        print(f"  📊 JSON Report: {json_file}")
        print(f"  📋 Summary: {summary_file}")

        if self.args.html_report:
            html_file = self.results_dir / "report.html"
            if html_file.exists():
                print(f"  🌐 HTML Report: {html_file}")

    def _write_text_summary(self, f, report: ComprehensiveTestReport):
        """Write text summary report."""
        f.write("BSN Knowledge B.7 Test Suite - Execution Summary\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Generated: {report.generated_at}\n")
        f.write(f"Total Execution Time: {report.total_execution_time:.2f} seconds\n\n")

        f.write("Overall Results:\n")
        f.write(f"  Total Tests: {report.total_tests}\n")
        f.write(f"  Passed: {report.total_passed}\n")
        f.write(f"  Failed: {report.total_failed}\n")
        f.write(f"  Skipped: {report.total_skipped}\n")
        f.write(f"  Coverage: {report.overall_coverage:.1f}%\n")
        f.write(f"  CI/CD Ready: {'Yes' if report.ci_cd_readiness else 'No'}\n\n")

        f.write("Category Results:\n")
        for result in report.categories:
            f.write(f"  {result.category.upper()}:\n")
            f.write(
                f"    Tests: {result.tests_run} | Passed: {result.tests_passed} | Failed: {result.tests_failed}\n"
            )
            f.write(
                f"    Time: {result.execution_time:.2f}s | Coverage: {result.coverage_percentage:.1f}%\n\n"
            )

        if report.recommendations:
            f.write("Recommendations:\n")
            for i, rec in enumerate(report.recommendations, 1):
                f.write(f"  {i}. {rec}\n")

    def _display_summary(self, report: ComprehensiveTestReport):
        """Display test execution summary."""
        print("\n" + "=" * 80)
        print("🏁 BSN Knowledge B.7 Test Suite - EXECUTION COMPLETE")
        print("=" * 80)

        # Overall status
        overall_success = report.total_failed == 0
        status_emoji = "✅" if overall_success else "❌"

        print(
            f"\n{status_emoji} OVERALL STATUS: {'PASSED' if overall_success else 'FAILED'}"
        )
        print(f"⏱️  Total Execution Time: {report.total_execution_time:.2f} seconds")
        print(f"🧪 Total Tests: {report.total_tests}")
        print(f"✅ Passed: {report.total_passed}")
        print(f"❌ Failed: {report.total_failed}")
        print(f"⏭️  Skipped: {report.total_skipped}")
        print(f"📊 Coverage: {report.overall_coverage:.1f}%")

        # Category breakdown
        print("\n📋 CATEGORY RESULTS:")
        for result in report.categories:
            status = "✅" if result.exit_code == 0 else "❌"
            print(
                f"  {status} {result.category.upper()}: {result.tests_passed}/{result.tests_run} passed ({result.execution_time:.1f}s)"
            )

        # Performance benchmarks
        if report.performance_benchmarks["status"] == "completed":
            print("\n⚡ PERFORMANCE BENCHMARKS: ✅ COMPLETED")
        elif report.performance_benchmarks["status"] == "failed":
            print("\n⚡ PERFORMANCE BENCHMARKS: ❌ FAILED")

        # Security assessment
        if report.security_assessment["status"] == "passed":
            print(
                f"🔒 SECURITY ASSESSMENT: ✅ PASSED ({report.security_assessment['security_score']:.1f}%)"
            )
        elif report.security_assessment["status"] == "failed":
            print(
                f"🔒 SECURITY ASSESSMENT: ❌ FAILED ({len(report.security_assessment['vulnerabilities'])} issues)"
            )

        # CI/CD readiness
        ci_status = "✅ READY" if report.ci_cd_readiness else "❌ NOT READY"
        print(f"🚀 CI/CD READINESS: {ci_status}")

        # Recommendations
        if report.recommendations:
            print("\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"  {i}. {rec}")

        # B.7 Requirements Assessment
        print("\n📝 B.7 REQUIREMENTS ASSESSMENT:")
        b7_requirements = {
            "Unit Test Coverage >90%": report.overall_coverage >= 90.0,
            "Integration Tests Complete": any(
                r.category == "integration" and r.exit_code == 0
                for r in report.categories
            ),
            "Performance Tests Pass": any(
                r.category == "performance" and r.exit_code == 0
                for r in report.categories
            ),
            "Security Tests Pass": any(
                r.category == "security" and r.exit_code == 0 for r in report.categories
            ),
            "Error Handling Complete": report.total_failed == 0,
            "CI/CD Integration Ready": report.ci_cd_readiness,
        }

        for requirement, met in b7_requirements.items():
            status = "✅" if met else "❌"
            print(f"  {status} {requirement}")

        b7_compliance = sum(b7_requirements.values()) / len(b7_requirements) * 100
        print(f"\n🎯 B.7 COMPLIANCE: {b7_compliance:.1f}%")

        if b7_compliance >= 100:
            print("🎉 CONGRATULATIONS! All B.7 requirements met.")
        elif b7_compliance >= 90:
            print("🔸 Nearly complete. Address remaining issues for full compliance.")
        else:
            print("⚠️  Additional work needed to meet B.7 requirements.")


def main():
    """Main entry point for B.7 test suite runner."""
    parser = argparse.ArgumentParser(
        description="BSN Knowledge B.7 Comprehensive Test Suite Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_b7_test_suite.py                    # Run full test suite
    python run_b7_test_suite.py --quick            # Run quick test suite
    python run_b7_test_suite.py --performance      # Run performance tests only
    python run_b7_test_suite.py --security         # Run security tests only
    python run_b7_test_suite.py --coverage         # Include coverage reporting
    python run_b7_test_suite.py --html-report      # Generate HTML report
    python run_b7_test_suite.py --ci-mode          # Run in CI/CD mode
        """,
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick test suite (unit tests and validation only)",
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full comprehensive test suite (default)",
    )

    parser.add_argument(
        "--performance", action="store_true", help="Run performance tests only"
    )

    parser.add_argument(
        "--security", action="store_true", help="Run security tests only"
    )

    parser.add_argument(
        "--coverage", action="store_true", help="Generate test coverage report"
    )

    parser.add_argument(
        "--html-report", action="store_true", help="Generate HTML test report"
    )

    parser.add_argument(
        "--ci-mode", action="store_true", help="Run in CI/CD mode (minimal output)"
    )

    parser.add_argument(
        "--parallel", action="store_true", help="Run tests in parallel where possible"
    )

    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Continue running tests even after failures",
    )

    args = parser.parse_args()

    # Default to full suite if no specific mode chosen
    if not any([args.quick, args.performance, args.security]):
        args.full = True

    # Create and run test suite
    runner = B7TestSuiteRunner(args)

    try:
        report = runner.run_comprehensive_suite()

        # Exit with appropriate code
        exit_code = 0 if report.total_failed == 0 else 1
        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Test execution failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
