"""Test Orchestration Framework for E2E Pipeline Validation.

Provides comprehensive test execution coordination, parallel test management,
and result aggregation for multi-service integration testing.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Individual test result with comprehensive metrics."""

    test_id: str
    test_category: str
    test_name: str
    status: str  # "passed", "failed", "skipped", "error"
    duration_seconds: float
    error_message: str | None = None
    metrics: dict[str, Any] = None
    artifacts: list[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.metrics is None:
            self.metrics = {}
        if self.artifacts is None:
            self.artifacts = []


@dataclass
class TestSuite:
    """Test suite configuration and execution state."""

    suite_id: str
    name: str
    description: str
    test_cases: list[dict[str, Any]]
    parallel_execution: bool = True
    max_workers: int = 4
    timeout_seconds: int = 300
    retry_attempts: int = 1


class ServiceHealthChecker:
    """Health checking and dependency validation for test services."""

    def __init__(self, services_config: dict[str, str]):
        self.services = services_config
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def check_service_health(self, service_name: str, url: str) -> dict[str, Any]:
        """Check individual service health with detailed metrics."""
        start_time = time.time()
        try:
            response = await self.client.get(f"{url}/health")
            duration = time.time() - start_time

            return {
                "service": service_name,
                "status": "healthy" if response.status_code == 200 else "unhealthy",
                "status_code": response.status_code,
                "response_time_ms": round(duration * 1000, 2),
                "response_body": response.json()
                if response.headers.get("content-type", "").startswith(
                    "application/json"
                )
                else response.text[:200],
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            duration = time.time() - start_time
            return {
                "service": service_name,
                "status": "error",
                "error": str(e),
                "response_time_ms": round(duration * 1000, 2),
                "timestamp": datetime.now().isoformat(),
            }

    async def wait_for_services(self, max_wait_seconds: int = 120) -> bool:
        """Wait for all services to become healthy with exponential backoff."""
        logger.info(f"Waiting for {len(self.services)} services to become healthy...")

        wait_time = 1
        total_wait = 0

        while total_wait < max_wait_seconds:
            health_checks = []
            for service_name, url in self.services.items():
                health_checks.append(self.check_service_health(service_name, url))

            results = await asyncio.gather(*health_checks, return_exceptions=True)

            healthy_services = 0
            for result in results:
                if isinstance(result, dict) and result.get("status") == "healthy":
                    healthy_services += 1
                else:
                    logger.warning(f"Service check result: {result}")

            if healthy_services == len(self.services):
                logger.info(
                    f"All {len(self.services)} services are healthy after {total_wait:.1f}s"
                )
                return True

            logger.info(
                f"Services healthy: {healthy_services}/{len(self.services)}. Waiting {wait_time}s..."
            )
            await asyncio.sleep(wait_time)
            total_wait += wait_time
            wait_time = min(wait_time * 1.5, 10)  # Exponential backoff, max 10s

        logger.error(f"Services failed to become healthy within {max_wait_seconds}s")
        return False

    async def get_all_health_status(self) -> dict[str, Any]:
        """Get comprehensive health status for all services."""
        health_checks = []
        for service_name, url in self.services.items():
            health_checks.append(self.check_service_health(service_name, url))

        results = await asyncio.gather(*health_checks, return_exceptions=True)

        return {
            "timestamp": datetime.now().isoformat(),
            "services": results,
            "healthy_count": sum(
                1
                for r in results
                if isinstance(r, dict) and r.get("status") == "healthy"
            ),
            "total_count": len(self.services),
        }

    async def close(self):
        """Cleanup HTTP client resources."""
        await self.client.aclose()


class TestExecutor:
    """Parallel test execution with comprehensive result tracking."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.results: list[TestResult] = []

    async def execute_test_case(self, test_case: dict[str, Any]) -> TestResult:
        """Execute individual test case with metrics collection."""
        start_time = time.time()
        test_id = test_case.get("id", f"test_{int(time.time())}")

        try:
            logger.info(f"Executing test case: {test_id}")

            # Simulate test execution - replace with actual test logic
            test_function = test_case.get("function")
            test_params = test_case.get("params", {})

            if callable(test_function):
                if asyncio.iscoroutinefunction(test_function):
                    result = await test_function(**test_params)
                else:
                    result = test_function(**test_params)
            else:
                # Mock execution for demonstration
                await asyncio.sleep(0.1)
                result = {"status": "passed", "metrics": {"mock_metric": 1.0}}

            duration = time.time() - start_time

            return TestResult(
                test_id=test_id,
                test_category=test_case.get("category", "unknown"),
                test_name=test_case.get("name", test_id),
                status="passed",
                duration_seconds=duration,
                metrics=result.get("metrics", {}),
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Test case {test_id} failed: {str(e)}")

            return TestResult(
                test_id=test_id,
                test_category=test_case.get("category", "unknown"),
                test_name=test_case.get("name", test_id),
                status="failed",
                duration_seconds=duration,
                error_message=str(e),
            )

    def execute_test_suite_parallel(self, test_suite: TestSuite) -> list[TestResult]:
        """Execute test suite with parallel execution support."""
        logger.info(
            f"Starting test suite: {test_suite.name} ({len(test_suite.test_cases)} tests)"
        )

        if not test_suite.parallel_execution or len(test_suite.test_cases) == 1:
            # Sequential execution
            results = []
            for test_case in test_suite.test_cases:
                result = asyncio.run(self.execute_test_case(test_case))
                results.append(result)
            return results

        # Parallel execution with ThreadPoolExecutor
        with ThreadPoolExecutor(
            max_workers=min(test_suite.max_workers, len(test_suite.test_cases))
        ) as executor:
            future_to_test = {}

            for test_case in test_suite.test_cases:
                future = executor.submit(
                    lambda tc=test_case: asyncio.run(self.execute_test_case(tc))
                )
                future_to_test[future] = test_case

            results = []
            for future in as_completed(
                future_to_test, timeout=test_suite.timeout_seconds
            ):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    test_case = future_to_test[future]
                    logger.error(
                        f"Test execution failed for {test_case.get('id')}: {str(e)}"
                    )

                    results.append(
                        TestResult(
                            test_id=test_case.get("id", "unknown"),
                            test_category=test_case.get("category", "unknown"),
                            test_name=test_case.get("name", "unknown"),
                            status="error",
                            duration_seconds=0,
                            error_message=str(e),
                        )
                    )

            return results


class TestReporter:
    """Comprehensive test reporting with multiple output formats."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_summary_report(self, results: list[TestResult]) -> dict[str, Any]:
        """Generate comprehensive test execution summary."""
        total_tests = len(results)
        passed = sum(1 for r in results if r.status == "passed")
        failed = sum(1 for r in results if r.status == "failed")
        errors = sum(1 for r in results if r.status == "error")
        skipped = sum(1 for r in results if r.status == "skipped")

        total_duration = sum(r.duration_seconds for r in results)
        avg_duration = total_duration / total_tests if total_tests > 0 else 0

        # Performance metrics
        duration_p95 = (
            sorted([r.duration_seconds for r in results])[int(0.95 * len(results))]
            if results
            else 0
        )
        duration_p99 = (
            sorted([r.duration_seconds for r in results])[int(0.99 * len(results))]
            if results
            else 0
        )

        # Category breakdown
        categories = {}
        for result in results:
            cat = result.test_category
            if cat not in categories:
                categories[cat] = {"total": 0, "passed": 0, "failed": 0, "error": 0}

            categories[cat]["total"] += 1
            categories[cat][result.status] += 1

        return {
            "execution_summary": {
                "timestamp": datetime.now().isoformat(),
                "total_tests": total_tests,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "skipped": skipped,
                "success_rate": (passed / total_tests * 100) if total_tests > 0 else 0,
                "total_duration_seconds": round(total_duration, 2),
                "average_duration_seconds": round(avg_duration, 3),
                "p95_duration_seconds": round(duration_p95, 3),
                "p99_duration_seconds": round(duration_p99, 3),
            },
            "category_breakdown": categories,
            "test_results": [asdict(r) for r in results],
        }

    def save_json_report(
        self, results: list[TestResult], filename: str = "test_results.json"
    ):
        """Save test results in JSON format for programmatic analysis."""
        report = self.generate_summary_report(results)
        output_file = self.output_dir / filename

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON report saved to: {output_file}")

    def save_html_report(
        self, results: list[TestResult], filename: str = "test_results.html"
    ):
        """Generate HTML report with visualization and interactive elements."""
        summary = self.generate_summary_report(results)

        html_content = self._generate_html_template(summary)
        output_file = self.output_dir / filename

        with open(output_file, "w") as f:
            f.write(html_content)

        logger.info(f"HTML report saved to: {output_file}")

    def _generate_html_template(self, summary: dict[str, Any]) -> str:
        """Generate comprehensive HTML report template."""
        exec_summary = summary["execution_summary"]
        categories = summary["category_breakdown"]

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BSN Knowledge E2E Test Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric-value {{ font-size: 24px; font-weight: bold; }}
        .metric-label {{ font-size: 12px; color: #666; }}
        .success {{ color: #28a745; }}
        .failure {{ color: #dc3545; }}
        .warning {{ color: #ffc107; }}
        .category {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .status-passed {{ background-color: #d4edda; color: #155724; }}
        .status-failed {{ background-color: #f8d7da; color: #721c24; }}
        .status-error {{ background-color: #fff3cd; color: #856404; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BSN Knowledge E2E Pipeline Test Results</h1>
        <p>Execution completed at: {exec_summary["timestamp"]}</p>

        <div class="metric">
            <div class="metric-value success">{exec_summary["passed"]}</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value failure">{exec_summary["failed"]}</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric">
            <div class="metric-value warning">{exec_summary["errors"]}</div>
            <div class="metric-label">Errors</div>
        </div>
        <div class="metric">
            <div class="metric-value">{exec_summary["success_rate"]:.1f}%</div>
            <div class="metric-label">Success Rate</div>
        </div>
        <div class="metric">
            <div class="metric-value">{exec_summary["total_duration_seconds"]:.2f}s</div>
            <div class="metric-label">Total Duration</div>
        </div>
        <div class="metric">
            <div class="metric-value">{exec_summary["p95_duration_seconds"]:.3f}s</div>
            <div class="metric-label">P95 Duration</div>
        </div>
    </div>

    <h2>Category Breakdown</h2>"""

        for category, stats in categories.items():
            success_rate = (
                (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
            )
            html += f"""
    <div class="category">
        <h3>{category}</h3>
        <p>Total: {stats["total"]}, Passed: {stats["passed"]}, Failed: {stats["failed"]}, Success Rate: {success_rate:.1f}%</p>
    </div>"""

        html += """
    <h2>Detailed Test Results</h2>
    <table>
        <tr>
            <th>Test ID</th>
            <th>Category</th>
            <th>Name</th>
            <th>Status</th>
            <th>Duration (s)</th>
            <th>Error Message</th>
        </tr>"""

        for result in summary["test_results"]:
            status_class = f"status-{result['status']}"
            error_msg = (
                result.get("error_message", "")[:100]
                if result.get("error_message")
                else ""
            )

            html += f"""
        <tr>
            <td>{result["test_id"]}</td>
            <td>{result["test_category"]}</td>
            <td>{result["test_name"]}</td>
            <td class="{status_class}">{result["status"]}</td>
            <td>{result["duration_seconds"]:.3f}</td>
            <td>{error_msg}</td>
        </tr>"""

        html += """
    </table>
</body>
</html>"""

        return html


class E2ETestOrchestrator:
    """Main orchestrator for end-to-end pipeline testing."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.services = config.get("services", {})
        self.test_suites = config.get("test_suites", [])
        self.output_dir = Path(config.get("output_dir", "./test_results"))

        self.health_checker = ServiceHealthChecker(self.services)
        self.executor = TestExecutor(max_workers=config.get("max_workers", 4))
        self.reporter = TestReporter(self.output_dir)

    async def run_full_test_suite(self) -> dict[str, Any]:
        """Execute complete end-to-end test suite with health checking and reporting."""
        logger.info("Starting E2E test orchestration...")

        # Step 1: Health check all services
        logger.info("Performing service health checks...")
        services_ready = await self.health_checker.wait_for_services()

        if not services_ready:
            raise RuntimeError(
                "Services failed to become healthy - aborting test execution"
            )

        health_status = await self.health_checker.get_all_health_status()
        logger.info(
            f"All services healthy: {health_status['healthy_count']}/{health_status['total_count']}"
        )

        # Step 2: Execute all test suites
        all_results = []
        suite_summaries = []

        for suite_config in self.test_suites:
            suite = TestSuite(**suite_config)
            logger.info(f"Executing test suite: {suite.name}")

            suite_start_time = time.time()
            suite_results = self.executor.execute_test_suite_parallel(suite)
            suite_duration = time.time() - suite_start_time

            all_results.extend(suite_results)

            suite_summary = {
                "suite_id": suite.suite_id,
                "name": suite.name,
                "total_tests": len(suite_results),
                "passed": sum(1 for r in suite_results if r.status == "passed"),
                "failed": sum(1 for r in suite_results if r.status == "failed"),
                "duration_seconds": round(suite_duration, 2),
            }
            suite_summaries.append(suite_summary)

            logger.info(
                f"Suite '{suite.name}' completed: {suite_summary['passed']}/{suite_summary['total_tests']} passed"
            )

        # Step 3: Generate comprehensive reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.reporter.save_json_report(all_results, f"e2e_results_{timestamp}.json")
        self.reporter.save_html_report(all_results, f"e2e_results_{timestamp}.html")

        # Step 4: Generate final summary
        final_summary = self.reporter.generate_summary_report(all_results)
        final_summary["service_health"] = health_status
        final_summary["suite_summaries"] = suite_summaries

        # Cleanup
        await self.health_checker.close()

        logger.info(
            f"E2E testing completed. Success rate: {final_summary['execution_summary']['success_rate']:.1f}%"
        )

        return final_summary


# Example configuration and usage
if __name__ == "__main__":
    # Example configuration
    config = {
        "services": {
            "bsn-knowledge": "http://bsn-knowledge-test:8000",
            "ragnostic-mock": "http://ragnostic-mock:8000",
            "openai-mock": "http://openai-mock:8000",
            "umls-mock": "http://umls-mock:8000",
        },
        "test_suites": [
            {
                "suite_id": "e2e_pipeline",
                "name": "End-to-End Pipeline Tests",
                "description": "Complete RAGnostic -> BSN Knowledge pipeline validation",
                "test_cases": [
                    {
                        "id": "E2E-001",
                        "category": "integration",
                        "name": "UMLS to NCLEX Generation",
                    },
                    {
                        "id": "E2E-002",
                        "category": "performance",
                        "name": "Concurrent Load Testing",
                    },
                    {
                        "id": "E2E-003",
                        "category": "resilience",
                        "name": "Transaction Integrity",
                    },
                ],
                "parallel_execution": True,
                "max_workers": 3,
            }
        ],
        "output_dir": "./test_results",
        "max_workers": 4,
    }

    # Run orchestration
    orchestrator = E2ETestOrchestrator(config)
    summary = asyncio.run(orchestrator.run_full_test_suite())

    print(json.dumps(summary["execution_summary"], indent=2))
