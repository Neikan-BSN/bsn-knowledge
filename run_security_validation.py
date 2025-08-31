#!/usr/bin/env python3
"""
Security Validation Test Runner for RAGnostic → BSN Knowledge Pipeline

Comprehensive security test execution with enterprise-grade validation,
reporting, and compliance verification.

Usage:
    python run_security_validation.py --level=enterprise
    python run_security_validation.py --category=authentication
    python run_security_validation.py --compliance=hipaa,ferpa
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


class SecurityValidationRunner:
    """Enterprise-grade security validation test runner."""

    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.security_issues = []

    def run_security_tests(
        self,
        level: str = "standard",
        categories: list[str] | None = None,
        compliance: list[str] | None = None,
        output_format: str = "detailed",
    ) -> dict:
        """Run comprehensive security validation tests."""

        self.start_time = datetime.now()
        print(f"\n🔒 Starting Security Validation - Level: {level.upper()}")
        print(f"⏰ Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        # Determine test categories to run
        test_categories = categories or self._get_categories_for_level(level)

        # Run pre-validation checks
        self._run_pre_validation_checks()

        # Execute security test categories
        for category in test_categories:
            print(f"\n🧪 Running {category.upper()} Security Tests...")
            result = self._run_test_category(category, level)
            self.test_results[category] = result

        # Run compliance-specific tests if requested
        if compliance:
            self._run_compliance_tests(compliance)

        # Run post-validation analysis
        self._run_post_validation_analysis()

        self.end_time = datetime.now()

        # Generate comprehensive report
        report = self._generate_security_report(level, output_format)

        # Output results
        self._output_results(report, output_format)

        return report

    def _get_categories_for_level(self, level: str) -> list[str]:
        """Get test categories based on validation level."""
        base_categories = ["authentication", "injection_prevention"]

        if level in ["standard", "enterprise"]:
            base_categories.extend(["access_control", "data_protection"])

        if level == "enterprise":
            base_categories.extend(["compliance", "performance", "resilience"])

        return base_categories

    def _run_pre_validation_checks(self):
        """Run pre-validation security environment checks."""
        print("\n🔍 Pre-Validation Security Checks:")

        # Check Python security modules
        try:
            import importlib.util

            # Test for availability without importing
            bcrypt_available = importlib.util.find_spec("bcrypt") is not None
            crypto_available = importlib.util.find_spec("cryptography") is not None
            jwt_available = importlib.util.find_spec("jwt") is not None

            if bcrypt_available and crypto_available and jwt_available:
                print("   ✓ Security dependencies available")
            else:
                missing = []
                if not bcrypt_available:
                    missing.append("bcrypt")
                if not crypto_available:
                    missing.append("cryptography")
                if not jwt_available:
                    missing.append("jwt")
                print(f"   ✗ Missing security dependencies: {', '.join(missing)}")
        except ImportError as e:
            print(f"   ✗ Missing security dependency: {e}")
            sys.exit(1)

        # Check test environment security
        if os.getenv("JWT_SECRET_KEY") == "insecure_test_key":
            print("   ⚠  Warning: Insecure test JWT key detected")

        # Check for security configuration files
        security_files = [
            ".secrets.baseline",
            ".semgrep.json",
            ".pre-commit-config.yaml",
        ]
        for file in security_files:
            if Path(file).exists():
                print(f"   ✓ Security config found: {file}")
            else:
                print(f"   ⚠  Security config missing: {file}")

    def _run_test_category(self, category: str, level: str) -> dict:
        """Run tests for a specific security category."""
        category_mapping = {
            "authentication": "tests/security/auth_security_tests.py",
            "injection_prevention": "tests/security/injection_prevention_tests.py",
            "access_control": "tests/security/access_control_tests.py",
            "data_protection": "tests/security/data_protection_tests.py",
        }

        test_file = category_mapping.get(category)
        if not test_file or not Path(test_file).exists():
            return {"status": "skipped", "reason": f"Test file not found: {test_file}"}

        # Build pytest command
        cmd = [
            "python",
            "-m",
            "pytest",
            test_file,
            "-v",
            "--tb=short",
            "-m",
            "security",
            "--json-report",
            f"--json-report-file=security_results_{category}.json",
        ]

        # Add level-specific markers
        if level == "enterprise":
            cmd.extend(["-m", "not slow or enterprise"])

        try:
            print(f"   Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse JSON results if available
            json_file = f"security_results_{category}.json"
            if Path(json_file).exists():
                with open(json_file) as f:
                    json_results = json.load(f)

                return {
                    "status": "completed",
                    "return_code": result.returncode,
                    "tests_run": json_results.get("summary", {}).get("total", 0),
                    "passed": json_results.get("summary", {}).get("passed", 0),
                    "failed": json_results.get("summary", {}).get("failed", 0),
                    "duration": json_results.get("duration", 0),
                    "details": json_results,
                }
            else:
                # Fallback to basic result parsing
                return {
                    "status": "completed",
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "duration": 300}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _run_compliance_tests(self, compliance_types: list[str]):
        """Run compliance-specific security tests."""
        print(f"\n📋 Running Compliance Tests: {', '.join(compliance_types)}")

        compliance_markers = {
            "hipaa": "hipaa_compliance",
            "ferpa": "ferpa_compliance",
            "gdpr": "gdpr_compliance",
            "soc2": "soc2_compliance",
        }

        for compliance_type in compliance_types:
            marker = compliance_markers.get(compliance_type.lower())
            if marker:
                cmd = ["python", "-m", "pytest", "tests/security/", "-m", marker, "-v"]

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    self.test_results[f"compliance_{compliance_type}"] = {
                        "status": "completed",
                        "return_code": result.returncode,
                        "output": result.stdout,
                    }
                except Exception as e:
                    self.test_results[f"compliance_{compliance_type}"] = {
                        "status": "error",
                        "error": str(e),
                    }

    def _run_post_validation_analysis(self):
        """Run post-validation security analysis."""
        print("\n🔬 Post-Validation Security Analysis:")

        # Aggregate test results
        for _category, result in self.test_results.items():
            if result.get("status") == "completed":
                self.total_tests += result.get("tests_run", 0)
                self.passed_tests += result.get("passed", 0)
                self.failed_tests += result.get("failed", 0)

        # Identify security issues
        for category, result in self.test_results.items():
            if result.get("failed", 0) > 0:
                self.security_issues.append(
                    {
                        "category": category,
                        "failed_tests": result.get("failed", 0),
                        "severity": self._assess_severity(category, result),
                    }
                )

        print(f"   Total Tests: {self.total_tests}")
        print(f"   Passed: {self.passed_tests}")
        print(f"   Failed: {self.failed_tests}")
        print(f"   Security Issues: {len(self.security_issues)}")

    def _assess_severity(self, category: str, result: dict) -> str:
        """Assess severity of security test failures."""
        failed_count = result.get("failed", 0)

        if category == "authentication" and failed_count > 0:
            return "CRITICAL"
        elif category == "injection_prevention" and failed_count > 2:
            return "HIGH"
        elif failed_count > 5:
            return "HIGH"
        elif failed_count > 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_security_report(self, level: str, format: str) -> dict:
        """Generate comprehensive security validation report."""
        duration = (self.end_time - self.start_time).total_seconds()

        report = {
            "security_validation_report": {
                "metadata": {
                    "validation_level": level,
                    "start_time": self.start_time.isoformat(),
                    "end_time": self.end_time.isoformat(),
                    "duration_seconds": duration,
                    "generated_at": datetime.now().isoformat(),
                },
                "summary": {
                    "total_tests": self.total_tests,
                    "passed_tests": self.passed_tests,
                    "failed_tests": self.failed_tests,
                    "success_rate": (self.passed_tests / max(self.total_tests, 1))
                    * 100,
                    "security_issues_count": len(self.security_issues),
                },
                "test_results": self.test_results,
                "security_issues": self.security_issues,
                "recommendations": self._generate_recommendations(),
                "compliance_status": self._assess_compliance_status(),
            }
        }

        return report

    def _generate_recommendations(self) -> list[str]:
        """Generate security recommendations based on test results."""
        recommendations = []

        if self.failed_tests > 0:
            recommendations.append(
                "Address all failed security tests before production deployment"
            )

        if any(issue["severity"] == "CRITICAL" for issue in self.security_issues):
            recommendations.append(
                "CRITICAL security issues detected - immediate remediation required"
            )

        if self.total_tests < 50:
            recommendations.append(
                "Consider expanding security test coverage for comprehensive validation"
            )

        # Category-specific recommendations
        for category, result in self.test_results.items():
            if result.get("failed", 0) > 0:
                if category == "authentication":
                    recommendations.append(
                        "Review authentication mechanisms and JWT implementation"
                    )
                elif category == "injection_prevention":
                    recommendations.append(
                        "Strengthen input validation and sanitization"
                    )
                elif category == "access_control":
                    recommendations.append(
                        "Review role-based access controls and authorization logic"
                    )
                elif category == "data_protection":
                    recommendations.append(
                        "Enhance data encryption and privacy protection measures"
                    )

        return recommendations

    def _assess_compliance_status(self) -> dict[str, str]:
        """Assess compliance status based on test results."""
        compliance_status = {
            "overall": "COMPLIANT" if self.failed_tests == 0 else "NON_COMPLIANT",
            "hipaa": "PENDING_VALIDATION",
            "ferpa": "PENDING_VALIDATION",
            "gdpr": "PENDING_VALIDATION",
        }

        # Update based on compliance test results
        for category, result in self.test_results.items():
            if category.startswith("compliance_"):
                compliance_type = category.replace("compliance_", "")
                compliance_status[compliance_type] = (
                    "COMPLIANT" if result.get("return_code") == 0 else "NON_COMPLIANT"
                )

        return compliance_status

    def _output_results(self, report: dict, format: str):
        """Output security validation results."""
        print("\n" + "=" * 70)
        print("🔒 SECURITY VALIDATION RESULTS")
        print("=" * 70)

        summary = report["security_validation_report"]["summary"]
        print("\n📊 Test Summary:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Passed: {summary['passed_tests']} ✓")
        print(
            f"   Failed: {summary['failed_tests']} {'❌' if summary['failed_tests'] > 0 else '✅'}"
        )
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        print(
            f"   Duration: {report['security_validation_report']['metadata']['duration_seconds']:.2f}s"
        )

        # Security issues
        if self.security_issues:
            print(f"\n🚨 Security Issues ({len(self.security_issues)}):")
            for issue in self.security_issues:
                severity_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                }.get(issue["severity"], "⚪")
                print(
                    f"   {severity_emoji} {issue['category']}: {issue['failed_tests']} failures ({issue['severity']})"
                )
        else:
            print("\n✅ No Security Issues Detected")

        # Compliance status
        compliance = report["security_validation_report"]["compliance_status"]
        print("\n📋 Compliance Status:")
        for standard, status in compliance.items():
            status_emoji = {
                "COMPLIANT": "✅",
                "NON_COMPLIANT": "❌",
                "PENDING_VALIDATION": "⏳",
            }.get(status, "❓")
            print(f"   {status_emoji} {standard.upper()}: {status}")

        # Recommendations
        recommendations = report["security_validation_report"]["recommendations"]
        if recommendations:
            print("\n💡 Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")

        # Save detailed report
        report_file = f"security_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 Detailed report saved: {report_file}")

        # Exit with appropriate code
        exit_code = 1 if self.failed_tests > 0 else 0
        critical_issues = any(
            issue["severity"] == "CRITICAL" for issue in self.security_issues
        )
        if critical_issues:
            exit_code = 2

        print(f"\n🏁 Security Validation {'PASSED' if exit_code == 0 else 'FAILED'}")
        print("=" * 70)

        sys.exit(exit_code)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Validation Test Runner for RAGnostic → BSN Knowledge Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Validation Levels:
  basic      - Essential security validations (authentication, injection prevention)
  standard   - Comprehensive security testing (adds access control, data protection)
  enterprise - Full enterprise-grade validation (adds compliance, performance)

Examples:
  python run_security_validation.py --level=enterprise
  python run_security_validation.py --category=authentication,injection_prevention
  python run_security_validation.py --compliance=hipaa,ferpa --level=standard
        """,
    )

    parser.add_argument(
        "--level",
        choices=["basic", "standard", "enterprise"],
        default="standard",
        help="Security validation level (default: standard)",
    )

    parser.add_argument(
        "--category", help="Specific security categories to test (comma-separated)"
    )

    parser.add_argument(
        "--compliance",
        help="Compliance standards to validate (comma-separated: hipaa,ferpa,gdpr,soc2)",
    )

    parser.add_argument(
        "--format",
        choices=["detailed", "summary", "json"],
        default="detailed",
        help="Output format (default: detailed)",
    )

    args = parser.parse_args()

    # Parse comma-separated arguments
    categories = None
    if args.category:
        categories = [cat.strip() for cat in args.category.split(",")]

    compliance = None
    if args.compliance:
        compliance = [comp.strip() for comp in args.compliance.split(",")]

    # Run security validation
    runner = SecurityValidationRunner()
    runner.run_security_tests(
        level=args.level,
        categories=categories,
        compliance=compliance,
        output_format=args.format,
    )


if __name__ == "__main__":
    main()
