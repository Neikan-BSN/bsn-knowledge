#!/usr/bin/env python3
"""
Test runner script for BSN Knowledge API testing suite.
Provides easy commands for running different test categories.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and handle output."""
    if description:
        print(f"\n🔄 {description}")
        print("=" * len(description))

    print(f"Command: {cmd}")

    try:
        # S603 fix: Validate command arguments for medical platform security
        validated_cmd = _validate_test_command(cmd.split())
        result = subprocess.run(
            validated_cmd,
            shell=False,
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
            check=False,
        )

        if result.returncode == 0:
            print("✅ Success!")
            if result.stdout:
                print(result.stdout)
        else:
            print("❌ Failed!")
            if result.stderr:
                print("Error output:")
                print(result.stderr)
            if result.stdout:
                print("Standard output:")
                print(result.stdout)

        return result.returncode == 0
    except Exception as e:
        print(f"❌ Exception occurred: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="BSN Knowledge API Test Runner")
    parser.add_argument(
        "test_type",
        choices=[
            "all",
            "auth",
            "endpoints",
            "rate",
            "security",
            "integration",
            "performance",
            "coverage",
            "quick",
        ],
        help="Type of tests to run",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-cov", action="store_true", help="Skip coverage reporting")

    args = parser.parse_args()

    print("🧪 BSN Knowledge API Test Runner")
    print("=" * 40)

    base_cmd = "python -m pytest"
    verbose_flag = " -v" if args.verbose else ""
    coverage_flag = "" if args.no_cov else " --cov=src --cov-report=term-missing"

    test_commands = {
        "all": f"{base_cmd} tests/{verbose_flag}{coverage_flag}",
        "auth": f"{base_cmd} tests/test_authentication.py{verbose_flag}",
        "endpoints": f"{base_cmd} tests/test_endpoints.py{verbose_flag}",
        "rate": f"{base_cmd} tests/test_rate_limiting.py{verbose_flag}",
        "security": f"{base_cmd} tests/test_security.py{verbose_flag}",
        "integration": f"{base_cmd} tests/test_integration.py{verbose_flag}",
        "performance": f"{base_cmd} tests/test_performance.py{verbose_flag} -m performance",
        "coverage": f"{base_cmd} tests/ --cov=src --cov-report=html --cov-report=term-missing",
        "quick": f"{base_cmd} tests/ -m 'not slow and not performance'{verbose_flag}",
    }

    descriptions = {
        "all": "Running all tests with coverage",
        "auth": "Running authentication and authorization tests",
        "endpoints": "Running API endpoint tests",
        "rate": "Running rate limiting tests",
        "security": "Running security tests",
        "integration": "Running integration tests",
        "performance": "Running performance tests",
        "coverage": "Running coverage analysis",
        "quick": "Running quick tests (excluding slow/performance)",
    }

    test_type = args.test_type

    if test_type not in test_commands:
        print(f"❌ Unknown test type: {test_type}")
        return 1

    success = run_command(test_commands[test_type], descriptions[test_type])

    if success:
        print(f"\n✅ {descriptions[test_type]} completed successfully!")

        if test_type == "coverage":
            print("\n📊 Coverage report generated!")
            print("View HTML report: open htmlcov/index.html")

        elif test_type == "all":
            print("\n🎉 All tests passed! API is ready for deployment.")

    else:
        print(f"\n❌ {descriptions[test_type]} failed!")
        print("Check the error output above for details.")
        return 1

    return 0


def _validate_test_command(cmd: list[str]) -> list[str]:
    """Validate test command for BSN Knowledge medical platform security (S603 fix)."""
    if not cmd:
        raise ValueError("Empty command not allowed for medical platform")

    # Whitelist of allowed executables for BSN Knowledge medical education platform
    allowed_executables = {
        "python",
        "python3",
        "pytest",
        "/usr/bin/python3",
        "/usr/bin/pytest",
    }

    executable = cmd[0]
    if executable not in allowed_executables:
        raise ValueError(
            f"Executable '{executable}' not allowed for medical education platform security"
        )

    # Validate pytest arguments for medical education compliance
    if len(cmd) > 1:
        allowed_args = {
            "-m",
            "pytest",
            "tests/",
            "-v",
            "--cov=src",
            "--cov-report=term-missing",
            "--cov-report=html",
            "performance",
            "not",
            "slow",
            "and",
        }

        for arg in cmd[1:]:
            # Allow test file paths and coverage patterns
            if (arg.startswith("tests/") and arg.endswith(".py")) or arg == "tests/":
                continue
            if arg.startswith("'not") or arg.startswith("'performance"):
                continue
            if arg not in allowed_args:
                raise ValueError(
                    f"Test argument '{arg}' not allowed for medical platform security"
                )

    return cmd


if __name__ == "__main__":
    sys.exit(main())
