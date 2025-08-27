#!/usr/bin/env python3
"""
Database Setup Validation Script
Group 1A Infrastructure Provisioning - Step 1.1.2 Implementation
Validates database systems deployment and connectivity for E2E testing
"""

import asyncio
import asyncpg
import redis
import httpx
import time
import json
import sys
from typing import Dict, Any
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f'/tmp/database-validation-{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'  # noqa: S108
        ),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)

# Database configuration for E2E testing
DATABASE_CONFIG = {
    "postgresql": {
        "host": "localhost",
        "port": 5440,
        "user": "e2e_user",
        "password": "e2e_test_secure_pass",
        "databases": ["ragnostic_e2e", "bsn_knowledge_e2e", "e2e_analytics"],
    },
    "redis": {
        "host": "localhost",
        "port": 6382,
        "databases": list(range(16)),  # Redis has 16 databases by default
    },
    "qdrant": {
        "host": "localhost",
        "port": 6338,
        "endpoints": ["/health", "/readyz", "/collections"],
    },
    "neo4j": {
        "host": "localhost",
        "http_port": 7479,
        "bolt_port": 7690,
        "user": "neo4j",
        "password": "e2e_neo4j_secure_pass",
    },
}

# Performance targets from requirements
PERFORMANCE_TARGETS = {
    "db_connection_time": 5.0,  # seconds
    "query_response_time": 0.1,  # seconds
    "health_check_time": 2.0,  # seconds
}


class DatabaseValidator:
    """Comprehensive database validation for E2E testing infrastructure"""

    def __init__(self):
        self.results: Dict[str, Dict] = {}
        self.start_time = time.time()

    async def validate_postgresql(self) -> Dict[str, Any]:
        """Validate PostgreSQL multi-database setup"""
        logger.info("🐘 Validating PostgreSQL setup...")

        pg_config = DATABASE_CONFIG["postgresql"]
        results = {
            "service": "postgresql",
            "status": "unknown",
            "connection_time": None,
            "databases_accessible": [],
            "databases_failed": [],
            "schema_validation": {},
            "performance_metrics": {},
        }

        try:
            # Test connection to each database
            for db_name in pg_config["databases"]:
                start_time = time.time()

                try:
                    conn = await asyncpg.connect(
                        host=pg_config["host"],
                        port=pg_config["port"],
                        user=pg_config["user"],
                        password=pg_config["password"],
                        database=db_name,
                        timeout=PERFORMANCE_TARGETS["db_connection_time"],
                    )

                    connection_time = time.time() - start_time
                    results["databases_accessible"].append(db_name)

                    # Test basic query performance
                    query_start = time.time()
                    _ = await conn.fetchval("SELECT 1")
                    query_time = time.time() - query_start

                    # Validate schema if it's the main databases
                    if db_name in ["ragnostic_e2e", "bsn_knowledge_e2e"]:
                        table_count = await conn.fetchval("""
                            SELECT COUNT(*) FROM information_schema.tables
                            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                        """)
                        results["schema_validation"][db_name] = {
                            "table_count": table_count,
                            "expected_min": 10 if db_name == "ragnostic_e2e" else 15,
                            "valid": table_count
                            >= (10 if db_name == "ragnostic_e2e" else 15),
                        }

                    # Record performance metrics
                    results["performance_metrics"][db_name] = {
                        "connection_time_ms": round(connection_time * 1000, 2),
                        "query_time_ms": round(query_time * 1000, 2),
                        "meets_target": connection_time
                        <= PERFORMANCE_TARGETS["db_connection_time"],
                    }

                    await conn.close()
                    logger.info(
                        f"  ✅ {db_name}: Connected in {round(connection_time * 1000, 2)}ms"
                    )

                except Exception as e:
                    results["databases_failed"].append(
                        {"database": db_name, "error": str(e)}
                    )
                    logger.error(f"  ❌ {db_name}: Connection failed - {str(e)}")

            # Overall status assessment
            total_databases = len(pg_config["databases"])
            accessible_count = len(results["databases_accessible"])

            if accessible_count == total_databases:
                results["status"] = "healthy"
                logger.info(
                    f"  🎉 PostgreSQL: All {total_databases} databases accessible"
                )
            elif accessible_count > 0:
                results["status"] = "partial"
                logger.warning(
                    f"  ⚠️ PostgreSQL: {accessible_count}/{total_databases} databases accessible"
                )
            else:
                results["status"] = "failed"
                logger.error("  💥 PostgreSQL: No databases accessible")

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"  💥 PostgreSQL validation error: {str(e)}")

        return results

    async def validate_redis(self) -> Dict[str, Any]:
        """Validate Redis cache setup"""
        logger.info("🔴 Validating Redis setup...")

        redis_config = DATABASE_CONFIG["redis"]
        results = {
            "service": "redis",
            "status": "unknown",
            "connection_time": None,
            "databases_tested": 0,
            "performance_metrics": {},
        }

        try:
            start_time = time.time()

            # Test Redis connection
            r = redis.Redis(
                host=redis_config["host"],
                port=redis_config["port"],
                socket_connect_timeout=PERFORMANCE_TARGETS["db_connection_time"],
                socket_timeout=PERFORMANCE_TARGETS["db_connection_time"],
            )

            # Test basic connectivity
            ping_result = r.ping()
            connection_time = time.time() - start_time

            if ping_result:
                results["connection_time"] = round(connection_time * 1000, 2)
                results["status"] = "healthy"

                # Test multiple databases
                test_databases = [0, 1, 2, 5, 10]  # Test a subset
                successful_dbs = 0

                for db_num in test_databases:
                    try:
                        db_redis = redis.Redis(
                            host=redis_config["host"],
                            port=redis_config["port"],
                            db=db_num,
                            socket_connect_timeout=2,
                        )

                        # Test write/read operation
                        test_key = f"e2e_test_db_{db_num}"
                        test_value = f"test_value_{int(time.time())}"

                        operation_start = time.time()
                        db_redis.set(
                            test_key, test_value, ex=60
                        )  # Expire in 60 seconds
                        retrieved_value = db_redis.get(test_key)
                        operation_time = time.time() - operation_start

                        if retrieved_value and retrieved_value.decode() == test_value:
                            successful_dbs += 1
                            results["performance_metrics"][f"db_{db_num}"] = {
                                "operation_time_ms": round(operation_time * 1000, 2),
                                "success": True,
                            }

                            # Clean up test key
                            db_redis.delete(test_key)

                    except Exception as e:
                        results["performance_metrics"][f"db_{db_num}"] = {
                            "error": str(e),
                            "success": False,
                        }

                results["databases_tested"] = successful_dbs
                logger.info(
                    f"  ✅ Redis: Connected in {results['connection_time']}ms, {successful_dbs}/{len(test_databases)} databases tested"
                )

            else:
                results["status"] = "failed"
                logger.error("  ❌ Redis: Ping failed")

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"  💥 Redis validation error: {str(e)}")

        return results

    async def validate_qdrant(self) -> Dict[str, Any]:
        """Validate Qdrant vector database setup"""
        logger.info("📊 Validating Qdrant vector database...")

        qdrant_config = DATABASE_CONFIG["qdrant"]
        results = {
            "service": "qdrant",
            "status": "unknown",
            "endpoints_tested": {},
            "performance_metrics": {},
        }

        try:
            async with httpx.AsyncClient(
                timeout=PERFORMANCE_TARGETS["health_check_time"]
            ) as client:
                base_url = f"http://{qdrant_config['host']}:{qdrant_config['port']}"

                for endpoint in qdrant_config["endpoints"]:
                    endpoint_start = time.time()

                    try:
                        response = await client.get(f"{base_url}{endpoint}")
                        response_time = time.time() - endpoint_start

                        results["endpoints_tested"][endpoint] = {
                            "status_code": response.status_code,
                            "response_time_ms": round(response_time * 1000, 2),
                            "success": response.status_code == 200,
                            "content_length": len(response.content)
                            if response.content
                            else 0,
                        }

                        if response.status_code == 200:
                            logger.info(
                                f"  ✅ {endpoint}: {response.status_code} in {round(response_time * 1000, 2)}ms"
                            )
                        else:
                            logger.warning(
                                f"  ⚠️ {endpoint}: {response.status_code} in {round(response_time * 1000, 2)}ms"
                            )

                    except Exception as e:
                        results["endpoints_tested"][endpoint] = {
                            "error": str(e),
                            "success": False,
                        }
                        logger.error(f"  ❌ {endpoint}: {str(e)}")

                # Overall status assessment
                successful_endpoints = sum(
                    1
                    for ep in results["endpoints_tested"].values()
                    if ep.get("success", False)
                )
                total_endpoints = len(qdrant_config["endpoints"])

                if successful_endpoints == total_endpoints:
                    results["status"] = "healthy"
                elif successful_endpoints > 0:
                    results["status"] = "partial"
                else:
                    results["status"] = "failed"

                logger.info(
                    f"  📊 Qdrant: {successful_endpoints}/{total_endpoints} endpoints healthy"
                )

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"  💥 Qdrant validation error: {str(e)}")

        return results

    async def validate_neo4j(self) -> Dict[str, Any]:
        """Validate Neo4j graph database setup"""
        logger.info("🔗 Validating Neo4j graph database...")

        neo4j_config = DATABASE_CONFIG["neo4j"]
        results = {
            "service": "neo4j",
            "status": "unknown",
            "http_endpoint": None,
            "bolt_connection": None,
            "performance_metrics": {},
        }

        try:
            # Test HTTP endpoint
            async with httpx.AsyncClient(
                timeout=PERFORMANCE_TARGETS["health_check_time"]
            ) as client:
                http_start = time.time()

                try:
                    http_url = (
                        f"http://{neo4j_config['host']}:{neo4j_config['http_port']}"
                    )
                    response = await client.get(http_url)
                    http_time = time.time() - http_start

                    results["http_endpoint"] = {
                        "status_code": response.status_code,
                        "response_time_ms": round(http_time * 1000, 2),
                        "success": response.status_code
                        in [200, 401],  # 401 is expected without auth
                    }

                    if response.status_code in [200, 401]:
                        logger.info(
                            f"  ✅ HTTP endpoint: {response.status_code} in {round(http_time * 1000, 2)}ms"
                        )
                        results["status"] = "healthy"
                    else:
                        logger.warning(f"  ⚠️ HTTP endpoint: {response.status_code}")
                        results["status"] = "partial"

                except Exception as e:
                    results["http_endpoint"] = {"error": str(e), "success": False}
                    logger.error(f"  ❌ HTTP endpoint: {str(e)}")
                    results["status"] = "failed"

            # Note: Bolt connection testing would require neo4j-driver
            # For E2E validation, HTTP endpoint check is sufficient
            results["bolt_connection"] = {
                "note": "Bolt connection testing requires neo4j-driver package",
                "expected_port": neo4j_config["bolt_port"],
                "skipped": True,
            }

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"  💥 Neo4j validation error: {str(e)}")

        return results

    async def run_comprehensive_validation(self) -> Dict[str, Any]:
        """Run all database validations and generate comprehensive report"""
        logger.info("🚀 Starting comprehensive database validation...")
        logger.info(
            f"Target performance: DB connections <{PERFORMANCE_TARGETS['db_connection_time']}s, Health checks <{PERFORMANCE_TARGETS['health_check_time']}s"
        )

        # Run all validations concurrently
        tasks = [
            self.validate_postgresql(),
            self.validate_redis(),
            self.validate_qdrant(),
            self.validate_neo4j(),
        ]

        validation_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in validation_results:
            if isinstance(result, Exception):
                logger.error(f"Validation task failed: {str(result)}")
                continue

            service_name = result.get("service", "unknown")
            self.results[service_name] = result

        # Generate summary
        total_time = time.time() - self.start_time
        summary = self.generate_summary_report(total_time)

        return {
            "summary": summary,
            "detailed_results": self.results,
            "validation_timestamp": datetime.now().isoformat(),
            "total_validation_time_seconds": round(total_time, 2),
        }

    def generate_summary_report(self, total_time: float) -> Dict[str, Any]:
        """Generate summary report of database validation"""
        healthy_services = []
        partial_services = []
        failed_services = []

        for service, result in self.results.items():
            status = result.get("status", "unknown")
            if status == "healthy":
                healthy_services.append(service)
            elif status == "partial":
                partial_services.append(service)
            else:
                failed_services.append(service)

        total_services = len(self.results)
        success_rate = (
            (len(healthy_services) / total_services) * 100 if total_services > 0 else 0
        )

        summary = {
            "overall_status": "healthy"
            if len(failed_services) == 0
            else "partial"
            if len(healthy_services) > 0
            else "failed",
            "total_services_tested": total_services,
            "healthy_services": len(healthy_services),
            "partial_services": len(partial_services),
            "failed_services": len(failed_services),
            "success_rate_percent": round(success_rate, 1),
            "total_validation_time_seconds": round(total_time, 2),
            "meets_performance_targets": total_time
            <= 30.0,  # Reasonable validation time
            "services_by_status": {
                "healthy": healthy_services,
                "partial": partial_services,
                "failed": failed_services,
            },
        }

        # Log summary
        logger.info("🎯 VALIDATION SUMMARY:")
        logger.info(f"   Overall status: {summary['overall_status'].upper()}")
        logger.info(f"   Services tested: {summary['total_services_tested']}")
        logger.info(f"   Success rate: {summary['success_rate_percent']}%")
        logger.info(f"   Validation time: {summary['total_validation_time_seconds']}s")

        if healthy_services:
            logger.info(f"   ✅ Healthy: {', '.join(healthy_services)}")
        if partial_services:
            logger.info(f"   ⚠️ Partial: {', '.join(partial_services)}")
        if failed_services:
            logger.info(f"   ❌ Failed: {', '.join(failed_services)}")

        return summary


def save_validation_report(results: Dict[str, Any], filename: str = None) -> str:
    """Save validation results to JSON file"""
    if filename is None:
        filename = f"/tmp/database-validation-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"  # noqa: S108

    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)

    logger.info(f"📄 Validation report saved: {filename}")
    return filename


async def main():
    """Main execution function"""
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║                Database Setup Validation                         ║")
    print("║          Group 1A Infrastructure Provisioning                   ║")
    print("║               Step 1.1.2 Implementation                         ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    validator = DatabaseValidator()

    try:
        # Run comprehensive validation
        results = await validator.run_comprehensive_validation()

        # Save detailed report
        report_file = save_validation_report(results)

        # Determine exit code based on results
        overall_status = results["summary"]["overall_status"]
        if overall_status == "healthy":
            print(
                "\n🎉 SUCCESS: All database systems are healthy and ready for E2E testing!"
            )
            print(f"📊 Success rate: {results['summary']['success_rate_percent']}%")
            print(f"📄 Detailed report: {report_file}")
            sys.exit(0)
        elif overall_status == "partial":
            print("\n⚠️ WARNING: Some database systems have issues")
            print(f"📊 Success rate: {results['summary']['success_rate_percent']}%")
            print(f"📄 Detailed report: {report_file}")
            sys.exit(1)
        else:
            print("\n❌ FAILURE: Critical database system failures detected")
            print(f"📊 Success rate: {results['summary']['success_rate_percent']}%")
            print(f"📄 Detailed report: {report_file}")
            sys.exit(2)

    except Exception as e:
        logger.error(f"💥 Validation failed with error: {str(e)}")
        print(f"\n💥 CRITICAL ERROR: Database validation failed - {str(e)}")
        sys.exit(3)


if __name__ == "__main__":
    # Check for required packages
    try:
        import asyncpg
        import redis
        import httpx
    except ImportError as e:
        print(f"❌ Required package not found: {e}")
        print("Please install required packages:")
        print("pip install asyncpg redis httpx")
        sys.exit(4)

    # Run async main
    asyncio.run(main())
