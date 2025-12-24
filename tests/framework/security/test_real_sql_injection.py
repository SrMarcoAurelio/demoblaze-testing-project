"""
Real SQL Injection Testing
Uses HTTP interception and response analysis to detect real SQL injection vulnerabilities.

Author: Marc Arévalo
Version: 1.0

IMPORTANT: This test performs REAL security testing by:
1. Intercepting HTTP traffic
2. Analyzing server responses for SQL errors
3. Detecting authentication bypass
4. Generating detailed vulnerability reports

⚠️ ETHICAL WARNING: AUTHORIZED TESTING ONLY
"""

import logging

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from examples.demoblaze.pages.login_page import LoginPage
from utils.security.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.real_detection
def test_real_sql_injection_login_form(browser, base_url):
    """
    TC-SEC-REAL-SQL-001: Real SQL Injection Detection in Login Form

    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)

    This test performs REAL SQL injection detection by:
    - Injecting SQL payloads
    - Intercepting HTTP responses
    - Analyzing responses for SQL errors
    - Detecting authentication bypass

    Unlike basic UI tests, this detects:
    - SQL error messages in HTTP responses
    - Successful authentication bypass
    - Database information disclosure
    - Backend server errors
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Initialize vulnerability scanner
    scanner = VulnerabilityScanner(browser, base_url)

    logger.info("=" * 80)
    logger.info("STARTING REAL SQL INJECTION DETECTION")
    logger.info("=" * 80)

    # Open login modal
    login_page.open_login_modal()
    wait = WebDriverWait(browser, 10)

    # Get form elements
    username_field = wait.until(
        EC.presence_of_element_located((By.ID, "loginusername"))
    )
    password_field = browser.find_element(By.ID, "loginpassword")
    login_button = browser.find_element(
        By.CSS_SELECTOR, "button[onclick='logIn()']"
    )

    # Test for SQL injection
    vulnerabilities = scanner.scan_authentication_bypass(
        username_field=username_field,
        password_field=password_field,
        submit_button=login_button,
        url=base_url,
    )

    # Get report
    report = scanner.get_report()

    logger.info("=" * 80)
    logger.info("SQL INJECTION SCAN COMPLETE")
    logger.info(f"Total tests performed: {report.total_tests}")
    logger.info(f"Vulnerabilities found: {report.get_vulnerability_count()}")
    logger.info("=" * 80)

    # Save detailed report
    scanner.save_report(output_dir="reports/security_real")

    # Assert results
    if vulnerabilities:
        logger.critical("=" * 80)
        logger.critical("CRITICAL VULNERABILITIES DETECTED!")
        logger.critical("=" * 80)

        for vuln in vulnerabilities:
            logger.critical(f"Type: {vuln.vulnerability_type}")
            logger.critical(f"Severity: {vuln.severity.value.upper()}")
            logger.critical(f"Payload: {vuln.payload_used}")
            logger.critical(f"URL: {vuln.url}")
            logger.critical("Evidence:")
            for evidence in vuln.evidence:
                logger.critical(f"  - {evidence}")
            logger.critical(f"Remediation: {vuln.remediation}")
            logger.critical("=" * 80)

        pytest.fail(
            f"DISCOVERED: {len(vulnerabilities)} SQL injection vulnerabilities with REAL HTTP evidence. "
            f"See detailed report in reports/security_real/"
        )
    else:
        logger.info("✓ No SQL injection vulnerabilities detected")
        logger.info("✓ All SQL payloads were properly sanitized or blocked")
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.real_detection
def test_real_sql_injection_all_forms(browser, base_url):
    """
    TC-SEC-REAL-SQL-002: Scan All Forms for SQL Injection

    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)

    Automatically scans all input fields on the page for SQL injection
    with real HTTP response analysis.

    This is a comprehensive test that:
    - Finds all input fields automatically
    - Tests each with multiple SQL payloads
    - Analyzes HTTP responses for each test
    - Generates detailed vulnerability report
    """
    browser.get(base_url)

    # Initialize vulnerability scanner
    scanner = VulnerabilityScanner(browser, base_url)

    logger.info("=" * 80)
    logger.info("SCANNING ALL FORMS FOR SQL INJECTION")
    logger.info("=" * 80)

    # Scan all inputs on the page
    vulnerabilities = scanner.scan_all_inputs(
        vulnerability_types=["sql_injection"]
    )

    # Get report
    report = scanner.get_report()
    severity_counts = report.get_severity_counts()

    logger.info("=" * 80)
    logger.info("COMPREHENSIVE SQL INJECTION SCAN COMPLETE")
    logger.info(f"Total tests performed: {report.total_tests}")
    logger.info(f"Total vulnerabilities: {report.get_vulnerability_count()}")
    logger.info(f"Critical: {severity_counts['critical']}")
    logger.info(f"High: {severity_counts['high']}")
    logger.info(f"Medium: {severity_counts['medium']}")
    logger.info("=" * 80)

    # Save detailed report
    scanner.save_report(
        output_dir="reports/security_real",
        formats=["json", "html", "markdown"],
    )
    logger.info("Detailed reports saved to reports/security_real/")

    # Assert results
    if report.has_critical_vulnerabilities():
        logger.critical("=" * 80)
        logger.critical("CRITICAL VULNERABILITIES DETECTED!")
        logger.critical(
            f"Found {severity_counts['critical']} critical vulnerabilities"
        )
        logger.critical("=" * 80)

        pytest.fail(
            f"DISCOVERED: {report.get_vulnerability_count()} vulnerabilities. "
            f"Critical: {severity_counts['critical']}, High: {severity_counts['high']}. "
            f"See detailed HTML report in reports/security_real/"
        )
    elif vulnerabilities:
        logger.warning(
            f"Found {len(vulnerabilities)} non-critical vulnerabilities"
        )
        logger.warning("See detailed report for analysis")
        pytest.fail(
            f"DISCOVERED: {len(vulnerabilities)} SQL injection vulnerabilities"
        )
    else:
        logger.info("✓ No SQL injection vulnerabilities detected")
        assert True
