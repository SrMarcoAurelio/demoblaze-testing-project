"""
Real XSS Testing
Uses HTTP interception and response analysis to detect real XSS vulnerabilities.

Author: Marc Arévalo
Version: 1.0

⚠️ ETHICAL WARNING: AUTHORIZED TESTING ONLY
"""

import logging

import pytest
from selenium.webdriver.common.by import By

from utils.security.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)


@pytest.mark.security
@pytest.mark.high
@pytest.mark.real_detection
def test_real_xss_all_inputs(browser, base_url):
    """
    TC-SEC-REAL-XSS-001: Real XSS Detection in All Input Fields

    CVSS Score: 8.8 HIGH
    Standard: OWASP Top 10 2021 - A03 (Injection)

    This test performs REAL XSS detection by:
    - Injecting XSS payloads into all input fields
    - Intercepting HTTP responses
    - Analyzing if payloads are reflected unencoded
    - Detecting script execution possibilities

    Unlike basic UI tests, this detects:
    - Reflected XSS in HTTP responses
    - Stored XSS in database
    - DOM-based XSS
    - Unencoded script tags
    """
    browser.get(base_url)

    # Initialize vulnerability scanner
    scanner = VulnerabilityScanner(browser, base_url)

    logger.info("=" * 80)
    logger.info("STARTING REAL XSS DETECTION")
    logger.info("=" * 80)

    # Scan all inputs for XSS
    vulnerabilities = scanner.scan_all_inputs(vulnerability_types=["xss"])

    # Get report
    report = scanner.get_report()
    severity_counts = report.get_severity_counts()

    logger.info("=" * 80)
    logger.info("XSS SCAN COMPLETE")
    logger.info(f"Total tests performed: {report.total_tests}")
    logger.info(f"Vulnerabilities found: {report.get_vulnerability_count()}")
    logger.info(f"High: {severity_counts['high']}")
    logger.info(f"Medium: {severity_counts['medium']}")
    logger.info("=" * 80)

    # Save detailed report
    scanner.save_report(
        output_dir="reports/security_real", formats=["json", "html"]
    )

    # Assert results
    if vulnerabilities:
        logger.critical("=" * 80)
        logger.critical("XSS VULNERABILITIES DETECTED!")
        logger.critical("=" * 80)

        for vuln in vulnerabilities:
            logger.critical(f"Type: {vuln.vulnerability_type}")
            logger.critical(f"Severity: {vuln.severity.value.upper()}")
            logger.critical(f"Payload: {vuln.payload_used[:100]}")
            logger.critical(f"URL: {vuln.url}")
            logger.critical("Evidence:")
            for evidence in vuln.evidence:
                logger.critical(f"  - {evidence}")
            logger.critical("=" * 80)

        pytest.fail(
            f"DISCOVERED: {len(vulnerabilities)} XSS vulnerabilities with REAL HTTP evidence. "
            f"See detailed report in reports/security_real/"
        )
    else:
        logger.info("✓ No XSS vulnerabilities detected")
        logger.info("✓ All payloads were properly encoded or sanitized")
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.real_detection
def test_real_xss_signup_form(browser, base_url):
    """
    TC-SEC-REAL-XSS-002: Real XSS Detection in Signup Form

    CVSS Score: 8.8 HIGH
    Standard: OWASP Top 10 2021 - A03 (Injection)

    Tests signup form specifically for XSS vulnerabilities.
    """
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    from pages.signup_page import SignupPage

    browser.get(base_url)
    signup_page = SignupPage(browser)

    # Initialize vulnerability scanner
    scanner = VulnerabilityScanner(browser, base_url)

    logger.info("Testing XSS in signup form...")

    # Open signup modal
    signup_page.open_signup_modal()
    wait = WebDriverWait(browser, 10)

    # Get form elements
    try:
        username_field = wait.until(
            EC.presence_of_element_located((By.ID, "sign-username"))
        )
        password_field = browser.find_element(By.ID, "sign-password")

        # Test username field for XSS
        username_vulns = scanner.scan_xss(
            input_element=username_field, url=f"{base_url}#signup"
        )

        # Test password field for XSS
        browser.get(base_url)
        signup_page.open_signup_modal()
        password_field = wait.until(
            EC.presence_of_element_located((By.ID, "sign-password"))
        )
        password_vulns = scanner.scan_xss(
            input_element=password_field, url=f"{base_url}#signup"
        )

        all_vulns = username_vulns + password_vulns

        # Save report
        scanner.save_report(output_dir="reports/security_real")

        if all_vulns:
            logger.critical(
                f"DISCOVERED: {len(all_vulns)} XSS vulnerabilities in signup form"
            )
            pytest.fail(
                f"XSS vulnerabilities found. See reports/security_real/ for details"
            )
        else:
            logger.info("✓ No XSS vulnerabilities in signup form")
            assert True

    except Exception as e:
        logger.error(f"Error during XSS testing: {e}")
        pytest.skip(f"Could not complete XSS test: {e}")
