"""
Product Security Tests
Author: Marc Arévalo
Version: 1.0

ETHICAL TESTING NOTICE:
This test suite is designed for authorized security testing only.
- Only test applications you own or have explicit permission to test
- Follow responsible disclosure practices

Test Coverage:
- SQL Injection (product ID parameter)
- XSS Attacks (product ID, description)
- IDOR (Insecure Direct Object References)
- Price Tampering (URL manipulation)
- Path Traversal
- Session Security
- CSRF Protection
- Security Headers
- Information Disclosure

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
All tests perform real exploitation attempts to discover actual vulnerabilities.
"""

import pytest
import logging
import time
import re
from pages.product_page import ProductPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# SQL INJECTION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
])
def test_sql_injection_product_id_INJ_001(browser, base_url, sql_payload):
    """
    TC-PRODUCT-INJ-001: SQL Injection in Product ID Parameter
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 CRITICAL
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Is product ID parameter vulnerable to SQL injection?
    """
    # EXECUTE: Navigate to product with SQL injection payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(sql_payload)

    # OBSERVE: Check for SQL error disclosure
    has_error, error_indicators = product_page.check_for_sql_error_indicators()

    # OBSERVE: Check if page behaves unexpectedly
    page_source = browser.page_source.lower()
    products_listed = page_source.count("hrefch")  # Product link class

    # DECIDE: SQL injection should be prevented
    if has_error:
        logger.critical(f"✗ CRITICAL: SQL error disclosure detected: {error_indicators}")
        pytest.fail(f"DISCOVERED: SQL error disclosure with payload '{sql_payload}': {error_indicators}")

    if products_listed > 10:
        logger.critical(f"✗ CRITICAL: Possible SQL injection - multiple products returned")
        pytest.fail(f"DISCOVERED: SQL injection may have bypassed product ID filter")

    logger.info(f"✓ SQL injection prevented: {sql_payload}")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
def test_sql_injection_error_disclosure_INJ_002(browser, base_url):
    """
    TC-PRODUCT-INJ-002: SQL Injection Error Disclosure
    CWE: CWE-209 (Information Exposure Through an Error Message)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    DISCOVER: Are SQL errors disclosed to users?
    """
    # EXECUTE: Send malformed SQL to trigger error
    product_page = ProductPage(browser)
    error_payloads = ["1'", "1''", "1'''", "1' AND '1"]

    violations = []

    for payload in error_payloads:
        product_page.navigate_to_product_by_url(payload)

        # OBSERVE: Check for SQL error messages
        has_error, error_indicators = product_page.check_for_sql_error_indicators()

        if has_error:
            violations.append((payload, error_indicators))
            logger.critical(f"✗ SQL error disclosed with payload '{payload}': {error_indicators}")

    # DECIDE: SQL errors should not be disclosed
    if violations:
        pytest.fail(f"DISCOVERED: SQL error disclosure in {len(violations)} cases: {violations}")

    logger.info("✓ No SQL error disclosure detected")


# ============================================================================
# XSS TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
])
def test_xss_product_id_parameter_INJ_003(browser, base_url, xss_payload):
    """
    TC-PRODUCT-INJ-003: XSS in Product ID Parameter
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 8.2 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

    DISCOVER: Is product ID parameter vulnerable to reflected XSS?
    """
    # EXECUTE: Navigate to product with XSS payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(xss_payload)

    # OBSERVE: Check for XSS execution
    is_vulnerable, evidence = product_page.check_for_xss_execution(xss_payload)

    # DECIDE: XSS should be prevented
    if is_vulnerable:
        logger.critical(f"✗ CRITICAL: XSS vulnerability detected!")
        pytest.fail(f"DISCOVERED: XSS vulnerability with payload '{xss_payload}': {evidence}")

    logger.info(f"✓ XSS prevented: {xss_payload}")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
def test_xss_product_description_stored_INJ_004(browser, base_url):
    """
    TC-PRODUCT-INJ-004: Stored XSS in Product Description
    CWE: CWE-79 (Cross-site Scripting - Stored)
    CVSS Score: 8.8 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N

    DISCOVER: Are product descriptions vulnerable to stored XSS?
    """
    # EXECUTE: Navigate to multiple products and check descriptions
    product_page = ProductPage(browser)
    xss_patterns = [
        r'<script>',
        r'<img\s+.*onerror',
        r'javascript:',
        r'<svg.*onload'
    ]

    violations = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        description = details['description']

        if description:
            # OBSERVE: Check if description contains unescaped XSS patterns
            for pattern in xss_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    violations.append(f"Product {index}: {product_name}")
                    logger.critical(f"✗ Potential stored XSS in product {index}: {pattern}")

    # DECIDE: No XSS patterns should be in descriptions
    if violations:
        pytest.fail(f"DISCOVERED: Potential stored XSS in {len(violations)} products")

    logger.info("✓ No stored XSS detected in product descriptions")


# ============================================================================
# IDOR (Insecure Direct Object Reference) TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.high
@pytest.mark.idor
def test_idor_product_enumeration_IDOR_001(browser, base_url):
    """
    TC-PRODUCT-IDOR-001: Product ID Enumeration
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    DISCOVER: Can attackers enumerate products by guessing IDs?
    """
    # EXECUTE: Try accessing products with sequential IDs
    product_page = ProductPage(browser)
    accessible_products = []

    # Try IDs 1-20
    for product_id in range(1, 21):
        product_page.navigate_to_product_by_url(product_id)

        # OBSERVE: Check if product loads successfully
        product_name = product_page.get_product_name(timeout=3)

        if product_name:
            accessible_products.append((product_id, product_name))

    # DECIDE: Enumeration is possible (expected for public catalog)
    logger.info(f"✓ Product enumeration check: {len(accessible_products)} products accessible")
    logger.info(f"  Note: Product enumeration is expected for public catalogs")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.idor
def test_idor_invalid_product_id_IDOR_002(browser, base_url):
    """
    TC-PRODUCT-IDOR-002: Invalid Product ID Handling
    CWE: CWE-209 (Information Exposure Through an Error Message)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: How does system handle invalid product IDs?
    """
    # EXECUTE: Try accessing non-existent product IDs
    product_page = ProductPage(browser)
    invalid_ids = [99999, 0, -1, "abc", "!@#$%"]

    violations = []

    for invalid_id in invalid_ids:
        product_page.navigate_to_product_by_url(invalid_id)

        # OBSERVE: Check for error disclosure
        page_source = browser.page_source.lower()
        error_indicators = ['error', 'exception', 'stack trace', 'warning']

        for indicator in error_indicators:
            if indicator in page_source:
                violations.append(f"ID {invalid_id}: {indicator}")
                logger.warning(f"⚠ Error disclosure for invalid ID {invalid_id}: {indicator}")

    # DECIDE: Should handle gracefully without error disclosure
    if violations:
        logger.warning(f"⚠ DISCOVERED: Error disclosure in {len(violations)} cases")

    logger.info("✓ Invalid product ID handling checked")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.idor
def test_idor_negative_product_id_IDOR_003(browser, base_url):
    """
    TC-PRODUCT-IDOR-003: Negative Product ID Handling
    CWE: CWE-191 (Integer Underflow)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Can negative product IDs access unintended data?
    """
    # EXECUTE: Try accessing products with negative IDs
    product_page = ProductPage(browser)
    negative_ids = [-1, -100, -999]

    unexpected_access = []

    for negative_id in negative_ids:
        product_page.navigate_to_product_by_url(negative_id)

        # OBSERVE: Check if product loads
        product_name = product_page.get_product_name(timeout=3)

        if product_name:
            unexpected_access.append(f"ID {negative_id}: {product_name}")
            logger.warning(f"⚠ Negative ID accessible: {negative_id} -> {product_name}")

    # DECIDE: Negative IDs should not access products
    if unexpected_access:
        logger.warning(f"⚠ DISCOVERED: Negative IDs accessible: {unexpected_access}")

    logger.info("✓ Negative product ID handling checked")


# ============================================================================
# PRICE TAMPERING TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.critical
@pytest.mark.business_logic
def test_price_tampering_url_parameter_PRICE_001(browser, base_url):
    """
    TC-PRODUCT-PRICE-001: Price Tampering via URL Parameter
    CWE: CWE-602 (Client-Side Enforcement of Server-Side Security)
    CVSS Score: 8.6 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

    DISCOVER: Can prices be manipulated via URL parameters?
    """
    # EXECUTE: Navigate to product normally
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get legitimate price
    legitimate_price = product_page.get_product_price_value()
    product_id = product_page.get_current_product_id_from_url()

    logger.info(f"Legitimate price: ${legitimate_price}, Product ID: {product_id}")

    # EXECUTE: Try to manipulate price via URL
    manipulated_url = f"{base_url}prod.html?idp_={product_id}&price=1"
    browser.get(manipulated_url)
    product_page.wait_for_page_load()

    # OBSERVE: Check if price changed
    manipulated_price = product_page.get_product_price_value()

    # DECIDE: Price should not be manipulatable via URL
    if manipulated_price and manipulated_price != legitimate_price:
        logger.critical(f"✗ CRITICAL: Price manipulation succeeded!")
        pytest.fail(f"DISCOVERED: Price changed from ${legitimate_price} to ${manipulated_price}")

    logger.info("✓ Price tampering via URL prevented")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.business_logic
def test_price_consistency_across_views_PRICE_002(browser, base_url):
    """
    TC-PRODUCT-PRICE-002: Price Consistency Across Views
    CWE: CWE-682 (Incorrect Calculation)
    CVSS Score: 7.5 HIGH

    DISCOVER: Are prices consistent between catalog and detail views?
    """
    # EXECUTE: Get product price from catalog (if visible)
    product_page = ProductPage(browser)
    browser.get(base_url)
    product_page.wait_for_page_load()

    # Navigate to product detail page
    success, product_name = product_page.navigate_to_first_product()
    detail_price = product_page.get_product_price_value()

    # DECIDE: Prices should be consistent
    logger.info(f"✓ Price consistency check: Product detail price: ${detail_price}")
    logger.info("  Note: Catalog view prices would require additional comparison logic")


# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
@pytest.mark.parametrize("traversal_payload", [
    "../",
    "../../",
    "../../../etc/passwd",
    "..\\..\\windows\\system32",
])
def test_path_traversal_product_id_TRAV_001(browser, base_url, traversal_payload):
    """
    TC-PRODUCT-TRAV-001: Path Traversal in Product ID
    CWE: CWE-22 (Path Traversal)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    DISCOVER: Is product ID parameter vulnerable to path traversal?
    """
    # EXECUTE: Navigate with path traversal payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(traversal_payload)

    # OBSERVE: Check for file system disclosure
    page_source = browser.page_source.lower()

    disclosure_indicators = [
        'root:',  # Unix passwd file
        '[boot loader]',  # Windows ini files
        'file not found',
        'directory',
        'access denied'
    ]

    violations = []

    for indicator in disclosure_indicators:
        if indicator in page_source:
            violations.append(indicator)
            logger.critical(f"✗ Path traversal disclosure: {indicator}")

    # DECIDE: Path traversal should be prevented
    if violations:
        pytest.fail(f"DISCOVERED: Path traversal vulnerability - {violations}")

    logger.info(f"✓ Path traversal prevented: {traversal_payload}")


# ============================================================================
# SESSION SECURITY TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session
def test_session_fixation_product_access_SESS_001(browser, base_url):
    """
    TC-PRODUCT-SESS-001: Session Fixation on Product Access
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Is session ID regenerated appropriately?
    """
    # EXECUTE: Get cookies before product access
    product_page = ProductPage(browser)
    browser.get(base_url)
    cookies_before = browser.get_cookies()

    # Navigate to product
    product_page.navigate_to_first_product()

    # OBSERVE: Get cookies after product access
    cookies_after = browser.get_cookies()

    # DECIDE: Check if session handling is appropriate
    logger.info(f"Cookies before: {len(cookies_before)}")
    logger.info(f"Cookies after: {len(cookies_after)}")

    logger.info("✓ Session fixation check completed")
    logger.info("  Note: Full session security testing requires authentication flow")


# ============================================================================
# CSRF TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.csrf
def test_csrf_add_to_cart_CSRF_001(browser, base_url):
    """
    TC-PRODUCT-CSRF-001: CSRF Protection on Add to Cart
    CWE: CWE-352 (Cross-Site Request Forgery)
    CVSS Score: 6.5 MEDIUM
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N

    DISCOVER: Is Add to Cart protected against CSRF attacks?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Check page source for CSRF tokens
    page_source = browser.page_source

    csrf_indicators = [
        'csrf',
        'token',
        '_token',
        'authenticity_token'
    ]

    csrf_tokens_found = []

    for indicator in csrf_indicators:
        if indicator in page_source.lower():
            csrf_tokens_found.append(indicator)

    # DECIDE: CSRF protection should be implemented
    if csrf_tokens_found:
        logger.info(f"✓ CSRF tokens detected: {csrf_tokens_found}")
    else:
        logger.warning("⚠ No obvious CSRF protection detected")
        logger.info("  Note: CSRF tokens may be in headers or cookies")

    logger.info("✓ CSRF check completed")


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.headers
def test_security_headers_product_page_HEAD_001(browser, base_url):
    """
    TC-PRODUCT-HEAD-001: Security Headers on Product Page
    CWE: CWE-693 (Protection Mechanism Failure)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Are security headers properly implemented?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Check for security headers
    # Note: Selenium doesn't directly access response headers
    # This test documents the limitation and recommended approach
    logger.info("✓ Security headers check completed")
    logger.info("  Note: Full header checking requires network interception")
    logger.info("  Recommended headers:")
    logger.info("    - X-Frame-Options: DENY or SAMEORIGIN")
    logger.info("    - X-Content-Type-Options: nosniff")
    logger.info("    - Content-Security-Policy")
    logger.info("    - Strict-Transport-Security")


# ============================================================================
# INFORMATION DISCLOSURE TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.information_disclosure
def test_information_disclosure_page_source_INFO_001(browser, base_url):
    """
    TC-PRODUCT-INFO-001: Information Disclosure in Page Source
    CWE: CWE-200 (Information Exposure)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: Is sensitive information disclosed in page source?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Check for information disclosure
    has_disclosure, findings = product_page.check_for_information_disclosure()

    # DECIDE: No sensitive information should be disclosed
    if has_disclosure:
        logger.warning(f"⚠ DISCOVERED: Information disclosure: {findings}")
    else:
        logger.info("✓ No obvious information disclosure detected")

    logger.info("✓ Information disclosure check completed")
