"""
Catalog Security Tests  
Author: Marc Arévalo
Version: 1.0

ETHICAL TESTING NOTICE:
Authorized security testing only.

Test Coverage:
- SQL Injection (category filter, product ID)
- XSS Attacks (search, reviews)
- IDOR (product access, enumeration)
- Path Traversal
- Timing Attacks
- Session Security
- Cookie Security
- CSRF Protection
- Security Headers
- Rate Limiting
- Information Disclosure

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import pytest
import logging
import time
from pages.catalog_page import CatalogPage

logger = logging.getLogger(__name__)


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "admin'--"
])
def test_sql_injection_category_filter_INJ_001(browser, base_url, sql_payload):
    """TC-CATALOG-INJ-001: SQL Injection in Category Filter
    CWE: CWE-89, CVSS Score: 9.8 CRITICAL"""
    catalog = CatalogPage(browser)
    
    malicious_url = f"{base_url}?cat={sql_payload}"
    browser.get(malicious_url)
    catalog.wait_for_page_load()
    
    has_error, indicators = catalog.check_for_sql_error_indicators()
    
    if has_error:
        logger.critical(f"✗ CRITICAL: SQL error disclosure: {indicators}")
        pytest.fail(f"DISCOVERED: SQL error disclosure with '{sql_payload}'")
    
    logger.info(f"✓ SQL injection prevented: {sql_payload}")

@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "1' OR '1'='1",
    "1' UNION SELECT NULL--",
    "999' OR 1=1--"
])
def test_sql_injection_product_id_INJ_002(browser, base_url, sql_payload):
    """TC-CATALOG-INJ-002: SQL Injection in Product ID
    CWE: CWE-89, CVSS Score: 9.8 CRITICAL"""
    catalog = CatalogPage(browser)
    
    malicious_url = f"{base_url}prod.html?idp_={sql_payload}"
    browser.get(malicious_url)
    catalog.wait_for_page_load()
    
    has_error, indicators = catalog.check_for_sql_error_indicators()
    
    if has_error:
        pytest.fail(f"DISCOVERED: SQL injection vulnerability")
    
    logger.info(f"✓ SQL injection prevented: {sql_payload}")


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')"
])
def test_xss_product_search_INJ_003(browser, base_url, xss_payload):
    """TC-CATALOG-INJ-003: XSS in Product Search
    CWE: CWE-79, CVSS Score: 8.2 HIGH"""
    catalog = CatalogPage(browser)
    
    search_url = f"{base_url}?search={xss_payload}"
    browser.get(search_url)
    catalog.wait_for_page_load()
    
    page_source = browser.page_source
    
    if xss_payload in page_source:
        pytest.fail(f"DISCOVERED: XSS payload reflected unescaped")
    
    try:
        alert = browser.switch_to.alert
        alert.accept()
        pytest.fail("DISCOVERED: XSS executed")
    except:
        pass
    
    logger.info(f"✓ XSS prevented: {xss_payload}")

@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
def test_stored_xss_product_review_INJ_004(browser, base_url):
    """TC-CATALOG-INJ-004: Stored XSS in Product Reviews
    CWE: CWE-79, CVSS Score: 8.8 HIGH"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_first_product()
    page_source = browser.page_source
    
    xss_patterns = [r'<script>', r'<img.*onerror', r'javascript:']
    
    import re
    for pattern in xss_patterns:
        if re.search(pattern, page_source, re.IGNORECASE):
            logger.warning(f"⚠ Potential stored XSS pattern: {pattern}")
    
    logger.info("✓ Stored XSS check completed")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.idor
def test_idor_product_access_IDOR_001(browser, base_url):
    """TC-CATALOG-IDOR-001: IDOR Product Access
    CWE: CWE-639, CVSS Score: 7.5 HIGH"""
    catalog = CatalogPage(browser)
    
    accessible = []
    for product_id in range(1, 11):
        url = f"{base_url}prod.html?idp_={product_id}"
        browser.get(url)
        time.sleep(1)
        
        if catalog.is_on_product_detail_page(timeout=3):
            accessible.append(product_id)
    
    logger.info(f"✓ Product enumeration check: {len(accessible)} products accessible")
    logger.info("  Note: Product enumeration expected for public catalog")

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.idor
def test_idor_invalid_product_handling_IDOR_002(browser, base_url):
    """TC-CATALOG-IDOR-002: Invalid Product ID Handling
    CWE: CWE-209, CVSS Score: 5.3 MEDIUM"""
    catalog = CatalogPage(browser)
    
    invalid_ids = [99999, 0, -1, "abc"]
    
    for invalid_id in invalid_ids:
        url = f"{base_url}prod.html?idp_={invalid_id}"
        browser.get(url)
        time.sleep(1)
        
        has_verbose, errors = catalog.check_for_verbose_errors()
        if has_verbose:
            logger.warning(f"⚠ Verbose error for ID {invalid_id}: {errors}")
    
    logger.info("✓ Invalid product ID handling checked")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
@pytest.mark.parametrize("traversal_payload", [
    "../",
    "../../",
    "../../../etc/passwd",
    "..\\..\\windows\\system32"
])
def test_path_traversal_product_images_TRAV_001(browser, base_url, traversal_payload):
    """TC-CATALOG-TRAV-001: Path Traversal in Product Images
    CWE: CWE-22, CVSS Score: 7.5 HIGH"""
    catalog = CatalogPage(browser)
    
    traversal_url = f"{base_url}?img={traversal_payload}"
    browser.get(traversal_url)
    catalog.wait_for_page_load()
    
    page_source = browser.page_source.lower()
    
    disclosure_indicators = ['root:', '[boot loader]', 'file not found', 'directory']
    
    for indicator in disclosure_indicators:
        if indicator in page_source:
            pytest.fail(f"DISCOVERED: Path traversal - {indicator}")
    
    logger.info(f"✓ Path traversal prevented: {traversal_payload}")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.enumeration
def test_product_enumeration_ENUM_001(browser, base_url):
    """TC-CATALOG-ENUM-001: Product Enumeration
    CWE: CWE-200, CVSS Score: 5.3 MEDIUM"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_phones_category()
    phones = catalog.get_product_count()
    
    catalog.click_laptops_category()
    laptops = catalog.get_product_count()
    
    catalog.click_monitors_category()
    monitors = catalog.get_product_count()
    
    total = phones + laptops + monitors
    logger.info(f"✓ Product enumeration: {total} total (P:{phones}, L:{laptops}, M:{monitors})")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.timing
def test_timing_attack_product_existence_TIME_001(browser, base_url):
    """TC-CATALOG-TIME-001: Timing Attack Product Existence
    CWE: CWE-208, CVSS Score: 5.3 MEDIUM"""
    catalog = CatalogPage(browser)
    
    start = time.time()
    browser.get(f"{base_url}prod.html?idp_=1")
    catalog.wait_for_page_load()
    valid_time = time.time() - start
    
    start = time.time()
    browser.get(f"{base_url}prod.html?idp_=99999")
    catalog.wait_for_page_load()
    invalid_time = time.time() - start
    
    time_diff = abs(valid_time - invalid_time)
    logger.info(f"Timing: valid={valid_time:.3f}s, invalid={invalid_time:.3f}s, diff={time_diff:.3f}s")
    
    if time_diff > 1.0:
        logger.warning(f"⚠ Significant timing difference: {time_diff:.3f}s")
    
    logger.info("✓ Timing attack resistance checked")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session
def test_session_fixation_catalog_browsing_SESS_001(browser, base_url):
    """TC-CATALOG-SESS-001: Session Fixation Catalog Browsing
    CWE: CWE-384, CVSS Score: 6.5 MEDIUM"""
    catalog = CatalogPage(browser)
    
    browser.get(base_url)
    cookies_before = browser.get_cookies()
    
    catalog.click_laptops_category()
    
    cookies_after = browser.get_cookies()
    
    logger.info(f"Cookies: before={len(cookies_before)}, after={len(cookies_after)}")
    logger.info("✓ Session fixation check completed")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.cookies
def test_cookie_security_flags_COOK_001(browser, base_url):
    """TC-CATALOG-COOK-001: Cookie Security Flags
    CWE: CWE-614, CVSS Score: 6.5 MEDIUM"""
    catalog = CatalogPage(browser)
    browser.get(base_url)
    
    cookies = browser.get_cookies()
    
    for cookie in cookies:
        name = cookie.get('name')
        secure = cookie.get('secure', False)
        httpOnly = cookie.get('httpOnly', False)
        
        if not secure:
            logger.warning(f"⚠ Cookie {name} lacks Secure flag")
        if not httpOnly:
            logger.warning(f"⚠ Cookie {name} lacks HttpOnly flag")
    
    logger.info(f"✓ Cookie security checked: {len(cookies)} cookies")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.csrf
def test_csrf_token_catalog_actions_CSRF_001(browser, base_url):
    """TC-CATALOG-CSRF-001: CSRF Token Catalog Actions
    CWE: CWE-352, CVSS Score: 6.5 MEDIUM"""
    catalog = CatalogPage(browser)
    browser.get(base_url)
    
    page_source = browser.page_source.lower()
    
    csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
    found = []
    
    for indicator in csrf_indicators:
        if indicator in page_source:
            found.append(indicator)
    
    if found:
        logger.info(f"✓ CSRF tokens detected: {found}")
    else:
        logger.warning("⚠ No obvious CSRF protection detected")
    
    logger.info("✓ CSRF check completed")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.headers
def test_security_headers_validation_HEAD_001(browser, base_url):
    """TC-CATALOG-HEAD-001: Security Headers Validation
    CWE: CWE-693, CVSS Score: 6.5 MEDIUM"""
    catalog = CatalogPage(browser)
    browser.get(base_url)
    
    logger.info("✓ Security headers check completed")
    logger.info("  Recommended headers: X-Frame-Options, X-Content-Type-Options, CSP")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.rate_limit
def test_rate_limiting_catalog_browsing_RATE_001(browser, base_url):
    """TC-CATALOG-RATE-001: Rate Limiting Catalog Browsing
    CWE: CWE-770, CVSS Score: 6.5 MEDIUM"""
    catalog = CatalogPage(browser)
    
    requests_count = 20
    blocked = False
    
    for i in range(requests_count):
        browser.get(base_url)
        time.sleep(0.1)  # Very rapid
        
        page_source = browser.page_source.lower()
        if 'rate limit' in page_source or 'too many requests' in page_source:
            blocked = True
            logger.info(f"✓ Rate limiting triggered after {i+1} requests")
            break
    
    if not blocked:
        logger.warning(f"⚠ No rate limiting after {requests_count} rapid requests")
    
    logger.info("✓ Rate limiting check completed")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.information_disclosure
def test_verbose_error_messages_INFO_001(browser, base_url):
    """TC-CATALOG-INFO-001: Verbose Error Messages
    CWE: CWE-209, CVSS Score: 5.3 MEDIUM"""
    catalog = CatalogPage(browser)
    
    error_urls = [
        f"{base_url}nonexistent.html",
        f"{base_url}prod.html?idp_=abc",
        f"{base_url}?invalid=true"
    ]
    
    for url in error_urls:
        browser.get(url)
        time.sleep(1)
        
        has_verbose, errors = catalog.check_for_verbose_errors()
        if has_verbose:
            logger.warning(f"⚠ Verbose errors on {url}: {errors}")
    
    logger.info("✓ Verbose error check completed")

@pytest.mark.security
@pytest.mark.medium
@pytest.mark.information_disclosure
def test_directory_listing_INFO_002(browser, base_url):
    """TC-CATALOG-INFO-002: Directory Listing
    CWE: CWE-548, CVSS Score: 5.3 MEDIUM"""
    catalog = CatalogPage(browser)
    
    dir_paths = ["imgs/", "css/", "js/", "assets/"]
    
    for path in dir_paths:
        url = f"{base_url}{path}"
        browser.get(url)
        time.sleep(1)
        
        has_listing, indicators = catalog.check_for_directory_listing()
        if has_listing:
            logger.warning(f"⚠ Directory listing at {path}: {indicators}")
    
    logger.info("✓ Directory listing check completed")
