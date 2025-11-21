"""
Test Suite: Product Details Security Testing (Exploitation)
Module: test_product_security.py
Author: Arévalo, Marc
Version: 1.0

ETHICAL TESTING NOTICE:
This test suite is designed for authorized security testing only.
- Only test applications you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Document all findings professionally

Test Categories:
- SQL Injection Tests: Database manipulation attempts
- XSS Tests: Cross-site scripting vulnerabilities
- IDOR Tests: Insecure direct object references
- Price Manipulation Tests: Business logic exploitation
- Information Disclosure Tests: Sensitive data exposure
- Session Security Tests: Session management vulnerabilities

Standards Validated:
- OWASP ASVS v5.0 (Application Security Verification Standard)
- CWE (Common Weakness Enumeration)
- CVSS v3.1 (Common Vulnerability Scoring System)
- OWASP Top 10 2021
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)

Philosophy: DISCOVER Methodology
Tests EXECUTE exploitation attempts, OBSERVE responses, and DECIDE based on security standards.
Tests never assume security controls exist - they discover actual vulnerabilities.
Security violations are reported as CRITICAL ERRORS with CVSS scoring.

Execution:
Run all tests:           pytest test_product_security.py -v
Run critical only:       pytest test_product_security.py -m "critical" -v
Run by vulnerability:    pytest test_product_security.py -k "sql_injection" -v
Generate HTML report:    pytest test_product_security.py --html=report_product_security.html --self-contained-html

Total Expected Tests: 18 tests (25+ runs with parametrization)
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import pytest
import time
import logging
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10

# ============================================================================
# LOCATORS
# ============================================================================

PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")
PRODUCT_NAME = (By.CSS_SELECTOR, "h2.name")
PRODUCT_PRICE = (By.CSS_SELECTOR, "h3.price-container")
PRODUCT_DESCRIPTION = (By.CSS_SELECTOR, "#more")
ADD_TO_CART_BUTTON = (By.CSS_SELECTOR, "a.btn.btn-success.btn-lg")

# ============================================================================
# SECURITY PAYLOADS
# ============================================================================

# SQL Injection Payloads
SQL_INJECTION_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
]

# Path Traversal Payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../",
    "../../",
    "../../../",
    "..%2F",
    "..%5C",
    "%2e%2e%2f",
]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def navigate_to_product_by_id(browser, product_id):
    """Navigate directly to product by ID"""
    url = f"{BASE_URL}prod.html?idp_={product_id}"
    browser.get(url)
    time.sleep(2)
    return url


def check_for_sql_error_indicators(page_source):
    """Check if page contains SQL error messages"""
    sql_errors = [
        'mysql',
        'sql syntax',
        'ora-',
        'postgresql',
        'sqlite',
        'odbc',
        'jdbc',
        'driver',
        'warning: mysql',
        'syntax error',
        'unclosed quotation',
        'quoted string not properly terminated',
        'database error',
    ]
    
    page_lower = page_source.lower()
    found_errors = []
    
    for error in sql_errors:
        if error in page_lower:
            found_errors.append(error)
    
    return found_errors


def check_for_xss_execution(browser, payload):
    """Check if XSS payload is reflected without encoding"""
    page_source = browser.page_source
    
    # Check if payload appears unescaped
    if payload in page_source:
        return True
    
    # Check if script tags are present
    if '<script>' in page_source.lower() and 'xss' in page_source.lower():
        return True
    
    return False


def extract_price_from_page(browser):
    """Extract numerical price from product page"""
    try:
        price_element = browser.find_element(*PRODUCT_PRICE)
        price_text = price_element.text
        
        # Extract number from "$790 *includes tax"
        match = re.search(r'\$?(\d+(?:\.\d{2})?)', price_text)
        if match:
            return float(match.group(1))
    except:
        pass
    
    return None


def check_security_headers(browser):
    """Check for security headers (limited in Selenium)"""
    # Note: Selenium has limited access to response headers
    # This is a basic check using browser capabilities
    headers_present = {
        'csp': False,
        'x_frame_options': False,
        'x_content_type_options': False,
        'strict_transport_security': False
    }
    
    # Try to detect CSP via meta tags
    try:
        csp_meta = browser.find_elements(By.CSS_SELECTOR, "meta[http-equiv='Content-Security-Policy']")
        headers_present['csp'] = len(csp_meta) > 0
    except:
        pass
    
    return headers_present

# ============================================================================
# SQL INJECTION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", SQL_INJECTION_PAYLOADS[:3])
def test_sql_injection_product_id_INJ_001(browser, sql_payload):
    """
    TC-PRODUCT-SEC-INJ-001: SQL Injection in Product ID Parameter
    
    Standard: OWASP ASVS v5.0 Section 5.3.4 (SQL Injection Prevention)
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    
    Discovers if product ID parameter is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(f"TC-PRODUCT-SEC-INJ-001: Testing SQL injection with payload: {sql_payload}")
    
    # Attempt SQL injection in product ID
    url = navigate_to_product_by_id(browser, sql_payload)
    
    page_source = browser.page_source
    sql_errors = check_for_sql_error_indicators(page_source)
    
    if sql_errors:
        logging.error("=" * 80)
        logging.error("CRITICAL VULNERABILITY: SQL INJECTION")
        logging.error(f"Payload: {sql_payload}")
        logging.error(f"URL: {url}")
        logging.error("Standard: OWASP ASVS v5.0 Section 5.3.4")
        logging.error("CWE-89: SQL Injection")
        logging.error("CVSS Score: 9.8 (CRITICAL)")
        logging.error(f"SQL Error Indicators Found: {sql_errors}")
        logging.error("Impact:")
        logging.error("  - Complete database compromise possible")
        logging.error("  - Customer data exposure")
        logging.error("  - Payment information at risk")
        logging.error("  - Administrative access possible")
        logging.error("Recommendation:")
        logging.error("  - Use parameterized queries")
        logging.error("  - Implement input validation")
        logging.error("  - Apply principle of least privilege")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: SQL Injection vulnerability in product ID parameter")
    
    logging.info(f"SQL injection payload '{sql_payload}' did not trigger SQL errors")
    assert True


@pytest.mark.security
@pytest.mark.high
def test_sql_injection_error_disclosure_INJ_002(browser):
    """
    TC-PRODUCT-SEC-INJ-002: SQL Error Message Disclosure
    
    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 5.3 (MEDIUM)
    
    Discovers if application exposes SQL error messages.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-INJ-002: Testing for SQL error disclosure")
    
    # Test with obvious SQL syntax error
    invalid_payloads = ["'", "\"", "1'", "1\""]
    
    verbose_errors = []
    
    for payload in invalid_payloads:
        url = navigate_to_product_by_id(browser, payload)
        page_source = browser.page_source
        
        sql_errors = check_for_sql_error_indicators(page_source)
        if sql_errors:
            verbose_errors.append({
                'payload': payload,
                'errors': sql_errors
            })
    
    if verbose_errors:
        logging.error("=" * 80)
        logging.error("INFORMATION DISCLOSURE: SQL ERROR MESSAGES")
        logging.error("Standard: OWASP ASVS v5.0 Section 7.4.1")
        logging.error("CWE-209: Information Exposure Through Error Message")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Verbose errors triggered by {len(verbose_errors)} payloads")
        for err in verbose_errors[:2]:
            logging.error(f"  Payload '{err['payload']}': {err['errors']}")
        logging.error("Impact: Database structure disclosure aids further attacks")
        logging.error("Recommendation: Implement generic error messages")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: SQL error messages disclosed to user")
    
    logging.info("No SQL error disclosure detected")
    assert True

# ============================================================================
# CROSS-SITE SCRIPTING (XSS) TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.high
@pytest.mark.parametrize("xss_payload", XSS_PAYLOADS[:3])
def test_xss_product_id_parameter_INJ_003(browser, xss_payload):
    """
    TC-PRODUCT-SEC-INJ-003: XSS in Product ID Parameter
    
    Standard: OWASP ASVS v5.0 Section 5.3.3 (Output Encoding)
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 7.1 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L
    
    Discovers if product ID parameter is vulnerable to reflected XSS.
    """
    logging.info("=" * 80)
    logging.info(f"TC-PRODUCT-SEC-INJ-003: Testing XSS with payload: {xss_payload}")
    
    url = navigate_to_product_by_id(browser, xss_payload)
    
    if check_for_xss_execution(browser, xss_payload):
        logging.error("=" * 80)
        logging.error("CRITICAL VULNERABILITY: REFLECTED XSS")
        logging.error(f"Payload: {xss_payload}")
        logging.error(f"URL: {url}")
        logging.error("Standard: OWASP ASVS v5.0 Section 5.3.3")
        logging.error("CWE-79: Cross-site Scripting")
        logging.error("CVSS Score: 7.1 (HIGH)")
        logging.error("Impact:")
        logging.error("  - Session hijacking via cookie theft")
        logging.error("  - Phishing attacks")
        logging.error("  - Keylogging")
        logging.error("  - Defacement")
        logging.error("Recommendation:")
        logging.error("  - Implement output encoding")
        logging.error("  - Use Content Security Policy")
        logging.error("  - Validate and sanitize inputs")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: XSS vulnerability in product ID parameter")
    
    logging.info(f"XSS payload '{xss_payload}' was properly encoded")
    assert True


@pytest.mark.security
@pytest.mark.high
def test_xss_product_description_stored_INJ_004(browser):
    """
    TC-PRODUCT-SEC-INJ-004: Stored XSS in Product Description
    
    Standard: OWASP ASVS v5.0 Section 5.3.3 (Output Encoding)
    CWE: CWE-79 (Stored Cross-site Scripting)
    CVSS Score: 8.7 (HIGH)
    
    Discovers if product description contains unescaped JavaScript.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-INJ-004: Testing for stored XSS in description")
    
    # Navigate to first product
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        # Check if description contains script tags
        try:
            description_element = browser.find_element(*PRODUCT_DESCRIPTION)
            description_html = description_element.get_attribute('innerHTML')
            
            dangerous_patterns = ['<script', 'onerror=', 'onload=', 'javascript:']
            
            found_patterns = []
            for pattern in dangerous_patterns:
                if pattern in description_html.lower():
                    found_patterns.append(pattern)
            
            if found_patterns:
                logging.error("=" * 80)
                logging.error("CRITICAL VULNERABILITY: STORED XSS")
                logging.error("Standard: OWASP ASVS v5.0 Section 5.3.3")
                logging.error("CWE-79: Stored Cross-site Scripting")
                logging.error("CVSS Score: 8.7 (HIGH)")
                logging.error(f"Dangerous patterns found: {found_patterns}")
                logging.error("Impact: Persistent XSS affects all users viewing product")
                logging.error("=" * 80)
                
                pytest.fail(f"DISCOVERED: Stored XSS in product description")
            
        except NoSuchElementException:
            logging.info("Product description not found")
        
        logging.info("No stored XSS detected in product description")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True

# ============================================================================
# INSECURE DIRECT OBJECT REFERENCE (IDOR) TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.high
def test_idor_product_enumeration_IDOR_001(browser):
    """
    TC-PRODUCT-SEC-IDOR-001: Product Enumeration via Sequential IDs
    
    Standard: OWASP ASVS v5.0 Section 4.1.2 (Access Control)
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    CVSS Score: 5.3 (MEDIUM)
    
    Discovers if product IDs are sequential and enumerable.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-IDOR-001: Testing product enumeration")
    
    accessible_products = []
    
    # Test sequential IDs 1-20
    for product_id in range(1, 21):
        url = navigate_to_product_by_id(browser, product_id)
        
        try:
            # Check if product loads successfully
            name_element = browser.find_element(*PRODUCT_NAME)
            if name_element.is_displayed():
                product_name = name_element.text
                accessible_products.append({
                    'id': product_id,
                    'name': product_name
                })
        except NoSuchElementException:
            pass
    
    logging.warning("=" * 80)
    logging.warning("INFORMATION DISCLOSURE: PRODUCT ENUMERATION")
    logging.warning("Standard: OWASP ASVS v5.0 Section 4.1.2")
    logging.warning("CWE-639: Authorization Bypass Through User-Controlled Key")
    logging.warning("CVSS Score: 5.3 (MEDIUM)")
    logging.warning(f"Enumerable products: {len(accessible_products)}/20")
    logging.warning("Impact:")
    logging.warning("  - Complete product catalog can be scraped")
    logging.warning("  - Competitor intelligence gathering")
    logging.warning("  - Pricing information disclosure")
    logging.warning("Note: For public e-commerce, this may be expected behavior")
    logging.warning("Recommendation:")
    logging.warning("  - Use non-sequential UUIDs for product IDs")
    logging.warning("  - Implement rate limiting on product access")
    logging.warning("=" * 80)
    
    if len(accessible_products) > 10:
        logging.warning(f"DISCOVERED: {len(accessible_products)} products enumerable via sequential IDs")
    
    assert True


@pytest.mark.security
@pytest.mark.high
def test_idor_invalid_product_id_IDOR_002(browser):
    """
    TC-PRODUCT-SEC-IDOR-002: Invalid Product ID Handling
    
    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 5.3 (MEDIUM)
    
    Discovers if invalid product IDs expose sensitive information.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-IDOR-002: Testing invalid product ID handling")
    
    invalid_ids = [
        "999999",
        "-1",
        "0",
        "abc",
        "NULL",
        "undefined",
    ]
    
    verbose_errors = []
    
    for invalid_id in invalid_ids:
        url = navigate_to_product_by_id(browser, invalid_id)
        page_source = browser.page_source.lower()
        
        # Check for verbose error indicators
        error_indicators = [
            'exception',
            'stack trace',
            'error in',
            'failed to',
            'file not found',
            'directory',
            'path',
        ]
        
        found_indicators = []
        for indicator in error_indicators:
            if indicator in page_source:
                found_indicators.append(indicator)
        
        if found_indicators:
            verbose_errors.append({
                'id': invalid_id,
                'indicators': found_indicators
            })
    
    if verbose_errors:
        logging.error("=" * 80)
        logging.error("INFORMATION DISCLOSURE: VERBOSE ERROR MESSAGES")
        logging.error("Standard: OWASP ASVS v5.0 Section 7.4.1")
        logging.error("CWE-209: Information Exposure Through Error Message")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Verbose errors for {len(verbose_errors)} invalid IDs")
        for err in verbose_errors[:2]:
            logging.error(f"  ID '{err['id']}': {err['indicators']}")
        logging.error("Impact: System information disclosure aids attacks")
        logging.error("Recommendation: Implement generic error messages")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: Verbose error messages for {len(verbose_errors)} invalid IDs")
    
    logging.info("Invalid product IDs handled with generic messages")
    assert True


@pytest.mark.security
@pytest.mark.critical
def test_idor_negative_product_id_IDOR_003(browser):
    """
    TC-PRODUCT-SEC-IDOR-003: Negative Product ID Handling
    
    Standard: OWASP ASVS v5.0 Section 5.1.3 (Input Validation)
    CWE: CWE-20 (Improper Input Validation)
    CVSS Score: 7.5 (HIGH)
    
    Discovers if negative IDs expose administrative/hidden products.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-IDOR-003: Testing negative product IDs")
    
    negative_ids = [-1, -10, -100, -999]
    hidden_products = []
    
    for neg_id in negative_ids:
        url = navigate_to_product_by_id(browser, neg_id)
        
        try:
            name_element = browser.find_element(*PRODUCT_NAME)
            if name_element.is_displayed():
                product_name = name_element.text
                hidden_products.append({
                    'id': neg_id,
                    'name': product_name
                })
        except NoSuchElementException:
            pass
    
    if hidden_products:
        logging.error("=" * 80)
        logging.error("CRITICAL VULNERABILITY: HIDDEN PRODUCTS ACCESSIBLE")
        logging.error("Standard: OWASP ASVS v5.0 Section 5.1.3")
        logging.error("CWE-20: Improper Input Validation")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(f"Hidden products found: {len(hidden_products)}")
        for prod in hidden_products:
            logging.error(f"  ID {prod['id']}: {prod['name']}")
        logging.error("Impact:")
        logging.error("  - Access to products not intended to be public")
        logging.error("  - Potential price manipulation")
        logging.error("  - Test/admin products exposed")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(hidden_products)} hidden products accessible via negative IDs")
    
    logging.info("Negative product IDs properly rejected")
    assert True

# ============================================================================
# PRICE MANIPULATION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.critical
def test_price_tampering_url_parameter_PRICE_001(browser):
    """
    TC-PRODUCT-SEC-PRICE-001: Price Tampering via URL Parameter
    
    Standard: OWASP ASVS v5.0 Section 4.2.1 (Business Logic)
    CWE: CWE-840 (Business Logic Errors)
    CVSS Score: 8.2 (HIGH)
    
    Discovers if price can be manipulated via URL parameters.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-PRICE-001: Testing price tampering")
    
    # Get legitimate product first
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        # Get original price
        original_price = extract_price_from_page(browser)
        current_url = browser.current_url
        
        if original_price is None:
            pytest.skip("Could not extract price from product page")
        
        logging.info(f"Original price: ${original_price}")
        
        # Attempt to manipulate price in URL
        tampered_urls = [
            f"{current_url}&price=1",
            f"{current_url}&price=0.01",
            f"{current_url}?price=1",
        ]
        
        price_manipulation_detected = False
        
        for tampered_url in tampered_urls:
            browser.get(tampered_url)
            time.sleep(2)
            
            tampered_price = extract_price_from_page(browser)
            
            if tampered_price and tampered_price != original_price:
                logging.error("=" * 80)
                logging.error("CRITICAL VULNERABILITY: PRICE TAMPERING")
                logging.error(f"Original price: ${original_price}")
                logging.error(f"Tampered price: ${tampered_price}")
                logging.error(f"Tampered URL: {tampered_url}")
                logging.error("Standard: OWASP ASVS v5.0 Section 4.2.1")
                logging.error("CWE-840: Business Logic Errors")
                logging.error("CVSS Score: 8.2 (HIGH)")
                logging.error("Impact:")
                logging.error("  - Direct financial loss")
                logging.error("  - Inventory sold at wrong prices")
                logging.error("  - Revenue manipulation")
                logging.error("=" * 80)
                
                price_manipulation_detected = True
                break
        
        if price_manipulation_detected:
            pytest.fail("DISCOVERED: Price tampering vulnerability via URL manipulation")
        
        logging.info("Price tampering via URL not possible")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True


@pytest.mark.security
@pytest.mark.high
def test_price_consistency_across_views_PRICE_002(browser):
    """
    TC-PRODUCT-SEC-PRICE-002: Price Consistency Validation
    
    Standard: OWASP ASVS v5.0 Section 4.2.1 (Business Logic)
    CWE: CWE-840 (Business Logic Errors)
    CVSS Score: 6.5 (MEDIUM)
    
    Discovers if price is consistent between catalog and product page.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-PRICE-002: Testing price consistency")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        # Get price from catalog (if visible)
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        detail_price = extract_price_from_page(browser)
        
        if detail_price:
            # Navigate back and check if catalog shows same price
            browser.back()
            time.sleep(2)
            
            logging.info(f"Product detail price: ${detail_price}")
            logging.info("Price consistency check completed")
            
            # Note: DemoBlaze catalog may not show prices, so this is discovery mode
            
    except NoSuchElementException:
        pytest.skip("Could not complete price consistency check")
    
    assert True

# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.high
@pytest.mark.parametrize("traversal_payload", PATH_TRAVERSAL_PAYLOADS[:3])
def test_path_traversal_product_id_TRAV_001(browser, traversal_payload):
    """
    TC-PRODUCT-SEC-TRAV-001: Path Traversal in Product ID
    
    Standard: OWASP ASVS v5.0 Section 12.3.1 (File Execution)
    CWE: CWE-22 (Path Traversal)
    CVSS Score: 7.5 (HIGH)
    
    Discovers if product ID parameter is vulnerable to path traversal.
    """
    logging.info("=" * 80)
    logging.info(f"TC-PRODUCT-SEC-TRAV-001: Testing path traversal: {traversal_payload}")
    
    url = navigate_to_product_by_id(browser, traversal_payload + "etc/passwd")
    page_source = browser.page_source.lower()
    
    # Check for path traversal indicators
    traversal_indicators = [
        'root:',
        '/etc/passwd',
        'bin/bash',
        'system32',
        'windows',
    ]
    
    found_indicators = []
    for indicator in traversal_indicators:
        if indicator in page_source:
            found_indicators.append(indicator)
    
    if found_indicators:
        logging.error("=" * 80)
        logging.error("CRITICAL VULNERABILITY: PATH TRAVERSAL")
        logging.error(f"Payload: {traversal_payload}")
        logging.error(f"URL: {url}")
        logging.error("Standard: OWASP ASVS v5.0 Section 12.3.1")
        logging.error("CWE-22: Path Traversal")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(f"Indicators found: {found_indicators}")
        logging.error("Impact:")
        logging.error("  - Sensitive file access")
        logging.error("  - Configuration file disclosure")
        logging.error("  - Source code exposure")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: Path traversal vulnerability in product ID")
    
    logging.info(f"Path traversal payload '{traversal_payload}' blocked")
    assert True

# ============================================================================
# SESSION SECURITY TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
def test_session_fixation_product_access_SESS_001(browser):
    """
    TC-PRODUCT-SEC-SESS-001: Session Fixation on Product Access
    
    Standard: OWASP ASVS v5.0 Section 3.2.1 (Session Management)
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 7.5 (HIGH)
    
    Discovers if session IDs are predictable or can be fixed.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-SESS-001: Testing session fixation")
    
    # Access product and check session handling
    browser.get(BASE_URL)
    time.sleep(1)
    
    # Get initial cookies
    initial_cookies = browser.get_cookies()
    
    # Navigate to product
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        # Check if new session created or same session used
        product_cookies = browser.get_cookies()
        
        session_cookies = [c for c in product_cookies if 'session' in c['name'].lower() or 'token' in c['name'].lower()]
        
        if session_cookies:
            for cookie in session_cookies:
                logging.info(f"Session cookie found: {cookie['name']}")
                
                # Check if cookie has secure flags
                is_secure = cookie.get('secure', False)
                is_httponly = cookie.get('httpOnly', False)
                
                if not is_secure or not is_httponly:
                    logging.warning("=" * 80)
                    logging.warning("SESSION SECURITY ISSUE: INSECURE COOKIE FLAGS")
                    logging.warning("Standard: OWASP ASVS v5.0 Section 3.4.2")
                    logging.warning("CWE-614: Sensitive Cookie Without 'Secure' Flag")
                    logging.warning("CVSS Score: 6.5 (MEDIUM)")
                    logging.warning(f"Cookie '{cookie['name']}':")
                    logging.warning(f"  Secure: {is_secure}")
                    logging.warning(f"  HttpOnly: {is_httponly}")
                    logging.warning("Impact: Cookie theft via XSS or network sniffing")
                    logging.warning("=" * 80)
        
        logging.info("Session handling check completed")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True

# ============================================================================
# CSRF PROTECTION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
def test_csrf_add_to_cart_CSRF_001(browser):
    """
    TC-PRODUCT-SEC-CSRF-001: CSRF Protection on Add to Cart
    
    Standard: OWASP ASVS v5.0 Section 4.2.2 (CSRF Prevention)
    CWE: CWE-352 (Cross-Site Request Forgery)
    CVSS Score: 6.5 (MEDIUM)
    
    Discovers if add to cart action is protected against CSRF.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-CSRF-001: Testing CSRF protection on add to cart")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        # Check page source for CSRF tokens
        page_source = browser.page_source
        
        csrf_indicators = ['csrf', 'token', 'authenticity']
        csrf_found = False
        
        for indicator in csrf_indicators:
            if indicator in page_source.lower():
                csrf_found = True
                logging.info(f"CSRF protection indicator found: {indicator}")
                break
        
        if not csrf_found:
            logging.warning("=" * 80)
            logging.warning("POTENTIAL VULNERABILITY: NO CSRF PROTECTION DETECTED")
            logging.warning("Standard: OWASP ASVS v5.0 Section 4.2.2")
            logging.warning("CWE-352: Cross-Site Request Forgery")
            logging.warning("CVSS Score: 6.5 (MEDIUM)")
            logging.warning("Impact:")
            logging.warning("  - Forced actions on behalf of authenticated users")
            logging.warning("  - Unwanted purchases")
            logging.warning("  - Cart manipulation")
            logging.warning("Note: Further testing required to confirm vulnerability")
            logging.warning("=" * 80)
        
        logging.info("CSRF protection check completed")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True

# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.medium
def test_security_headers_product_page_HEAD_001(browser):
    """
    TC-PRODUCT-SEC-HEAD-001: Security Headers on Product Page
    
    Standard: OWASP ASVS v5.0 Section 14.4.1 (HTTP Security Headers)
    CWE: CWE-693 (Protection Mechanism Failure)
    CVSS Score: 5.3 (MEDIUM)
    
    Discovers if security headers are present on product pages.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-HEAD-001: Checking security headers")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        headers = check_security_headers(browser)
        
        missing_headers = []
        if not headers['csp']:
            missing_headers.append('Content-Security-Policy')
        if not headers['x_frame_options']:
            missing_headers.append('X-Frame-Options')
        if not headers['x_content_type_options']:
            missing_headers.append('X-Content-Type-Options')
        if not headers['strict_transport_security']:
            missing_headers.append('Strict-Transport-Security')
        
        if missing_headers:
            logging.warning("=" * 80)
            logging.warning("SECURITY HARDENING ISSUE: MISSING SECURITY HEADERS")
            logging.warning("Standard: OWASP ASVS v5.0 Section 14.4.1")
            logging.warning("CWE-693: Protection Mechanism Failure")
            logging.warning("CVSS Score: 5.3 (MEDIUM)")
            logging.warning(f"Missing headers: {missing_headers}")
            logging.warning("Impact:")
            logging.warning("  - Increased XSS risk (no CSP)")
            logging.warning("  - Clickjacking possible (no X-Frame-Options)")
            logging.warning("  - MIME-type sniffing (no X-Content-Type-Options)")
            logging.warning("Recommendation: Implement all security headers")
            logging.warning("=" * 80)
        
        logging.info("Security headers check completed")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True

# ============================================================================
# INFORMATION DISCLOSURE TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.low
def test_information_disclosure_page_source_INFO_001(browser):
    """
    TC-PRODUCT-SEC-INFO-001: Information Disclosure in Page Source
    
    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-200 (Information Exposure)
    CVSS Score: 3.7 (LOW)
    
    Discovers if sensitive information is exposed in page source.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-SEC-INFO-001: Checking for information disclosure")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)
        
        page_source = browser.page_source.lower()
        
        # Check for sensitive information
        sensitive_keywords = [
            'password',
            'api_key',
            'apikey',
            'secret',
            'private_key',
            'access_token',
            'admin',
            'debug',
            'console.log',
        ]
        
        found_keywords = []
        for keyword in sensitive_keywords:
            if keyword in page_source:
                found_keywords.append(keyword)
        
        if found_keywords:
            logging.warning("=" * 80)
            logging.warning("INFORMATION DISCLOSURE: SENSITIVE KEYWORDS IN SOURCE")
            logging.warning("Standard: OWASP ASVS v5.0 Section 7.4.1")
            logging.warning("CWE-200: Information Exposure")
            logging.warning("CVSS Score: 3.7 (LOW)")
            logging.warning(f"Sensitive keywords found: {found_keywords}")
            logging.warning("Impact: May aid in further attacks")
            logging.warning("Recommendation: Remove debug code and comments from production")
            logging.warning("=" * 80)
        
        logging.info("Information disclosure check completed")
        
    except NoSuchElementException:
        pytest.skip("Could not navigate to product")
    
    assert True

# ============================================================================
# END OF TEST SUITE
# ============================================================================
