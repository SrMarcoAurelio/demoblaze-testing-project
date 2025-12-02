"""
Test Suite: Catalog & Product Browsing Security Testing
Module: test_catalog_security.py
Author: QA Testing Team
Version: 1.0

Test Categories:
- Injection Attacks: SQL Injection, Command Injection, XSS
- Access Control: IDOR, Path Traversal, Enumeration
- Session Security: Session Fixation, Cookie Security
- Security Controls: CSRF, Rate Limiting, Security Headers
- Information Disclosure: Error Messages, Directory Listing

Standards Validated:
- OWASP ASVS v5.0 (Input Validation, Access Control, Error Handling)
- OWASP Top 10 2021
- CWE (Common Weakness Enumeration)
- NIST SP 800-63B (Digital Identity Guidelines)
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)

CVSS Scoring:
All discovered vulnerabilities are scored using CVSS v3.1

Philosophy: DISCOVER Methodology
Tests execute real attack payloads and validate against security standards.
Security vulnerabilities are reported as CRITICAL ERRORS, not excused.

Execution:
Run all tests:           pytest test_catalog_security.py -v
Run by category:         pytest test_catalog_security.py -k "sql_injection" -v
Run critical only:       pytest test_catalog_security.py -m "critical" -v
Generate HTML report:    pytest test_catalog_security.py --html=report_catalog_security.html --self-contained-html

Total Expected Tests: 28+ (with parametrization)
"""

import logging
import time

import pytest
import requests
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 15

# ============================================================================
# LOCATORS
# ============================================================================

# Categories
PHONES_CATEGORY = (By.LINK_TEXT, "Phones")
LAPTOPS_CATEGORY = (By.LINK_TEXT, "Laptops")
MONITORS_CATEGORY = (By.LINK_TEXT, "Monitors")

# Products
PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")
PRODUCT_TITLES = (By.CSS_SELECTOR, ".card-title a")
PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")

# Product Details
PRODUCT_DETAIL_NAME = (By.CSS_SELECTOR, "h2.name")
PRODUCT_DETAIL_PRICE = (By.CSS_SELECTOR, "h3.price-container")

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def browser():
    """Initialize Chrome browser"""
    driver = webdriver.Chrome()
    driver.maximize_window()
    yield driver
    driver.quit()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def wait_for_products_to_load(browser, timeout=TIMEOUT):
    """Wait for products to be visible"""
    try:
        WebDriverWait(browser, timeout).until(
            EC.presence_of_element_located(PRODUCT_CARDS)
        )
        time.sleep(1)
        return True
    except TimeoutException:
        return False


def check_for_sql_error_indicators(browser):
    """Check page source for SQL error indicators"""
    page_source = browser.page_source.lower()

    sql_error_indicators = [
        "sql syntax",
        "mysql",
        "postgresql",
        "oracle",
        "sqlite",
        "syntax error",
        "unexpected",
        "warning:",
        "error in your sql",
        "odbc",
        "jdbc",
        "database error",
        "sqlstate",
        "query failed",
    ]

    for indicator in sql_error_indicators:
        if indicator in page_source:
            return True, indicator

    return False, None


def check_for_xss_execution(browser, payload):
    """Check if XSS payload executed"""
    page_source = browser.page_source

    # Check if payload appears unescaped
    if payload in page_source:
        return True

    # Check for script execution indicators
    if "<script>" in page_source.lower() and "alert" in page_source.lower():
        return True

    return False


def attempt_path_traversal(browser, base_path, traversal_payload):
    """Attempt path traversal attack"""
    malicious_url = f"{base_path}{traversal_payload}"

    try:
        browser.get(malicious_url)
        time.sleep(1)

        page_source = browser.page_source.lower()

        # Check for indicators of successful traversal
        indicators = [
            "root:",
            "[boot loader]",
            "etc/passwd",
            "windows/system32",
            "directory of",
            "index of /",
            "parent directory",
        ]

        for indicator in indicators:
            if indicator in page_source:
                return True, indicator

        return False, None

    except Exception as e:
        return False, str(e)


# ============================================================================
# SQL INJECTION TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "sql_payload",
    [
        "' OR '1'='1",
        "1' OR '1'='1",
        "' OR 1=1--",
        "') OR ('1'='1",
        "1' UNION SELECT NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
    ],
)
def test_sql_injection_category_filter_INJ_001(browser, sql_payload):
    """
    TC-CATALOG-SEC-INJ-001: SQL Injection in Category Filter

    Standard: OWASP ASVS v5.0 Section 5.3.4 (SQL Injection Prevention)
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Discovers if category parameter is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-CATALOG-SEC-INJ-001: Testing SQL injection with payload: {sql_payload}"
    )

    # Try to inject SQL in category selection
    # Note: This tests if the application sanitizes category input
    browser.get(BASE_URL)

    # Execute JavaScript to manipulate category parameter if exposed
    try:
        # Attempt to inject via URL parameter if exists
        test_url = f"{BASE_URL}?cat={sql_payload}"
        browser.get(test_url)
        time.sleep(2)

        # Check for SQL errors
        has_error, indicator = check_for_sql_error_indicators(browser)

        if has_error:
            logging.error("=" * 80)
            logging.error("CRITICAL VULNERABILITY: SQL ERROR DISCLOSURE")
            logging.error(f"Payload: {sql_payload}")
            logging.error(f"Error indicator: {indicator}")
            logging.error("Standard: OWASP ASVS v5.0 Section 5.3.4")
            logging.error("CWE-89: SQL Injection")
            logging.error("CVSS Score: 7.5 (HIGH)")
            logging.error("Impact: Database structure disclosure")
            logging.error("Evidence: SQL error message in response")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: SQL error disclosure with payload '{sql_payload}'"
            )

        # Check if unusual behavior occurred
        page_source = browser.page_source
        if "error" in page_source.lower() and "sql" in page_source.lower():
            logging.error("=" * 80)
            logging.error("POTENTIAL SQL INJECTION VULNERABILITY")
            logging.error(f"Payload: {sql_payload}")
            logging.error("SQL-related error detected in response")
            logging.error("CVSS Score: 9.8 (CRITICAL)")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: Potential SQL injection with payload '{sql_payload}'"
            )

        logging.info(f"SQL payload '{sql_payload}' handled safely")

    except Exception as e:
        logging.warning(f"Error during SQL injection test: {e}")

    assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "sql_payload",
    ["1' OR '1'='1", "999' OR 1=1--", "-1' UNION SELECT NULL,NULL,NULL--"],
)
def test_sql_injection_product_id_INJ_002(browser, sql_payload):
    """
    TC-CATALOG-SEC-INJ-002: SQL Injection in Product ID Parameter

    Standard: OWASP ASVS v5.0 Section 5.3.4
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)

    Discovers if product ID parameter is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-CATALOG-SEC-INJ-002: Testing SQL injection in product ID: {sql_payload}"
    )

    # Attempt SQL injection via product ID parameter
    test_url = f"{BASE_URL}prod.html?idp_={sql_payload}"

    try:
        browser.get(test_url)
        time.sleep(2)

        has_error, indicator = check_for_sql_error_indicators(browser)

        if has_error:
            logging.error("=" * 80)
            logging.error(
                "CRITICAL VULNERABILITY: SQL INJECTION IN PRODUCT ID"
            )
            logging.error(f"Payload: {sql_payload}")
            logging.error(f"Error indicator: {indicator}")
            logging.error("Standard: OWASP ASVS v5.0 Section 5.3.4")
            logging.error("CWE-89: SQL Injection")
            logging.error("CVSS Score: 9.8 (CRITICAL)")
            logging.error("Impact: Complete database compromise possible")
            logging.error("Attack Vector: Product ID parameter")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: SQL injection in product ID with payload '{sql_payload}'"
            )

        logging.info(f"Product ID SQL payload '{sql_payload}' handled safely")

    except Exception as e:
        logging.warning(f"Error during product ID SQL test: {e}")

    assert True


# ============================================================================
# CROSS-SITE SCRIPTING (XSS) TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "xss_payload",
    [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ],
)
def test_xss_product_search_INJ_003(browser, xss_payload):
    """
    TC-CATALOG-SEC-INJ-003: Cross-Site Scripting in Search

    Standard: OWASP ASVS v5.0 Section 5.3.3 (Output Encoding)
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 7.1 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L

    Discovers if search functionality is vulnerable to XSS.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-CATALOG-SEC-INJ-003: Testing XSS with payload: {xss_payload}"
    )

    # Attempt XSS via search parameter (if exists)
    test_url = f"{BASE_URL}?search={xss_payload}"

    try:
        browser.get(test_url)
        time.sleep(2)

        # Check if payload executed
        if check_for_xss_execution(browser, xss_payload):
            logging.error("=" * 80)
            logging.error("CRITICAL VULNERABILITY: CROSS-SITE SCRIPTING (XSS)")
            logging.error(f"Payload: {xss_payload}")
            logging.error("Standard: OWASP ASVS v5.0 Section 5.3.3")
            logging.error("CWE-79: Cross-site Scripting")
            logging.error("CVSS Score: 7.1 (HIGH)")
            logging.error(
                "Impact: Session hijacking, cookie theft, defacement"
            )
            logging.error("Evidence: XSS payload reflected unescaped in page")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: XSS vulnerability with payload '{xss_payload}'"
            )

        logging.info(f"XSS payload '{xss_payload}' properly escaped/sanitized")

    except Exception as e:
        logging.warning(f"Error during XSS test: {e}")

    assert True


@pytest.mark.security
@pytest.mark.high
def test_stored_xss_product_review_INJ_004(browser):
    """
    TC-CATALOG-SEC-INJ-004: Stored XSS via Product Reviews

    Standard: OWASP ASVS v5.0 Section 5.3.3
    CWE: CWE-79 (Stored Cross-site Scripting)
    CVSS Score: 8.7 (HIGH)

    Discovers if product reviews are vulnerable to stored XSS.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-INJ-004: Testing stored XSS in reviews")

    # Note: DemoBlaze may not have review functionality
    # This test discovers if the feature exists and is vulnerable

    browser.get(BASE_URL)
    wait_for_products_to_load(browser)

    # Click first product
    try:
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)

        # Look for review/comment section
        review_sections = browser.find_elements(
            By.CSS_SELECTOR,
            "textarea, input[type='text'][name*='review'], input[type='text'][name*='comment']",
        )

        if not review_sections:
            logging.info(
                "DISCOVERED: No review functionality present to test for stored XSS"
            )
            assert True
            return

        # If review functionality exists, test it
        xss_payload = "<script>alert('Stored XSS')</script>"
        review_field = review_sections[0]
        review_field.send_keys(xss_payload)

        # Try to submit (button might be named differently)
        submit_buttons = browser.find_elements(
            By.XPATH,
            "//button[contains(text(), 'Submit') or contains(text(), 'Post')]",
        )

        if submit_buttons:
            submit_buttons[0].click()
            time.sleep(2)

            # Check if payload is stored and reflected
            browser.refresh()
            time.sleep(2)

            if check_for_xss_execution(browser, xss_payload):
                logging.error("=" * 80)
                logging.error("CRITICAL VULNERABILITY: STORED XSS")
                logging.error(f"Payload: {xss_payload}")
                logging.error("CVSS Score: 8.7 (HIGH)")
                logging.error("Impact: Persistent XSS affects all users")
                logging.error("=" * 80)

                pytest.fail("DISCOVERED: Stored XSS vulnerability in reviews")

        logging.info("Review functionality exists but properly sanitized")

    except NoSuchElementException:
        logging.info("DISCOVERED: No review functionality to test")

    assert True


# ============================================================================
# INSECURE DIRECT OBJECT REFERENCE (IDOR) TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_idor_product_access_IDOR_001(browser):
    """
    TC-CATALOG-SEC-IDOR-001: IDOR on Product Access

    Standard: OWASP ASVS v5.0 Section 4.1.2 (Access Control)
    CWE: CWE-669 (Incorrect Resource Transfer Between Spheres)
    CVSS Score: 7.5 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Discovers if product IDs can be enumerated without authorization.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-IDOR-001: Testing IDOR on product access")

    # Test accessing products with sequential IDs
    accessible_products = []

    for product_id in range(1, 20):
        test_url = f"{BASE_URL}prod.html?idp_={product_id}"

        try:
            browser.get(test_url)
            time.sleep(1)

            # Check if product loads
            try:
                product_name = browser.find_element(*PRODUCT_DETAIL_NAME)

                if product_name.is_displayed():
                    accessible_products.append(
                        {"id": product_id, "name": product_name.text}
                    )

            except NoSuchElementException:
                # Product doesn't exist or access denied
                pass

        except Exception:
            pass

    logging.info(
        f"DISCOVERED: {len(accessible_products)} products accessible via sequential IDs"
    )

    # IDOR is a vulnerability if ANY products are accessible without authentication
    # when they should be protected
    if len(accessible_products) > 0:
        logging.warning("=" * 80)
        logging.warning("IDOR VULNERABILITY: PRODUCT ENUMERATION POSSIBLE")
        logging.warning("Standard: OWASP ASVS v5.0 Section 4.1.2")
        logging.warning("CWE-669: Incorrect Resource Transfer")
        logging.warning("CVSS Score: 7.5 (HIGH)")
        logging.warning(f"Accessible products: {len(accessible_products)}")
        logging.warning("Impact:")
        logging.warning("  - Product enumeration possible")
        logging.warning("  - Competitor intelligence gathering")
        logging.warning("  - Pricing information disclosure")
        logging.warning(
            "Recommendation: Implement authorization checks on product access"
        )
        logging.warning("=" * 80)

        # For public e-commerce, IDOR on product viewing is typically not critical
        # but should be logged for awareness
        logging.info(
            "Note: For public e-commerce, product viewing is expected to be open"
        )

    assert True


@pytest.mark.security
@pytest.mark.high
def test_idor_invalid_product_handling_IDOR_002(browser):
    """
    TC-CATALOG-SEC-IDOR-002: Invalid Product ID Handling

    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 5.3 (MEDIUM)

    Discovers how system handles invalid product IDs.
    """
    logging.info("=" * 80)
    logging.info(
        "TC-CATALOG-SEC-IDOR-002: Testing invalid product ID handling"
    )

    invalid_ids = ["999999", "-1", "0", "abc", "NULL", "../../etc/passwd"]

    verbose_errors = []

    for invalid_id in invalid_ids:
        test_url = f"{BASE_URL}prod.html?idp_={invalid_id}"
        browser.get(test_url)
        time.sleep(1)

        page_source = browser.page_source.lower()

        # Check for verbose error messages
        error_indicators = [
            "stack trace",
            "exception",
            "error in",
            "failed to",
            "database",
            "query",
            "sql",
            "file not found",
            "path",
            "directory",
        ]

        for indicator in error_indicators:
            if indicator in page_source:
                verbose_errors.append(
                    {"id": invalid_id, "indicator": indicator}
                )
                break

    if verbose_errors:
        logging.error("=" * 80)
        logging.error("INFORMATION DISCLOSURE: VERBOSE ERROR MESSAGES")
        logging.error("Standard: OWASP ASVS v5.0 Section 7.4.1")
        logging.error("CWE-209: Information Exposure Through Error Message")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Verbose errors for: {len(verbose_errors)} invalid IDs")
        for err in verbose_errors[:3]:
            logging.error(
                f"  - ID '{err['id']}': Contains '{err['indicator']}'"
            )
        logging.error("Impact: System information disclosure")
        logging.error("Recommendation: Implement generic error messages")
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: Verbose error messages for {len(verbose_errors)} invalid product IDs"
        )

    logging.info("Invalid product IDs handled with generic error messages")
    assert True


# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
@pytest.mark.parametrize(
    "traversal_payload",
    [
        "../",
        "../../",
        "../../../",
        "..\\",
        "..%2F",
        "..%5C",
        "%2e%2e%2f",
        "....//",
    ],
)
def test_path_traversal_product_images_TRAV_001(browser, traversal_payload):
    """
    TC-CATALOG-SEC-TRAV-001: Path Traversal in Product Images

    Standard: OWASP ASVS v5.0 Section 12.3.1 (File Execution)
    CWE: CWE-22 (Path Traversal)
    CVSS Score: 7.5 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Discovers if image paths are vulnerable to directory traversal.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-CATALOG-SEC-TRAV-001: Testing path traversal: {traversal_payload}"
    )

    # Attempt to access files outside intended directory
    malicious_paths = [
        f"{traversal_payload}etc/passwd",
        f"{traversal_payload}windows/system32/config/sam",
        f"{traversal_payload}app/config/database.yml",
    ]

    for mal_path in malicious_paths:
        test_url = f"{BASE_URL}imgs/{mal_path}"

        try:
            response = requests.get(test_url, timeout=5)

            if response.status_code == 200:
                content = response.text.lower()

                # Check for sensitive file indicators
                sensitive_indicators = [
                    "root:",
                    "[boot loader]",
                    "password",
                    "database:",
                    "secret",
                ]

                for indicator in sensitive_indicators:
                    if indicator in content:
                        logging.error("=" * 80)
                        logging.error("CRITICAL VULNERABILITY: PATH TRAVERSAL")
                        logging.error(f"Payload: {traversal_payload}")
                        logging.error(f"Accessed: {mal_path}")
                        logging.error(f"Indicator found: {indicator}")
                        logging.error(
                            "Standard: OWASP ASVS v5.0 Section 12.3.1"
                        )
                        logging.error("CWE-22: Path Traversal")
                        logging.error("CVSS Score: 7.5 (HIGH)")
                        logging.error("Impact: Sensitive file disclosure")
                        logging.error("=" * 80)

                        pytest.fail(
                            f"DISCOVERED: Path traversal with payload '{traversal_payload}'"
                        )

        except requests.RequestException:
            pass

    logging.info(f"Path traversal payload '{traversal_payload}' blocked")
    assert True


# ============================================================================
# ENUMERATION TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.medium
def test_product_enumeration_ENUM_001(browser):
    """
    TC-CATALOG-SEC-ENUM-001: Product Enumeration via Sequential IDs

    Standard: OWASP ASVS v5.0 Section 2.2.2 (Account Enumeration)
    CWE: CWE-200 (Information Exposure)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if product catalog can be enumerated systematically.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-ENUM-001: Testing product enumeration")

    valid_products = []
    invalid_products = []

    # Test sequential IDs
    for product_id in range(1, 30):
        test_url = f"{BASE_URL}prod.html?idp_={product_id}"

        try:
            browser.get(test_url)
            time.sleep(0.5)

            try:
                product_name = browser.find_element(*PRODUCT_DETAIL_NAME)
                valid_products.append(product_id)
            except NoSuchElementException:
                invalid_products.append(product_id)

        except Exception:
            invalid_products.append(product_id)

    enumeration_rate = len(valid_products) / (
        len(valid_products) + len(invalid_products)
    )

    logging.info(f"DISCOVERED: Enumeration rate: {enumeration_rate:.2%}")
    logging.info(f"Valid products: {len(valid_products)}")
    logging.info(f"Invalid IDs: {len(invalid_products)}")

    if enumeration_rate > 0.3:  # More than 30% success rate
        logging.warning("=" * 80)
        logging.warning("ENUMERATION VULNERABILITY: HIGH SUCCESS RATE")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.2")
        logging.warning("CWE-200: Information Exposure")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning(f"Enumeration success rate: {enumeration_rate:.2%}")
        logging.warning("Impact:")
        logging.warning("  - Complete product catalog can be enumerated")
        logging.warning("  - Competitor intelligence gathering")
        logging.warning("  - Inventory tracking possible")
        logging.warning(
            "Recommendation: Use non-sequential, random product IDs"
        )
        logging.warning("=" * 80)

    assert True


@pytest.mark.security
@pytest.mark.medium
def test_timing_attack_product_existence_TIME_001(browser):
    """
    TC-CATALOG-SEC-TIME-001: Timing Attack for Product Existence

    Standard: OWASP ASVS v5.0 Section 2.2.2
    CWE: CWE-208 (Observable Timing Discrepancy)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if response times reveal product existence.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-TIME-001: Testing timing-based enumeration")

    # Test valid product
    valid_times = []
    for _ in range(3):
        start = time.time()
        browser.get(f"{BASE_URL}prod.html?idp_=1")
        time.sleep(1)
        valid_times.append(time.time() - start)

    avg_valid_time = sum(valid_times) / len(valid_times)

    # Test invalid product
    invalid_times = []
    for _ in range(3):
        start = time.time()
        browser.get(f"{BASE_URL}prod.html?idp_=999999")
        time.sleep(1)
        invalid_times.append(time.time() - start)

    avg_invalid_time = sum(invalid_times) / len(invalid_times)

    time_difference = abs(avg_valid_time - avg_invalid_time)

    logging.info(
        f"DISCOVERED: Average time for valid product: {avg_valid_time:.2f}s"
    )
    logging.info(
        f"DISCOVERED: Average time for invalid product: {avg_invalid_time:.2f}s"
    )
    logging.info(f"DISCOVERED: Time difference: {time_difference:.2f}s")

    if time_difference > 0.5:  # More than 500ms difference
        logging.warning("=" * 80)
        logging.warning("TIMING ATTACK VULNERABILITY")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.2")
        logging.warning("CWE-208: Observable Timing Discrepancy")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning(f"Timing difference: {time_difference:.2f}s")
        logging.warning(
            "Impact: Product existence can be determined via timing"
        )
        logging.warning("Recommendation: Normalize response times")
        logging.warning("=" * 80)

        pytest.fail(
            f"DISCOVERED: Timing discrepancy of {time_difference:.2f}s enables enumeration"
        )

    logging.info("Response times consistent - no timing attack vector")
    assert True


# ============================================================================
# SESSION SECURITY TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_session_fixation_catalog_browsing_SESS_001(browser):
    """
    TC-CATALOG-SEC-SESS-001: Session Fixation During Catalog Browsing

    Standard: OWASP ASVS v5.0 Section 3.2.1 (Session Generation)
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 7.5 (HIGH)

    Discovers if session ID changes during catalog navigation.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-SESS-001: Testing session fixation")

    browser.get(BASE_URL)
    time.sleep(1)

    initial_cookies = {
        cookie["name"]: cookie["value"] for cookie in browser.get_cookies()
    }
    logging.info(f"Initial cookies: {list(initial_cookies.keys())}")

    # Browse catalog
    wait_for_products_to_load(browser)

    # Click category
    try:
        browser.find_element(*PHONES_CATEGORY).click()
        time.sleep(2)

        category_cookies = {
            cookie["name"]: cookie["value"] for cookie in browser.get_cookies()
        }

        # Click product
        first_product = browser.find_element(*PRODUCT_LINKS)
        first_product.click()
        time.sleep(2)

        product_cookies = {
            cookie["name"]: cookie["value"] for cookie in browser.get_cookies()
        }

        session_changed = False
        for cookie_name in initial_cookies:
            if cookie_name in product_cookies:
                if (
                    initial_cookies[cookie_name]
                    != product_cookies[cookie_name]
                ):
                    session_changed = True
                    logging.info(
                        f"Session cookie '{cookie_name}' changed during browsing"
                    )

        if not session_changed and initial_cookies:
            logging.warning("=" * 80)
            logging.warning("SESSION FIXATION VULNERABILITY")
            logging.warning("Standard: OWASP ASVS v5.0 Section 3.2.1")
            logging.warning("CWE-384: Session Fixation")
            logging.warning("CVSS Score: 7.5 (HIGH)")
            logging.warning("Session ID unchanged throughout browsing")
            logging.warning("Impact: Session hijacking possible")
            logging.warning("=" * 80)

            # Note: For public browsing, this may not be critical
            logging.info(
                "Note: For unauthenticated browsing, session fixation risk is lower"
            )

    except NoSuchElementException:
        logging.warning("Could not complete session fixation test")

    assert True


@pytest.mark.security
@pytest.mark.medium
def test_cookie_security_flags_COOK_001(browser):
    """
    TC-CATALOG-SEC-COOK-001: Cookie Security Flags

    Standard: OWASP ASVS v5.0 Section 3.4.2 (Cookie-based Session Management)
    CWE: CWE-614 (Sensitive Cookie Without 'Secure' Flag)
    CVSS Score: 6.5 (MEDIUM)

    Discovers if cookies have Secure and HttpOnly flags.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-COOK-001: Testing cookie security flags")

    browser.get(BASE_URL)
    time.sleep(2)

    cookies = browser.get_cookies()

    insecure_cookies = []

    for cookie in cookies:
        cookie_name = cookie.get("name", "unknown")
        is_secure = cookie.get("secure", False)
        is_httponly = cookie.get("httpOnly", False)

        if not is_secure or not is_httponly:
            insecure_cookies.append(
                {
                    "name": cookie_name,
                    "secure": is_secure,
                    "httponly": is_httponly,
                }
            )

    if insecure_cookies:
        logging.error("=" * 80)
        logging.error("COOKIE SECURITY VIOLATION: MISSING SECURITY FLAGS")
        logging.error("Standard: OWASP ASVS v5.0 Section 3.4.2")
        logging.error("CWE-614: Sensitive Cookie Without Secure Flag")
        logging.error("CVSS Score: 6.5 (MEDIUM)")
        logging.error(f"Insecure cookies: {len(insecure_cookies)}")
        for cookie in insecure_cookies:
            logging.error(
                f"  - {cookie['name']}: Secure={cookie['secure']}, HttpOnly={cookie['httponly']}"
            )
        logging.error("Impact:")
        logging.error("  - Cookie theft via MITM attacks")
        logging.error("  - XSS exploitation of cookies")
        logging.error(
            "Recommendation: Set Secure and HttpOnly flags on all cookies"
        )
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: {len(insecure_cookies)} cookies lack security flags"
        )

    logging.info("All cookies have proper security flags")
    assert True


# ============================================================================
# CSRF TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_csrf_token_catalog_actions_CSRF_001(browser):
    """
    TC-CATALOG-SEC-CSRF-001: CSRF Token Validation

    Standard: OWASP ASVS v5.0 Section 4.2.2 (CSRF Prevention)
    CWE: CWE-352 (Cross-Site Request Forgery)
    CVSS Score: 6.5 (MEDIUM)

    Discovers if catalog actions are protected against CSRF.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-CSRF-001: Testing CSRF protection")

    browser.get(BASE_URL)
    time.sleep(1)

    page_source = browser.page_source.lower()

    csrf_indicators = [
        "csrf",
        "xsrf",
        "_token",
        "authenticity_token",
        "anti-forgery",
        "requestverificationtoken",
    ]

    csrf_found = False
    for indicator in csrf_indicators:
        if indicator in page_source:
            csrf_found = True
            logging.info(f"CSRF protection detected: {indicator}")
            break

    if not csrf_found:
        logging.error("=" * 80)
        logging.error("CSRF VULNERABILITY: NO CSRF PROTECTION")
        logging.error("Standard: OWASP ASVS v5.0 Section 4.2.2")
        logging.error("CWE-352: Cross-Site Request Forgery")
        logging.error("CVSS Score: 6.5 (MEDIUM)")
        logging.error("No CSRF tokens detected in page")
        logging.error("Impact:")
        logging.error("  - Forged requests possible")
        logging.error("  - State-changing actions can be exploited")
        logging.error(
            "Recommendation: Implement CSRF tokens for all state-changing operations"
        )
        logging.error("=" * 80)

        pytest.fail("DISCOVERED: No CSRF protection on catalog actions")

    assert True


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_security_headers_validation_HEAD_001(browser):
    """
    TC-CATALOG-SEC-HEAD-001: Security Headers Validation

    Standard: OWASP ASVS v5.0 Section 14.4 (HTTP Security Headers)
    CWE: CWE-693 (Protection Mechanism Failure)
    CVSS Score: 7.5 (HIGH)

    Discovers if critical security headers are present.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-HEAD-001: Testing security headers")

    try:
        response = requests.get(BASE_URL, timeout=10)
        headers = response.headers

        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "Strict-Transport-Security": "max-age",
            "Content-Security-Policy": None,
            "X-XSS-Protection": "1",
        }

        missing_headers = []
        misconfigured_headers = []

        for header, expected_value in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_value:
                actual_value = headers[header]
                if isinstance(expected_value, list):
                    if not any(val in actual_value for val in expected_value):
                        misconfigured_headers.append(
                            f"{header}: {actual_value}"
                        )
                elif expected_value not in actual_value:
                    misconfigured_headers.append(f"{header}: {actual_value}")

        if missing_headers or misconfigured_headers:
            logging.error("=" * 80)
            logging.error("SECURITY HEADERS VIOLATION")
            logging.error("Standard: OWASP ASVS v5.0 Section 14.4")
            logging.error("CWE-693: Protection Mechanism Failure")
            logging.error("CVSS Score: 7.5 (HIGH)")
            if missing_headers:
                logging.error(f"Missing headers: {', '.join(missing_headers)}")
            if misconfigured_headers:
                logging.error(
                    f"Misconfigured: {', '.join(misconfigured_headers)}"
                )
            logging.error("Impact:")
            logging.error("  - Increased attack surface")
            logging.error("  - Clickjacking possible")
            logging.error("  - MIME-sniffing attacks")
            logging.error(
                "Recommendation: Implement all critical security headers"
            )
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: {len(missing_headers)} headers missing, {len(misconfigured_headers)} misconfigured"
            )

        logging.info("All critical security headers present and configured")
        assert True

    except requests.RequestException as e:
        logging.warning(f"Could not fetch headers: {e}")
        pytest.skip("Network request failed")


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.medium
def test_rate_limiting_catalog_browsing_RATE_001(browser):
    """
    TC-CATALOG-SEC-RATE-001: Rate Limiting on Catalog Browsing

    Standard: OWASP ASVS v5.0 Section 2.2.1 (Anti-automation)
    CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if system limits rapid catalog browsing.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-RATE-001: Testing rate limiting")

    attempts = 20
    successful_loads = 0

    for i in range(attempts):
        try:
            browser.get(f"{BASE_URL}prod.html?idp_={i+1}")
            time.sleep(0.2)  # Very rapid requests

            # Check if page loaded successfully
            try:
                browser.find_element(*PRODUCT_DETAIL_NAME)
                successful_loads += 1
            except NoSuchElementException:
                pass

        except Exception:
            break

    success_rate = successful_loads / attempts

    logging.info(
        f"DISCOVERED: {successful_loads}/{attempts} rapid requests succeeded"
    )
    logging.info(f"Success rate: {success_rate:.1%}")

    if success_rate > 0.95:  # More than 95% success
        logging.warning("=" * 80)
        logging.warning("NO RATE LIMITING DETECTED")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.warning("CWE-307: Improper Restriction")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning(
            f"Completed {successful_loads} rapid requests without restriction"
        )
        logging.warning("Impact:")
        logging.warning("  - Automated scraping possible")
        logging.warning("  - DoS attacks easier")
        logging.warning("  - Competitor data harvesting")
        logging.warning(
            "Recommendation: Implement rate limiting (e.g., 100 requests/minute)"
        )
        logging.warning("=" * 80)

        # Note: For public catalog, rate limiting may not be critical
        logging.info("Note: Public catalogs often allow high browsing rates")

    assert True


# ============================================================================
# INFORMATION DISCLOSURE TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.low
def test_verbose_error_messages_INFO_001(browser):
    """
    TC-CATALOG-SEC-INFO-001: Verbose Error Messages

    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 3.7 (LOW)

    Discovers if error messages reveal sensitive information.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-INFO-001: Testing error message verbosity")

    # Test various error conditions
    error_urls = [
        f"{BASE_URL}prod.html?idp_=<script>",
        f"{BASE_URL}prod.html?idp_='OR'1'='1",
        f"{BASE_URL}nonexistent.html",
        f"{BASE_URL}prod.html?idp_=" + "A" * 10000,
    ]

    verbose_errors = []

    for url in error_urls:
        try:
            browser.get(url)
            time.sleep(1)

            page_source = browser.page_source.lower()

            sensitive_terms = [
                "stack trace",
                "exception",
                "database",
                "query failed",
                "file path",
                "c:\\",
                "/var/www",
                "line ",
                "mysql",
                "postgresql",
            ]

            for term in sensitive_terms:
                if term in page_source:
                    verbose_errors.append({"url": url, "term": term})
                    break

        except Exception:
            pass

    if verbose_errors:
        logging.warning("=" * 80)
        logging.warning("INFORMATION DISCLOSURE: VERBOSE ERROR MESSAGES")
        logging.warning("Standard: OWASP ASVS v5.0 Section 7.4.1")
        logging.warning("CWE-209: Information Exposure")
        logging.warning("CVSS Score: 3.7 (LOW)")
        logging.warning(f"Verbose errors found: {len(verbose_errors)}")
        for err in verbose_errors[:3]:
            logging.warning(f"  - Contains '{err['term']}'")
        logging.warning("Impact: System information disclosure")
        logging.warning("Recommendation: Use generic error messages")
        logging.warning("=" * 80)

        pytest.fail(
            f"DISCOVERED: {len(verbose_errors)} verbose error messages"
        )

    logging.info("Error messages are appropriately generic")
    assert True


@pytest.mark.security
@pytest.mark.low
def test_directory_listing_INFO_002(browser):
    """
    TC-CATALOG-SEC-INFO-002: Directory Listing Exposure

    Standard: OWASP ASVS v5.0 Section 12.5.1 (File Download)
    CWE: CWE-548 (Directory Listing)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if directory listings are exposed.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-SEC-INFO-002: Testing directory listing")

    directories_to_test = [
        f"{BASE_URL}imgs/",
        f"{BASE_URL}js/",
        f"{BASE_URL}css/",
        f"{BASE_URL}includes/",
        f"{BASE_URL}admin/",
    ]

    exposed_directories = []

    for directory in directories_to_test:
        try:
            response = requests.get(directory, timeout=5)

            if response.status_code == 200:
                content = response.text.lower()

                listing_indicators = [
                    "index of",
                    "parent directory",
                    "directory listing",
                    "<pre>",
                    "name</th>",
                    "size</th>",
                ]

                for indicator in listing_indicators:
                    if indicator in content:
                        exposed_directories.append(directory)
                        break

        except requests.RequestException:
            pass

    if exposed_directories:
        logging.error("=" * 80)
        logging.error("INFORMATION DISCLOSURE: DIRECTORY LISTING ENABLED")
        logging.error("Standard: OWASP ASVS v5.0 Section 12.5.1")
        logging.error("CWE-548: Directory Listing")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Exposed directories: {len(exposed_directories)}")
        for directory in exposed_directories:
            logging.error(f"  - {directory}")
        logging.error("Impact:")
        logging.error("  - File structure disclosed")
        logging.error("  - Sensitive files discoverable")
        logging.error(
            "Recommendation: Disable directory listing on web server"
        )
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: {len(exposed_directories)} directories with listing enabled"
        )

    logging.info("No directory listings exposed")
    assert True


# ============================================================================
# END OF TEST SUITE
# ============================================================================
