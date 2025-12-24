"""
WCAG 2.1 Accessibility Tests - DemoBlaze
Author: Marc Arévalo
Version: 1.0 - Phase 9

Tests for WCAG 2.1 Level AA compliance using axe-core.
"""

import logging

import pytest

from utils.accessibility.axe_helper import AxeHelper

logger = logging.getLogger(__name__)


@pytest.mark.accessibility
@pytest.mark.critical
def test_homepage_wcag_aa_compliance(browser, base_url):
    """
    A11Y-001: Homepage WCAG 2.1 Level AA Compliance

    Objective: Verify homepage meets WCAG 2.1 AA standards
    Standard: WCAG 2.1 Level AA
    """
    browser.get(base_url)
    axe = AxeHelper(browser)

    results = axe.run_wcag_aa()
    summary = axe.get_summary(results)

    logger.info(f"Homepage A11y Summary: {summary}")

    # Save report
    axe.save_report(results, "results/accessibility/homepage_wcag_aa.json")

    # Allow minor issues, but no critical/serious
    axe.assert_no_violations(results, allow_minor=True)


@pytest.mark.accessibility
@pytest.mark.high
def test_login_modal_accessibility(login_page):
    """
    A11Y-002: Login Modal Accessibility

    Objective: Verify login modal is accessible
    Focus: Keyboard navigation, screen readers, form labels
    """
    login_page.open_login_modal()
    axe = AxeHelper(login_page.driver)

    results = axe.run_wcag_aa()
    summary = axe.get_summary(results)

    logger.info(f"Login Modal A11y: {summary}")
    axe.save_report(results, "results/accessibility/login_modal_wcag_aa.json")

    axe.assert_no_violations(results, allow_minor=True)


@pytest.mark.accessibility
@pytest.mark.high
def test_catalog_page_accessibility(catalog_page):
    """
    A11Y-003: Catalog Page Accessibility

    Objective: Verify product catalog is accessible
    Focus: Images alt text, links, headings structure
    """
    axe = AxeHelper(catalog_page.driver)

    results = axe.run_wcag_aa()
    summary = axe.get_summary(results)

    logger.info(f"Catalog A11y: {summary}")
    axe.save_report(results, "results/accessibility/catalog_wcag_aa.json")

    axe.assert_no_violations(results, allow_minor=True)


@pytest.mark.accessibility
@pytest.mark.medium
def test_product_page_accessibility(catalog_page, product_phone):
    """
    A11Y-004: Product Page Accessibility

    Objective: Verify product details page is accessible
    Focus: Images, buttons, content structure
    """
    from pages.product_page import ProductPage

    catalog_page.select_product(product_phone)
    product_page = ProductPage(catalog_page.driver)

    axe = AxeHelper(product_page.driver)
    results = axe.run_wcag_aa()
    summary = axe.get_summary(results)

    logger.info(f"Product Page A11y: {summary}")
    axe.save_report(results, "results/accessibility/product_wcag_aa.json")

    axe.assert_no_violations(results, allow_minor=True)


@pytest.mark.accessibility
@pytest.mark.medium
def test_cart_page_accessibility(logged_in_user):
    """
    A11Y-005: Cart Page Accessibility

    Objective: Verify shopping cart is accessible
    Focus: Tables, buttons, form elements
    """
    from pages.cart_page import CartPage

    cart_page = CartPage(logged_in_user.driver)
    cart_page.go_to_cart()

    axe = AxeHelper(cart_page.driver)
    results = axe.run_wcag_aa()
    summary = axe.get_summary(results)

    logger.info(f"Cart Page A11y: {summary}")
    axe.save_report(results, "results/accessibility/cart_wcag_aa.json")

    axe.assert_no_violations(results, allow_minor=True)


@pytest.mark.accessibility
@pytest.mark.low
def test_full_accessibility_scan(browser, base_url):
    """
    A11Y-006: Full Accessibility Scan

    Objective: Run complete accessibility audit
    Includes: All rules (not just WCAG AA)
    """
    browser.get(base_url)
    axe = AxeHelper(browser)

    results = axe.run_full()
    summary = axe.get_summary(results)

    logger.info(f"Full A11y Scan: {summary}")
    axe.save_report(
        results, "results/accessibility/full_scan.json", include_passes=True
    )

    # Just log, don't fail (informational test)
    violations = axe.get_violations(results)
    if violations:
        logger.warning(f"Full scan found {len(violations)} total violations")
        logger.warning(
            axe.format_violations_summary(violations[:5])
        )  # First 5


@pytest.mark.accessibility
@pytest.mark.medium
def test_color_contrast_compliance(browser, base_url):
    """
    A11Y-007: Color Contrast Compliance

    Objective: Verify sufficient color contrast (WCAG AA)
    Standard: 4.5:1 for normal text, 3:1 for large text
    """
    browser.get(base_url)
    axe = AxeHelper(browser)

    # Run with specific focus on color contrast
    results = axe.run_wcag_aa()

    # Filter for color-contrast violations
    violations = axe.get_violations(results)
    contrast_violations = [
        v for v in violations if "color-contrast" in v.get("id", "")
    ]

    if contrast_violations:
        logger.warning(
            f"Color contrast violations: {len(contrast_violations)}"
        )
        logger.warning(axe.format_violations_summary(contrast_violations))

    assert (
        len(contrast_violations) == 0
    ), f"Found {len(contrast_violations)} color contrast violations"


@pytest.mark.accessibility
@pytest.mark.medium
def test_keyboard_navigation_accessibility(browser, base_url):
    """
    A11Y-008: Keyboard Navigation

    Objective: Verify all interactive elements are keyboard accessible
    Focus: Tab order, focus indicators, no keyboard traps
    """
    browser.get(base_url)
    axe = AxeHelper(browser)

    results = axe.run_wcag_aa()

    # Focus on keyboard-related rules
    violations = axe.get_violations(results)
    keyboard_violations = [
        v
        for v in violations
        if any(
            keyword in v.get("id", "")
            for keyword in ["keyboard", "focus", "tabindex"]
        )
    ]

    if keyboard_violations:
        logger.warning(
            f"Keyboard accessibility issues: {len(keyboard_violations)}"
        )

    assert (
        len(keyboard_violations) == 0
    ), "Keyboard accessibility violations found"
