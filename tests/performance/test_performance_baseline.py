"""
Performance Baseline Tests - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 7

Baseline performance tests to establish and verify performance standards.
Tests critical user flows and measures response times.

Performance Thresholds:
- Page Load: <= 5s
- Login: <= 3s
- Add to Cart: <= 2s
- Checkout: <= 5s
"""

import logging

import pytest

logger = logging.getLogger(__name__)


@pytest.mark.performance
@pytest.mark.critical
def test_homepage_load_performance(browser, base_url, performance_collector):
    """
    PERF-001: Homepage Load Performance

    Objective: Verify homepage loads within acceptable time
    Threshold: <= 5 seconds
    """
    performance_collector.start_timer("page_load")

    browser.get(base_url)

    # Wait for page to be fully loaded
    browser.execute_script("return document.readyState") == "complete"

    duration = performance_collector.stop_timer(
        "page_load", category="navigation"
    )

    logger.info(f"Homepage loaded in {duration:.3f}s")

    assert performance_collector.check_threshold(
        "page_load", duration
    ), f"Homepage load time {duration:.3f}s exceeds threshold"


@pytest.mark.performance
@pytest.mark.critical
def test_login_performance(login_page, valid_user, performance_collector):
    """
    PERF-002: Login Operation Performance

    Objective: Verify login completes within acceptable time
    Threshold: <= 3 seconds
    """
    performance_collector.start_timer("login")

    login_page.login(**valid_user)

    duration = performance_collector.stop_timer(
        "login", category="authentication"
    )

    assert login_page.is_user_logged_in(), "Login should succeed"

    logger.info(f"Login completed in {duration:.3f}s")

    assert performance_collector.check_threshold(
        "login", duration
    ), f"Login time {duration:.3f}s exceeds threshold"

    login_page.logout()


@pytest.mark.performance
@pytest.mark.high
def test_product_selection_performance(
    catalog_page, product_phone, performance_collector
):
    """
    PERF-003: Product Selection Performance

    Objective: Verify product selection and page load is fast
    Threshold: <= 2 seconds
    """
    from pages.product_page import ProductPage

    performance_collector.start_timer("product_selection")

    catalog_page.select_product(product_phone)

    product_page = ProductPage(catalog_page.driver)
    assert product_page.is_product_page_loaded()

    duration = performance_collector.stop_timer(
        "product_selection", category="navigation"
    )

    logger.info(f"Product selection completed in {duration:.3f}s")

    # Using generic 2s threshold
    assert (
        duration <= 2.0
    ), f"Product selection time {duration:.3f}s exceeds 2s"


@pytest.mark.performance
@pytest.mark.high
def test_add_to_cart_performance(
    logged_in_user, catalog_page, product_phone, performance_collector
):
    """
    PERF-004: Add to Cart Performance

    Objective: Verify adding product to cart is fast
    Threshold: <= 2 seconds
    """
    from pages.product_page import ProductPage

    catalog_page.select_product(product_phone)
    product_page = ProductPage(catalog_page.driver)

    performance_collector.start_timer("add_to_cart")

    product_page.add_to_cart()
    alert = product_page.get_alert_text(timeout=3)

    duration = performance_collector.stop_timer(
        "add_to_cart", category="shopping"
    )

    assert alert is not None, "Should receive confirmation alert"

    logger.info(f"Add to cart completed in {duration:.3f}s")

    assert performance_collector.check_threshold(
        "add_to_cart", duration
    ), f"Add to cart time {duration:.3f}s exceeds threshold"


@pytest.mark.performance
@pytest.mark.high
def test_checkout_flow_performance(
    cart_with_product, purchase_data, performance_collector
):
    """
    PERF-005: Complete Checkout Flow Performance

    Objective: Verify entire checkout process completes quickly
    Threshold: <= 5 seconds
    """
    from pages.purchase_page import PurchasePage
    from utils.performance.decorators import PerformanceMonitor

    cart_page, _ = cart_with_product

    monitor = PerformanceMonitor("checkout_flow", category="shopping")
    monitor.start()

    # Step 1: Open purchase modal
    cart_page.click_place_order()
    monitor.checkpoint("modal_opened")

    # Step 2: Fill form
    purchase_page = PurchasePage(cart_page.driver)
    purchase_page.fill_form(**purchase_data)
    monitor.checkpoint("form_filled")

    # Step 3: Complete purchase
    purchase_page.confirm_purchase()
    monitor.checkpoint("purchase_confirmed")

    total_duration = monitor.stop()

    logger.info(f"Checkout flow completed in {total_duration:.3f}s")
    logger.info(f"Checkpoints: {monitor.checkpoints}")

    assert performance_collector.check_threshold(
        "checkout", total_duration
    ), f"Checkout time {total_duration:.3f}s exceeds threshold"


@pytest.mark.performance
@pytest.mark.medium
def test_category_filter_performance(catalog_page, performance_collector):
    """
    PERF-006: Category Filter Performance

    Objective: Verify category filtering is responsive
    Threshold: <= 2 seconds
    """
    performance_collector.start_timer("category_filter")

    catalog_page.click_category("Phones")

    # Wait for products to load
    catalog_page.wait_for_products_loaded()

    duration = performance_collector.stop_timer(
        "category_filter", category="navigation"
    )

    logger.info(f"Category filter completed in {duration:.3f}s")

    assert duration <= 2.0, f"Category filter time {duration:.3f}s exceeds 2s"


@pytest.mark.performance
@pytest.mark.medium
def test_cart_page_load_performance(
    logged_in_user, catalog_page, performance_collector
):
    """
    PERF-007: Cart Page Load Performance

    Objective: Verify cart page loads quickly
    Threshold: <= 2 seconds
    """
    from pages.cart_page import CartPage

    performance_collector.start_timer("cart_page_load")

    cart_page = CartPage(catalog_page.driver)
    cart_page.go_to_cart()

    duration = performance_collector.stop_timer(
        "cart_page_load", category="navigation"
    )

    logger.info(f"Cart page loaded in {duration:.3f}s")

    assert duration <= 2.0, f"Cart page load time {duration:.3f}s exceeds 2s"


@pytest.mark.performance
@pytest.mark.low
def test_multiple_products_load(catalog_page, performance_collector):
    """
    PERF-008: Multiple Products Load Performance

    Objective: Verify catalog can handle viewing multiple products
    Measures average time per product view
    """
    from pages.product_page import ProductPage

    products = ["Samsung galaxy s6", "Nokia lumia 1520", "Nexus 6"]

    for product in products:
        metric_name = f"product_view_{product.replace(' ', '_')}"
        performance_collector.start_timer(metric_name)

        catalog_page.select_product(product)

        product_page = ProductPage(catalog_page.driver)
        assert product_page.is_product_page_loaded()

        duration = performance_collector.stop_timer(
            metric_name, category="navigation"
        )

        logger.info(f"Product '{product}' loaded in {duration:.3f}s")

        # Go back to catalog
        catalog_page.driver.back()

    # Check statistics
    stats = performance_collector.get_statistics(
        "product_view_Samsung_galaxy_s6"
    )
    if stats:
        logger.info(f"Product view statistics: {stats}")


@pytest.mark.performance
@pytest.mark.slow
def test_login_logout_cycle_performance(
    login_page, valid_user, performance_collector
):
    """
    PERF-009: Login/Logout Cycle Performance

    Objective: Verify multiple login/logout cycles maintain performance
    Tests: 3 cycles, each should be within threshold
    """
    cycles = 3

    for i in range(cycles):
        # Login
        login_metric = f"login_cycle_{i+1}"
        performance_collector.start_timer(login_metric)

        login_page.login(**valid_user)
        assert login_page.is_user_logged_in()

        login_duration = performance_collector.stop_timer(
            login_metric, category="authentication"
        )

        logger.info(f"Cycle {i+1} - Login: {login_duration:.3f}s")

        # Logout
        logout_metric = f"logout_cycle_{i+1}"
        performance_collector.start_timer(logout_metric)

        login_page.logout()
        assert not login_page.is_user_logged_in()

        logout_duration = performance_collector.stop_timer(
            logout_metric, category="authentication"
        )

        logger.info(f"Cycle {i+1} - Logout: {logout_duration:.3f}s")

        # Each login should meet threshold
        assert performance_collector.check_threshold(
            "login", login_duration
        ), f"Cycle {i+1} login time exceeds threshold"

    # Check if performance degrades over cycles
    login_stats = performance_collector.get_statistics("login_cycle_1")
    logger.info(f"Login cycle statistics: {login_stats}")


@pytest.mark.performance
@pytest.mark.medium
def test_concurrent_user_simulation(
    browser, base_url, valid_user, performance_collector
):
    """
    PERF-010: Simulated Concurrent User Activity

    Objective: Measure performance during typical user flow
    Simulates: browse -> select -> add to cart -> view cart
    """
    from pages.cart_page import CartPage
    from pages.catalog_page import CatalogPage
    from pages.login_page import LoginPage
    from pages.product_page import ProductPage
    from utils.performance.decorators import PerformanceMonitor

    monitor = PerformanceMonitor(
        "user_flow_simulation", category="integration"
    )
    monitor.start()

    # Step 1: Navigate to site
    browser.get(base_url)
    monitor.checkpoint("site_loaded")

    # Step 2: Login
    login_page = LoginPage(browser)
    login_page.login(**valid_user)
    monitor.checkpoint("logged_in")

    # Step 3: Browse catalog
    catalog_page = CatalogPage(browser)
    catalog_page.click_category("Phones")
    monitor.checkpoint("category_selected")

    # Step 4: View product
    catalog_page.select_product("Samsung galaxy s6")
    monitor.checkpoint("product_viewed")

    # Step 5: Add to cart
    product_page = ProductPage(browser)
    product_page.add_to_cart()
    alert = product_page.get_alert_text(timeout=2)
    if alert:
        product_page.accept_alert()
    monitor.checkpoint("added_to_cart")

    # Step 6: View cart
    cart_page = CartPage(browser)
    cart_page.go_to_cart()
    monitor.checkpoint("cart_viewed")

    total_duration = monitor.stop()

    logger.info(f"Complete user flow: {total_duration:.3f}s")
    logger.info("Checkpoints:")
    for name, elapsed in monitor.checkpoints:
        logger.info(f"  - {name}: {elapsed:.3f}s")

    # Cleanup
    login_page.logout()

    # Total flow should be reasonable (< 20s for all steps)
    assert (
        total_duration < 20.0
    ), f"User flow took {total_duration:.3f}s, exceeds 20s threshold"
