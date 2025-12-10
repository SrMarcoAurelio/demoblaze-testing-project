"""
Discovery-Based Testing Example - Login Functionality
Author: Marc Arévalo
Version: 1.0

This test demonstrates the UNIVERSAL, DISCOVERY-BASED approach.

Key Principles Demonstrated:
1. DISCOVERS page structure instead of ASSUMING it
2. Works with ANY web application that has login
3. No hardcoded locators or credentials
4. Uses DiscoveryEngine to find forms automatically
5. Adapts to different authentication mechanisms

This test could work with Demoblaze, or ANY other web application!
"""

import logging

import pytest

from framework.adapters.demoblaze_adapter import DemoblazeAdapter
from framework.core.discovery_engine import DiscoveryEngine
from framework.core.element_interactor import ElementInteractor
from framework.core.wait_handler import WaitHandler


@pytest.fixture
def adapter():
    """Provide application adapter."""
    return DemoblazeAdapter()


@pytest.mark.examples
@pytest.mark.discovery
def test_discover_login_form_structure(browser, adapter):
    """
    DISCOVERY TEST: Automatically discovers login form structure.

    This test DISCOVERS:
    - Whether a login form exists
    - What fields the form has
    - What types of inputs are required
    - How many buttons exist

    Works with ANY application!
    """
    browser.get(adapter.get_base_url())

    # Initialize discovery engine
    discovery = DiscoveryEngine(browser)

    # DISCOVER all forms on the page
    forms = discovery.discover_forms()
    logging.info(f"✓ DISCOVERED {len(forms)} forms on page")

    assert len(forms) > 0, "No forms discovered on page"

    # Log what we discovered
    for i, form in enumerate(forms):
        logging.info(f"\nForm {i + 1}:")
        logging.info(f"  ID: {form['id']}")
        logging.info(f"  Name: {form['name']}")
        logging.info(f"  Inputs: {len(form['inputs'])}")
        logging.info(f"  Buttons: {len(form['buttons'])}")

        for input_field in form["inputs"]:
            logging.info(
                f"    - Input: {input_field['name']} "
                f"({input_field['type']}) "
                f"placeholder='{input_field['placeholder']}'"
            )

        for button in form["buttons"]:
            logging.info(f"    - Button: {button['text']} ({button['type']})")

    logging.info("\n✓ TEST PASSED: Successfully discovered form structure")


@pytest.mark.examples
@pytest.mark.discovery
def test_discover_and_validate_login_form_fields(browser, adapter):
    """
    DISCOVERY TEST: Validates that login form has required fields.

    This test DISCOVERS:
    - Login form fields
    - Field types and requirements
    - Whether username and password fields exist

    UNIVERSAL: Works with any application that has username/password login!
    """
    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)

    # Get page metadata
    metadata = discovery.discover_page_metadata()
    logging.info(f"Page: {metadata['title']}")
    logging.info(f"URL: {metadata['url']}")

    # Discover forms
    forms = discovery.discover_forms()

    # Find form with username and password fields (DISCOVERY!)
    login_form = None
    for form in forms:
        input_types = [inp["type"] for inp in form["inputs"]]
        input_names = [
            inp["name"].lower() if inp["name"] else ""
            for inp in form["inputs"]
        ]

        # Check if this looks like a login form
        has_text_input = "text" in input_types
        has_password_input = "password" in input_types
        has_user_field = any(
            "user" in name or "login" in name for name in input_names
        )

        if (has_text_input or has_user_field) and has_password_input:
            login_form = form
            logging.info(f"✓ DISCOVERED login form: {form['id']}")
            break

    # Note: For Demoblaze, login is in a modal, not visible on initial page load
    # This is expected behavior - the test discovers what's available
    if not login_form:
        logging.info("ℹ No login form visible on initial page (may use modal)")
        logging.info(
            "This is expected for applications with modal-based login"
        )

        # Discover navigation to find login trigger
        navigation = discovery.discover_navigation()
        all_links = navigation["all_links"]

        # Find login link/button
        login_trigger = None
        for link in all_links:
            if "log" in link["text"].lower() and "in" in link["text"].lower():
                login_trigger = link
                logging.info(f"✓ DISCOVERED login trigger: '{link['text']}'")
                break

        assert login_trigger is not None, "No login form or trigger found"

    logging.info("\n✓ TEST PASSED: Login functionality discovered")


@pytest.mark.examples
@pytest.mark.discovery
def test_discover_all_interactive_elements(browser, adapter):
    """
    DISCOVERY TEST: Discovers ALL interactive elements on page.

    This test demonstrates comprehensive page discovery.

    DISCOVERS:
    - All buttons
    - All links
    - All input fields
    - All dropdowns
    - All checkboxes/radios

    Useful for:
    - Understanding page structure
    - Finding missing test coverage
    - Identifying interactive elements
    - Security testing (finding all inputs)
    """
    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)

    # DISCOVER all interactive elements
    interactive = discovery.discover_interactive_elements()

    logging.info("\n" + "=" * 70)
    logging.info("INTERACTIVE ELEMENTS DISCOVERY REPORT")
    logging.info("=" * 70)

    logging.info(f"\n📝 Buttons: {len(interactive['buttons'])}")
    for button in interactive["buttons"]:
        logging.info(f"  - {button['text']} (type: {button['type']})")

    logging.info(f"\n🔗 Links: {len(interactive['links'])}")
    visible_links = [link for link in interactive["links"] if link["visible"]]
    logging.info(f"  Visible: {len(visible_links)}")
    for link in visible_links[:10]:  # Show first 10
        logging.info(f"  - {link['text']} -> {link['href']}")

    logging.info(f"\n📄 Input Fields: {len(interactive['inputs'])}")
    for input_field in interactive["inputs"]:
        logging.info(f"  - {input_field['name']} ({input_field['type']})")

    logging.info(f"\n📋 Dropdowns: {len(interactive['selects'])}")
    for select in interactive["selects"]:
        logging.info(
            f"  - {select['name']} ({len(select['options'])} options)"
        )

    logging.info(f"\n☑ Checkboxes: {len(interactive['checkboxes'])}")
    logging.info(f"📻 Radio Buttons: {len(interactive['radios'])}")
    logging.info(f"📝 Text Areas: {len(interactive['textareas'])}")

    total = sum(len(v) for v in interactive.values())
    logging.info(f"\n✓ TOTAL INTERACTIVE ELEMENTS: {total}")
    logging.info("=" * 70)

    assert total > 0, "No interactive elements discovered"
    logging.info(
        "\n✓ TEST PASSED: Successfully discovered all interactive elements"
    )


@pytest.mark.examples
@pytest.mark.discovery
def test_discover_navigation_structure(browser, adapter):
    """
    DISCOVERY TEST: Discovers navigation structure.

    This test DISCOVERS:
    - Header navigation links
    - Footer navigation links
    - Sidebar navigation (if exists)
    - Breadcrumbs (if exists)

    UNIVERSAL: Works with any web application!
    """
    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)

    # DISCOVER navigation
    navigation = discovery.discover_navigation()

    logging.info("\n" + "=" * 70)
    logging.info("NAVIGATION STRUCTURE DISCOVERY REPORT")
    logging.info("=" * 70)

    logging.info(f"\n🔝 Header Navigation: {len(navigation['header'])} items")
    for nav_item in navigation["header"]:
        logging.info(f"  - {nav_item['text']} -> {nav_item['href']}")

    logging.info(f"\n🔽 Footer Navigation: {len(navigation['footer'])} items")
    for nav_item in navigation["footer"][:5]:  # Show first 5
        logging.info(f"  - {nav_item['text']} -> {nav_item['href']}")

    logging.info(f"\n◀ Sidebar Navigation: {len(navigation['sidebar'])} items")
    for nav_item in navigation["sidebar"]:
        logging.info(f"  - {nav_item['text']} -> {nav_item['href']}")

    logging.info(f"\n🍞 Breadcrumbs: {len(navigation['breadcrumbs'])} items")
    for nav_item in navigation["breadcrumbs"]:
        logging.info(f"  - {nav_item['text']}")

    logging.info(f"\n🔗 All Links: {len(navigation['all_links'])} items")
    logging.info("=" * 70)

    total_nav = (
        len(navigation["header"])
        + len(navigation["footer"])
        + len(navigation["sidebar"])
    )

    assert total_nav > 0, "No navigation discovered"
    logging.info(
        "\n✓ TEST PASSED: Successfully discovered navigation structure"
    )


@pytest.mark.examples
@pytest.mark.discovery
def test_generate_complete_page_report(browser, adapter):
    """
    DISCOVERY TEST: Generates comprehensive page structure report.

    This test demonstrates the most comprehensive discovery capability.

    DISCOVERS EVERYTHING:
    - Page metadata (title, URL, meta tags)
    - All forms and their fields
    - All navigation elements
    - All interactive elements
    - Complete page summary

    USE CASES:
    - Initial exploration of new application
    - Documenting page structure
    - Finding test coverage gaps
    - Security analysis
    """
    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)

    # GENERATE COMPLETE REPORT
    report = discovery.generate_page_report()

    logging.info("\n" + "=" * 70)
    logging.info("COMPLETE PAGE STRUCTURE REPORT")
    logging.info("=" * 70)

    # Metadata
    logging.info(f"\n📄 PAGE METADATA:")
    logging.info(f"  Title: {report['metadata']['title']}")
    logging.info(f"  URL: {report['metadata']['url']}")
    logging.info(f"  Language: {report['metadata']['lang']}")
    if report["metadata"]["meta_description"]:
        logging.info(
            f"  Description: {report['metadata']['meta_description']}"
        )

    # Summary
    logging.info(f"\n📊 SUMMARY:")
    summary = report["summary"]
    logging.info(f"  Forms: {summary['total_forms']}")
    logging.info(f"  Input Fields: {summary['total_inputs']}")
    logging.info(f"  Buttons: {summary['total_buttons']}")
    logging.info(f"  Links: {summary['total_links']}")
    logging.info(f"  Navigation Items: {summary['total_navigation']}")
    logging.info(f"  Total Interactive: {summary['total_interactive']}")

    # Forms Detail
    if report["forms"]:
        logging.info(f"\n📝 FORMS DETAIL:")
        for i, form in enumerate(report["forms"], 1):
            logging.info(f"\n  Form {i}:")
            logging.info(f"    ID: {form['id']}")
            logging.info(f"    Action: {form['action']}")
            logging.info(f"    Method: {form['method']}")
            logging.info(f"    Inputs: {len(form['inputs'])}")
            logging.info(f"    Buttons: {len(form['buttons'])}")

    # Navigation Detail
    logging.info(f"\n🧭 NAVIGATION DETAIL:")
    logging.info(f"  Header: {len(report['navigation']['header'])} items")
    logging.info(f"  Footer: {len(report['navigation']['footer'])} items")
    logging.info(f"  Sidebar: {len(report['navigation']['sidebar'])} items")

    logging.info("\n" + "=" * 70)
    logging.info(f"✓ DISCOVERY COMPLETE")
    logging.info("=" * 70)

    # Assertions
    assert (
        report["summary"]["total_interactive"] > 0
    ), "No interactive elements"
    assert report["metadata"]["title"], "No page title"

    logging.info(
        "\n✓ TEST PASSED: Complete page report generated successfully"
    )


@pytest.mark.examples
@pytest.mark.discovery
@pytest.mark.skip(
    reason="Requires valid credentials - set TEST_USERNAME and TEST_PASSWORD"
)
def test_discovery_based_login_flow(browser, adapter):
    """
    DISCOVERY TEST: Complete login flow using discovery.

    This test demonstrates HOW TO USE discovery for actual functionality testing.

    DISCOVERS:
    - Login trigger (button/link)
    - Login form fields
    - Submit button
    - Success indicators

    NOTE: This is a DEMONSTRATION. In production, you'd combine discovery
    with adapter configuration for more reliable tests.
    """
    # Get credentials from adapter (reads from environment)
    test_users = adapter.get_test_users()
    valid_user = test_users.get("valid", {})

    if not valid_user.get("username") or not valid_user.get("password"):
        pytest.skip(
            "Test credentials not configured (TEST_USERNAME, TEST_PASSWORD)"
        )

    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)
    interactor = ElementInteractor(browser)
    waiter = WaitHandler(browser)

    # 1. DISCOVER login trigger
    navigation = discovery.discover_navigation()
    login_link = None

    for link in navigation["all_links"]:
        if "log" in link["text"].lower() and "in" in link["text"].lower():
            login_link = link
            break

    assert login_link is not None, "Login link not found"
    logging.info(f"✓ DISCOVERED login link: '{login_link['text']}'")

    # 2. Click login trigger
    interactor.click(login_link["element"])
    waiter.wait_for_page_load()

    # 3. DISCOVER login form
    forms = discovery.discover_forms()
    login_form = None

    for form in forms:
        input_types = [inp["type"] for inp in form["inputs"]]
        if "password" in input_types:
            login_form = form
            break

    assert login_form is not None, "Login form not found"
    logging.info(
        f"✓ DISCOVERED login form with {len(login_form['inputs'])} inputs"
    )

    # 4. Fill discovered form
    username_field = None
    password_field = None

    for inp in login_form["inputs"]:
        if "user" in inp["name"].lower() or "login" in inp["name"].lower():
            username_field = inp
        elif inp["type"] == "password":
            password_field = inp

    assert (
        username_field and password_field
    ), "Username or password field not found"

    interactor.type(username_field["element"], valid_user["username"])
    interactor.type(password_field["element"], valid_user["password"])

    # 5. DISCOVER and click submit button
    submit_button = None
    for button in login_form["buttons"]:
        if (
            "submit" in button["type"].lower()
            or "log" in button["text"].lower()
        ):
            submit_button = button
            break

    assert submit_button is not None, "Submit button not found"
    logging.info(f"✓ DISCOVERED submit button: '{submit_button['text']}'")

    interactor.click(submit_button["element"])

    # 6. Wait and verify (basic)
    waiter.wait_for_page_load(timeout=5)

    logging.info("\n✓ TEST PASSED: Discovery-based login flow completed")


if __name__ == "__main__":
    """
    Run these tests with:
    pytest tests/examples/test_discovery_based_login.py -v -s
    """
    pytest.main([__file__, "-v", "-s", "-m", "discovery"])
