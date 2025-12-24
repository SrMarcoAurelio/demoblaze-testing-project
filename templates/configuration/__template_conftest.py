"""
Universal Pytest Configuration Template (conftest.py)

INSTRUCTIONS:
1. Copy this file to your project root as: conftest.py
2. Replace ALL_CAPS placeholders with YOUR values
3. Remove pytest.skip() line
4. Adapt fixtures to YOUR application's needs
5. Add YOUR application-specific fixtures

Pytest fixtures provide:
- Test setup and teardown
- Shared test data
- Browser instances
- Database connections
- API clients
- etc.
"""

import os

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# SKIP BY DEFAULT - Remove this when you adapt the template
pytest.skip(
    "Template not adapted - configure for YOUR application",
    allow_module_level=True,
)


# ============================================================================
# CONFIGURATION FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def base_url():
    """
    Base URL of YOUR application.

    Reads from environment variable BASE_URL or uses default.

    Returns:
        Base URL string

    Usage in tests:
        def test_something(base_url):
            page.navigate_to(f"{base_url}/login")

    ADAPT THIS:
    - Replace default URL with YOUR application's URL
    - Or require it via environment variable
    """
    url = os.getenv("BASE_URL")
    if not url:
        pytest.fail(
            "BASE_URL environment variable not set. "
            "Set it in .env file or export BASE_URL=https://your-app-url.com"
        )
    return url.rstrip("/")


@pytest.fixture(scope="session")
def config():
    """
    Application configuration dictionary.

    Returns configuration values from environment or config file.

    Returns:
        Dictionary with configuration values

    ADAPT THIS:
    - Add YOUR application's configuration values
    - Load from YOUR config file if needed
    """
    return {
        "base_url": os.getenv("BASE_URL"),
        "timeout": int(os.getenv("DEFAULT_TIMEOUT", "10")),
        "headless": os.getenv("HEADLESS", "false").lower() == "true",
        # Add YOUR configuration values here
        # "api_url": os.getenv("API_URL"),
        # "database_url": os.getenv("DATABASE_URL"),
    }


# ============================================================================
# BROWSER FIXTURES
# ============================================================================


@pytest.fixture(scope="function")
def browser(request):
    """
    Selenium WebDriver browser instance.

    Creates a new browser for each test function.
    Automatically quits browser after test completes.

    Returns:
        WebDriver instance

    Usage in tests:
        def test_login(browser):
            browser.get("https://example.com")

    ADAPT THIS:
    - Configure YOUR preferred browser options
    - Add support for multiple browsers (Firefox, Edge, etc.)
    - Add YOUR desired capabilities
    """
    options = Options()

    # Common options
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")

    # Headless mode (for CI/CD)
    if os.getenv("HEADLESS", "false").lower() == "true":
        options.add_argument("--headless=new")

    # Window size
    window_size = os.getenv("WINDOW_SIZE", "1920,1080")
    options.add_argument(f"--window-size={window_size}")

    # Add YOUR custom options here
    # options.add_argument("--disable-notifications")
    # options.add_argument("--disable-popup-blocking")

    # Create driver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.maximize_window()

    # Set implicit wait (adapt to YOUR needs)
    driver.implicitly_wait(int(os.getenv("IMPLICIT_WAIT", "0")))

    yield driver

    # Teardown
    driver.quit()


@pytest.fixture(scope="session")
def browser_session(request):
    """
    Session-scoped browser for tests that need to share browser state.

    ⚠️ WARNING: Using session scope can cause test interdependence.
    Only use when necessary (e.g., expensive setup operations).

    Returns:
        WebDriver instance

    ADAPT THIS to YOUR needs, or remove if not needed.
    """
    options = Options()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    if os.getenv("HEADLESS", "false").lower() == "true":
        options.add_argument("--headless=new")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.maximize_window()

    yield driver

    driver.quit()


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def test_user():
    """
    Test user credentials.

    Returns:
        Dictionary with username and password

    ADAPT THIS:
    - Use YOUR test user credentials
    - Load from environment variables (recommended)
    - Or create test users dynamically
    """
    username = os.getenv("TEST_USERNAME")
    password = os.getenv("TEST_PASSWORD")

    if not username or not password:
        pytest.fail(
            "TEST_USERNAME and TEST_PASSWORD must be set in environment. "
            "Add them to your .env file."
        )

    return {
        "username": username,
        "password": password,
    }


@pytest.fixture(scope="function")
def test_data():
    """
    Generic test data fixture.

    Returns:
        Dictionary with test data

    ADAPT THIS:
    - Add YOUR application's test data
    - Generate dynamic data
    - Load from files or database
    """
    return {
        # Add YOUR test data here
        # "email": "test@example.com",
        # "phone": "+1234567890",
        # "address": "123 Test St",
    }


# ============================================================================
# PYTEST HOOKS (OPTIONAL)
# ============================================================================


def pytest_configure(config):
    """
    Pytest configuration hook.

    Runs once before test collection.

    ADAPT THIS:
    - Register custom markers
    - Set up test reporting
    - Configure logging
    """
    # Register custom markers
    config.addinivalue_line(
        "markers", "functional: Mark test as functional test"
    )
    config.addinivalue_line("markers", "security: Mark test as security test")
    config.addinivalue_line("markers", "smoke: Mark test as smoke test")
    # Add YOUR custom markers


def pytest_runtest_setup(item):
    """
    Hook called before each test runs.

    ADAPT THIS:
    - Add per-test setup logic
    - Skip tests based on conditions
    - Set up test environment
    """
    pass


def pytest_runtest_teardown(item, nextitem):
    """
    Hook called after each test runs.

    ADAPT THIS:
    - Add per-test cleanup logic
    - Capture screenshots on failure
    - Clean up test data
    """
    pass


# ============================================================================
# CUSTOM FIXTURES FOR YOUR APPLICATION
# ============================================================================

# Add YOUR application-specific fixtures here:
#
# @pytest.fixture
# def api_client(base_url):
#     """YOUR API client fixture"""
#     return APIClient(base_url)
#
# @pytest.fixture
# def database_connection():
#     """YOUR database fixture"""
#     conn = connect_to_db()
#     yield conn
#     conn.close()


# ADAPTATION CHECKLIST:
# [ ] Copied to project root as conftest.py
# [ ] Removed pytest.skip() line
# [ ] Updated base_url fixture with YOUR application URL
# [ ] Updated test_user fixture with YOUR test credentials
# [ ] Configured browser options for YOUR needs
# [ ] Added YOUR application-specific fixtures
# [ ] Registered YOUR custom pytest markers
# [ ] Tested fixtures work with YOUR tests
# [ ] Removed this checklist when done
