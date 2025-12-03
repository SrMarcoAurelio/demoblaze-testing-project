# Extending the Framework Guide

Complete guide for customizing and extending the framework.

## Table of Contents

1. [Creating New Page Objects](#creating-new-page-objects)
2. [Creating Custom Fixtures](#creating-custom-fixtures)
3. [Extending BasePage](#extending-basepage)
4. [Creating Custom Utilities](#creating-custom-utilities)
5. [Creating Custom Pytest Markers](#creating-custom-pytest-markers)
6. [Creating Custom Reporters](#creating-custom-reporters)
7. [Adding New Test Types](#adding-new-test-types)
8. [Integrating Third-Party Tools](#integrating-third-party-tools)

---

## Creating New Page Objects

### Step 1: Define Locators in JSON

**File:** `config/locators.json`

```json
{
  "profile": {
    "profile_link": {"by": "id", "value": "profileLink"},
    "username_display": {"by": "class", "value": "username"},
    "edit_button": {"by": "xpath", "value": "//button[text()='Edit']"},
    "save_button": {"by": "css", "value": ".btn-save"}
  }
}
```

### Step 2: Create Page Object Class

**File:** `pages/profile_page.py`

```python
"""
Profile Page Object
Author: Your Name
Version: 1.0
"""

from pages.base_page import BasePage
from utils.locators_loader import load_locator
from typing import Optional


class ProfilePage(BasePage):
    """Profile page interactions."""

    # Load locators
    profile_link = load_locator("profile", "profile_link")
    username_display = load_locator("profile", "username_display")
    edit_button = load_locator("profile", "edit_button")
    save_button = load_locator("profile", "save_button")

    def navigate_to_profile(self) -> None:
        """Navigate to profile page."""
        self.click(self.profile_link)

    def get_username(self) -> str:
        """Get displayed username."""
        return self.get_text(self.username_display)

    def edit_profile(self, name: Optional[str] = None) -> None:
        """Edit profile information."""
        self.click(self.edit_button)
        self.wait_for_element_visible(self.save_button)

        if name:
            # Add field interactions here
            pass

        self.click(self.save_button)

    def is_profile_updated(self) -> bool:
        """Check if profile was updated."""
        # Add verification logic
        return True
```

### Step 3: Create Fixture

**File:** `conftest.py`

```python
@pytest.fixture(scope="function")
def profile_page(browser, base_url):
    """Provide initialized ProfilePage instance."""
    from pages.profile_page import ProfilePage

    browser.get(base_url)
    return ProfilePage(browser)
```

### Step 4: Create Tests

**File:** `tests/profile/test_profile_functional.py`

```python
"""
Profile Functional Tests
Author: Your Name
"""

import pytest


@pytest.mark.functional
def test_view_profile(profile_page, logged_in_user):
    """Test viewing user profile."""
    profile_page.navigate_to_profile()

    username = profile_page.get_username()
    assert username != ""


@pytest.mark.functional
def test_edit_profile(profile_page, logged_in_user):
    """Test editing profile."""
    profile_page.navigate_to_profile()
    profile_page.edit_profile(name="New Name")

    assert profile_page.is_profile_updated()
```

---

## Creating Custom Fixtures

### Pattern 1: Simple Data Fixture

```python
# conftest.py

@pytest.fixture(scope="session")
def api_config():
    """Provide API configuration."""
    return {
        "base_url": "https://api.example.com",
        "version": "v1",
        "timeout": 30,
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    }
```

**Usage:**
```python
def test_api_call(api_config):
    response = requests.get(f"{api_config['base_url']}/users")
    assert response.status_code == 200
```

---

### Pattern 2: Fixture with Setup/Teardown

```python
@pytest.fixture(scope="function")
def test_database():
    """Provide test database with automatic cleanup."""
    # Setup
    db = Database("test.db")
    db.create_tables()
    db.insert_test_data()

    yield db  # Test uses database

    # Teardown
    db.drop_tables()
    db.close()
```

**Usage:**
```python
def test_database_query(test_database):
    result = test_database.query("SELECT * FROM users")
    assert len(result) > 0
```

---

### Pattern 3: Parameterized Fixture

```python
@pytest.fixture(scope="function", params=["chrome", "firefox", "edge"])
def multi_browser(request):
    """Provide different browsers."""
    browser_name = request.param

    if browser_name == "chrome":
        driver = webdriver.Chrome()
    elif browser_name == "firefox":
        driver = webdriver.Firefox()
    elif browser_name == "edge":
        driver = webdriver.Edge()

    yield driver

    driver.quit()
```

**Usage:**
```python
def test_cross_browser(multi_browser):
    # Runs 3 times - once for each browser
    multi_browser.get("https://example.com")
    assert "Example" in multi_browser.title
```

---

### Pattern 4: Fixture Factory

```python
@pytest.fixture
def make_user():
    """Factory for creating test users."""
    created_users = []

    def _make_user(username=None, email=None):
        user = {
            "username": username or generate_unique_username(),
            "email": email or generate_random_email(),
            "password": generate_random_password()
        }
        created_users.append(user)
        return user

    yield _make_user

    # Cleanup all created users
    for user in created_users:
        cleanup_user(user)
```

**Usage:**
```python
def test_multiple_users(make_user):
    user1 = make_user(username="alice")
    user2 = make_user(username="bob")

    # Both users automatically cleaned up after test
```

---

## Extending BasePage

### Adding New Common Methods

**File:** `pages/base_page.py`

```python
class BasePage:
    # ... existing methods ...

    def drag_and_drop(
        self,
        source_locator: Tuple[str, str],
        target_locator: Tuple[str, str]
    ) -> None:
        """
        Drag and drop element to target.

        Args:
            source_locator: Source element
            target_locator: Target element
        """
        source = self.find_element(source_locator)
        target = self.find_element(target_locator)

        ActionChains(self.driver).drag_and_drop(source, target).perform()
        self.logger.info(f"Dragged {source_locator} to {target_locator}")

    def select_dropdown_by_text(
        self,
        locator: Tuple[str, str],
        text: str
    ) -> None:
        """
        Select dropdown option by visible text.

        Args:
            locator: Dropdown element locator
            text: Visible text of option
        """
        from selenium.webdriver.support.ui import Select

        element = self.find_element(locator)
        select = Select(element)
        select.select_by_visible_text(text)
        self.logger.info(f"Selected '{text}' from dropdown: {locator}")

    def upload_file(
        self,
        locator: Tuple[str, str],
        file_path: str
    ) -> None:
        """
        Upload file to input element.

        Args:
            locator: File input element
            file_path: Absolute path to file
        """
        import os

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        element = self.find_element(locator)
        element.send_keys(file_path)
        self.logger.info(f"Uploaded file: {file_path}")
```

**Usage in Page Objects:**
```python
class UploadPage(BasePage):
    file_input = load_locator("upload", "file_input")

    def upload_document(self, file_path: str) -> None:
        self.upload_file(self.file_input, file_path)
```

---

### Creating Specialized Base Classes

**File:** `pages/base_modal_page.py`

```python
"""
Base class for modal dialogs.
Extends BasePage with modal-specific methods.
"""

from pages.base_page import BasePage
from typing import Tuple


class BaseModalPage(BasePage):
    """Base class for modal/dialog pages."""

    # Common modal locators (can be overridden)
    modal_container = None  # Override in subclass
    close_button = None     # Override in subclass

    def wait_for_modal_visible(self, timeout: int = 10) -> None:
        """Wait for modal to appear."""
        if not self.modal_container:
            raise NotImplementedError("modal_container must be defined")

        self.wait_for_element_visible(self.modal_container, timeout)
        self.logger.info("Modal visible")

    def close_modal(self) -> None:
        """Close modal dialog."""
        if not self.close_button:
            raise NotImplementedError("close_button must be defined")

        self.click(self.close_button)
        self.wait_for_modal_invisible()

    def wait_for_modal_invisible(self, timeout: int = 5) -> None:
        """Wait for modal to disappear."""
        if not self.modal_container:
            raise NotImplementedError("modal_container must be defined")

        self.wait_for_element_invisible(self.modal_container, timeout)
        self.logger.info("Modal closed")

    def is_modal_open(self) -> bool:
        """Check if modal is currently open."""
        if not self.modal_container:
            return False

        return self.is_element_visible(self.modal_container, timeout=2)
```

**Usage:**
```python
from pages.base_modal_page import BaseModalPage
from utils.locators_loader import load_locator


class LoginModal(BaseModalPage):
    """Login modal dialog."""

    # Define modal-specific locators
    modal_container = load_locator("login", "modal_container")
    close_button = load_locator("login", "close_button")
    username_field = load_locator("login", "username_field")

    def login(self, username: str, password: str) -> None:
        self.wait_for_modal_visible()
        self.type(self.username_field, username)
        # ... rest of login logic
```

---

## Creating Custom Utilities

### Example: Email Verification Utility

**File:** `utils/helpers/email_helper.py`

```python
"""
Email Helper Utility
Author: Your Name
Version: 1.0
"""

import imaplib
import email
from typing import Optional, List


class EmailHelper:
    """Helper for reading test emails."""

    def __init__(self, host: str, username: str, password: str):
        """
        Initialize email helper.

        Args:
            host: IMAP server host
            username: Email username
            password: Email password
        """
        self.host = host
        self.username = username
        self.password = password
        self.mail = None

    def connect(self) -> None:
        """Connect to IMAP server."""
        self.mail = imaplib.IMAP4_SSL(self.host)
        self.mail.login(self.username, self.password)
        self.mail.select("inbox")

    def get_latest_email(self, subject_contains: str) -> Optional[str]:
        """
        Get latest email with subject containing text.

        Args:
            subject_contains: Text to search in subject

        Returns:
            Email body or None if not found
        """
        if not self.mail:
            self.connect()

        # Search for emails
        _, message_numbers = self.mail.search(None, "ALL")

        for num in reversed(message_numbers[0].split()):
            _, msg = self.mail.fetch(num, "(RFC822)")
            email_body = msg[0][1]
            email_message = email.message_from_bytes(email_body)

            if subject_contains.lower() in email_message["subject"].lower():
                # Get email body
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            return part.get_payload(decode=True).decode()
                else:
                    return email_message.get_payload(decode=True).decode()

        return None

    def close(self) -> None:
        """Close connection."""
        if self.mail:
            self.mail.close()
            self.mail.logout()
```

**Fixture:**
```python
# conftest.py

@pytest.fixture(scope="session")
def email_helper():
    """Provide email verification helper."""
    helper = EmailHelper(
        host="imap.gmail.com",
        username="test@example.com",
        password="app_password"
    )

    yield helper

    helper.close()
```

**Usage:**
```python
def test_password_reset_email(signup_page, email_helper):
    """Test password reset sends email."""
    email = "test@example.com"
    signup_page.request_password_reset(email)

    # Wait and check email
    import time
    time.sleep(10)

    email_body = email_helper.get_latest_email("Password Reset")
    assert email_body is not None
    assert "reset your password" in email_body.lower()
```

---

## Creating Custom Pytest Markers

### Step 1: Define Markers

**File:** `pytest.ini`

```ini
[pytest]
markers =
    smoke: Critical smoke tests
    regression: Full regression suite
    functional: Functional tests
    security: Security tests
    accessibility: Accessibility tests
    performance: Performance tests
    api: API tests
    integration: Integration tests
    critical: Critical priority tests
    high: High priority tests
    medium: Medium priority tests
    low: Low priority tests
    wip: Work in progress tests
```

### Step 2: Use Markers in Tests

```python
import pytest


@pytest.mark.api
@pytest.mark.critical
def test_api_health_check():
    """Critical API health check."""
    response = requests.get("https://api.example.com/health")
    assert response.status_code == 200


@pytest.mark.integration
@pytest.mark.high
def test_full_user_flow():
    """High priority integration test."""
    # ... test logic
```

### Step 3: Run Tests by Marker

```bash
# Run only API tests
pytest -m api

# Run critical tests
pytest -m critical

# Combine markers
pytest -m "api and critical"

# Exclude markers
pytest -m "not slow"

# Complex expressions
pytest -m "(smoke or critical) and not wip"
```

---

## Creating Custom Reporters

### Example: Slack Notification Reporter

**File:** `utils/reporters/slack_reporter.py`

```python
"""
Slack Reporter
Sends test results to Slack channel
"""

import requests
import json
from typing import Dict, Any


class SlackReporter:
    """Report test results to Slack."""

    def __init__(self, webhook_url: str):
        """
        Initialize Slack reporter.

        Args:
            webhook_url: Slack incoming webhook URL
        """
        self.webhook_url = webhook_url

    def send_report(
        self,
        passed: int,
        failed: int,
        skipped: int,
        duration: float,
        environment: str = "test"
    ) -> None:
        """
        Send test report to Slack.

        Args:
            passed: Number of passed tests
            failed: Number of failed tests
            skipped: Number of skipped tests
            duration: Test duration in seconds
            environment: Test environment
        """
        total = passed + failed + skipped
        pass_rate = (passed / total * 100) if total > 0 else 0

        # Determine status color
        if failed == 0:
            color = "good"  # Green
            status = "✓ PASSED"
        elif failed < 5:
            color = "warning"  # Yellow
            status = "⚠ WARNING"
        else:
            color = "danger"  # Red
            status = "✗ FAILED"

        # Build message
        message = {
            "attachments": [
                {
                    "color": color,
                    "title": f"Test Report - {environment.upper()}",
                    "fields": [
                        {
                            "title": "Status",
                            "value": status,
                            "short": True
                        },
                        {
                            "title": "Pass Rate",
                            "value": f"{pass_rate:.1f}%",
                            "short": True
                        },
                        {
                            "title": "Passed",
                            "value": str(passed),
                            "short": True
                        },
                        {
                            "title": "Failed",
                            "value": str(failed),
                            "short": True
                        },
                        {
                            "title": "Skipped",
                            "value": str(skipped),
                            "short": True
                        },
                        {
                            "title": "Duration",
                            "value": f"{duration:.1f}s",
                            "short": True
                        }
                    ]
                }
            ]
        }

        # Send to Slack
        response = requests.post(
            self.webhook_url,
            data=json.dumps(message),
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 200:
            print(f"Failed to send Slack notification: {response.text}")
```

**Pytest Hook Integration:**

**File:** `conftest.py`

```python
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """Send Slack notification after test session."""
    # Get webhook from environment
    import os
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    if not webhook_url:
        return  # Skip if not configured

    # Collect statistics
    passed = len([r for r in session.items if r.passed])
    failed = len([r for r in session.items if r.failed])
    skipped = len([r for r in session.items if r.skipped])
    duration = time.time() - session.start_time

    # Send report
    from utils.reporters.slack_reporter import SlackReporter

    reporter = SlackReporter(webhook_url)
    reporter.send_report(
        passed=passed,
        failed=failed,
        skipped=skipped,
        duration=duration,
        environment=os.getenv("TEST_ENV", "test")
    )
```

**Usage:**
```bash
# Set webhook URL
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Run tests - report sent automatically
pytest tests/
```

---

## Adding New Test Types

### Example: Adding API Tests

**Step 1: Install Dependencies**
```bash
pip install requests
pip install jsonschema  # For JSON schema validation
```

**Step 2: Create API Utility**

**File:** `utils/api/api_client.py`

```python
"""
API Test Client
"""

import requests
from typing import Dict, Any, Optional


class APIClient:
    """HTTP client for API testing."""

    def __init__(self, base_url: str, default_headers: Optional[Dict] = None):
        self.base_url = base_url
        self.default_headers = default_headers or {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.session = requests.Session()

    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """GET request."""
        url = f"{self.base_url}{endpoint}"
        headers = {**self.default_headers, **kwargs.pop("headers", {})}
        return self.session.get(url, headers=headers, **kwargs)

    def post(self, endpoint: str, json: Dict = None, **kwargs) -> requests.Response:
        """POST request."""
        url = f"{self.base_url}{endpoint}"
        headers = {**self.default_headers, **kwargs.pop("headers", {})}
        return self.session.post(url, json=json, headers=headers, **kwargs)
```

**Step 3: Create Fixture**

**File:** `conftest.py`

```python
@pytest.fixture(scope="session")
def api_client():
    """Provide API client."""
    from utils.api.api_client import APIClient

    client = APIClient(
        base_url="https://api.example.com",
        default_headers={"Authorization": "Bearer test_token"}
    )

    yield client

    client.session.close()
```

**Step 4: Create API Tests**

**File:** `tests/api/test_users_api.py`

```python
"""
User API Tests
"""

import pytest


@pytest.mark.api
def test_get_users(api_client):
    """Test GET /users endpoint."""
    response = api_client.get("/users")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.api
def test_create_user(api_client):
    """Test POST /users endpoint."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com"
    }

    response = api_client.post("/users", json=user_data)

    assert response.status_code == 201
    assert response.json()["username"] == user_data["username"]
```

---

## Integrating Third-Party Tools

### Example: Integrating Allure Reports

**Step 1: Install Allure**
```bash
pip install allure-pytest
```

**Step 2: Configure Pytest**

**File:** `pytest.ini`

```ini
[pytest]
addopts =
    --alluredir=allure-results
    --clean-alluredir
```

**Step 3: Add Allure Decorators**

```python
import allure
import pytest


@allure.feature("Authentication")
@allure.story("User Login")
@allure.severity(allure.severity_level.CRITICAL)
def test_login(login_page, valid_user):
    """Test user login."""
    with allure.step("Open login modal"):
        login_page.open_login_modal()

    with allure.step("Enter credentials"):
        login_page.login(**valid_user)

    with allure.step("Verify login success"):
        assert login_page.is_user_logged_in()
```

**Step 4: Generate Report**
```bash
# Run tests
pytest tests/

# Generate HTML report
allure generate allure-results -o allure-report --clean

# Open report
allure open allure-report
```

---

## Best Practices for Extensions

1. **Follow framework conventions:**
   - Use type hints
   - Add docstrings
   - Follow naming patterns
   - Log actions

2. **Keep utilities universal:**
   - Avoid application-specific code in base classes
   - Make utilities reusable
   - Use dependency injection

3. **Document extensions:**
   - Add docstrings
   - Include examples
   - Update README if significant

4. **Test your extensions:**
   - Create unit tests for utilities
   - Test new fixtures
   - Verify backward compatibility

5. **Consider performance:**
   - Avoid unnecessary waits
   - Use appropriate fixture scopes
   - Cache expensive operations

---

## Related Documentation

- [API Reference](../api-reference/README.md) - Understand existing components
- [Code Walkthrough](code-walkthrough.md) - Understand execution flow
- [Test Fixtures Guide](test-fixtures.md) - Fixture patterns
