"""
Demoblaze Example - Pytest Configuration

This conftest.py is SPECIFIC to the Demoblaze example application.

DO NOT copy this to your project. Create your own conftest.py
adapted to YOUR application.
"""

import os

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Example-specific BASE_URL
DEMOBLAZE_BASE_URL = "https://www.demoblaze.com/"


@pytest.fixture(scope="session")
def base_url():
    """
    EXAMPLE: Base URL for Demoblaze

    Replace with YOUR application URL.
    """
    return os.getenv("BASE_URL", DEMOBLAZE_BASE_URL)


@pytest.fixture(scope="function")
def browser(request):
    """
    EXAMPLE: Browser fixture for Demoblaze tests

    Adapt to YOUR needs (different browsers, options, etc.)
    """
    options = Options()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Headless mode for CI/CD
    if os.getenv("HEADLESS", "false").lower() == "true":
        options.add_argument("--headless")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.maximize_window()

    yield driver

    driver.quit()


@pytest.fixture(scope="session")
def valid_user():
    """
    EXAMPLE: Valid user credentials for Demoblaze

    Replace with YOUR test user data.
    """
    return {
        "username": os.getenv("TEST_USERNAME", "Apolo2025"),
        "password": os.getenv("TEST_PASSWORD", "apolo2025"),
    }
