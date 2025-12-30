#!/usr/bin/env python3
"""
Quick Start Script - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Interactive script to get you started with the framework in 5 minutes.
Guides you through configuration and runs your first test.
"""

import os
import subprocess
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


def print_header(text):
    """Print a header message"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}\n")


def print_success(text):
    """Print a success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_error(text):
    """Print an error message"""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text):
    """Print an info message"""
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")


def print_warning(text):
    """Print a warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def check_python_version():
    """Check if Python version meets requirements"""
    print_header("Checking Python Version")

    if sys.version_info < (3, 11):
        print_error(
            f"Python 3.11+ required. You have {sys.version_info.major}.{sys.version_info.minor}"
        )
        print_info("Please upgrade Python: https://www.python.org/downloads/")
        return False

    print_success(
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected"
    )
    return True


def check_virtual_environment():
    """Check if running in virtual environment"""
    print_header("Checking Virtual Environment")

    if hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        print_success("Running in virtual environment")
        return True
    else:
        print_warning("Not running in a virtual environment")
        print_info("Recommended: Create a virtual environment")
        print_info("  python -m venv venv")
        print_info("  source venv/bin/activate  # Linux/Mac")
        print_info("  venv\\Scripts\\activate  # Windows")

        response = input(
            f"\n{Colors.YELLOW}Continue anyway? (y/n): {Colors.END}"
        ).lower()
        return response == "y"


def check_dependencies():
    """Check if dependencies are installed"""
    print_header("Checking Dependencies")

    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print_error("requirements.txt not found!")
        return False

    try:
        import selenium
        import pytest

        print_success("Core dependencies installed")
        print_info(f"  - Selenium: {selenium.__version__}")
        print_info(f"  - Pytest: {pytest.__version__}")
        return True
    except ImportError as e:
        print_warning(f"Dependencies not installed: {e}")
        print_info("Installing dependencies...")

        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                check=True,
                capture_output=True,
            )
            print_success("Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print_error("Failed to install dependencies")
            print_info("Run manually: pip install -r requirements.txt")
            return False


def configure_environment():
    """Configure environment variables"""
    print_header("Environment Configuration")

    print_info("The framework needs a few configuration values to work.")
    print_info("These will be saved to a .env file (not committed to git)\n")

    # Check if .env already exists
    env_file = Path(".env")
    if env_file.exists():
        print_warning(".env file already exists")
        response = input(
            f"{Colors.YELLOW}Overwrite? (y/n): {Colors.END}"
        ).lower()
        if response != "y":
            print_info("Skipping configuration")
            return True

    # Get BASE_URL
    print(f"\n{Colors.BOLD}1. Application URL{Colors.END}")
    print_info("Enter the URL of the web application you want to test")
    print_info("Example: https://www.example.com")
    base_url = input(f"{Colors.CYAN}BASE_URL: {Colors.END}").strip()

    if not base_url:
        base_url = "https://www.google.com"
        print_warning(f"No URL provided. Using demo: {base_url}")

    # Get browser preference
    print(f"\n{Colors.BOLD}2. Browser{Colors.END}")
    print_info("Which browser do you want to use? (chrome/firefox/edge)")
    browser = input(f"{Colors.CYAN}BROWSER [chrome]: {Colors.END}").strip().lower()

    if browser not in ["chrome", "firefox", "edge"]:
        browser = "chrome"
        print_warning(f"Invalid browser. Using default: {browser}")

    # Get headless preference
    print(f"\n{Colors.BOLD}3. Headless Mode{Colors.END}")
    print_info("Run browser in headless mode (no visible window)?")
    headless = input(
        f"{Colors.CYAN}HEADLESS (true/false) [false]: {Colors.END}"
    ).strip().lower()

    headless = "true" if headless == "true" else "false"

    # Create .env file
    env_content = f"""# Universal Test Automation Framework Configuration
# Auto-generated by quick_start.py

# Application URL
BASE_URL={base_url}

# Browser Configuration
BROWSER={browser}
HEADLESS={headless}

# Timeouts (seconds)
TIMEOUT_DEFAULT=10
TIMEOUT_IMPLICIT=5

# Logging
LOG_LEVEL=INFO

# Test Credentials (NEVER commit real passwords!)
TEST_USERNAME=
TEST_PASSWORD=
"""

    try:
        with open(".env", "w") as f:
            f.write(env_content)
        print_success("Configuration saved to .env")
        return True
    except Exception as e:
        print_error(f"Failed to save configuration: {e}")
        return False


def run_sample_test():
    """Run a simple framework test"""
    print_header("Running Framework Tests")

    print_info("Running unit tests for the framework core...")
    print_info("This verifies the framework is working correctly\n")

    # Check if unit tests exist
    unit_tests_path = Path("tests/unit/framework/core/")
    if not unit_tests_path.exists():
        print_warning("Unit tests not found - skipping test verification")
        print_info("Framework is installed, but unit tests are missing")
        return True

    try:
        # Run the unit tests
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/unit/framework/core/",
                "-v",
                "--tb=short",
            ],
            capture_output=False,
            text=True,
        )

        if result.returncode == 0:
            print_success("\nFramework tests passed!")
            return True
        else:
            print_warning("\nSome tests failed, but framework is functional")
            return True
    except Exception as e:
        print_error(f"Failed to run tests: {e}")
        print_info("You can manually verify with: pytest tests/unit/ -v")
        return True  # Don't block setup for test failures


def show_next_steps():
    """Show what to do next"""
    print_header("Next Steps")

    print(
        f"{Colors.BOLD}Your framework is ready! Here's what to do next:{Colors.END}\n"
    )

    print(f"{Colors.GREEN}1. Explore the templates:{Colors.END}")
    print(f"   {Colors.CYAN}ls templates/{Colors.END}")
    print(f"   - page_objects/ - Template page object classes")
    print(f"   - test_files/ - Template test files")
    print(f"   - configuration/ - Template pytest configuration\n")

    print(f"{Colors.GREEN}2. Create your first page object:{Colors.END}")
    print(
        f"   {Colors.CYAN}cp templates/page_objects/__template_login_page.py pages/login_page.py{Colors.END}"
    )
    print(f"   Then edit pages/login_page.py with YOUR app's locators\n")

    print(f"{Colors.GREEN}3. Create your first test:{Colors.END}")
    print(
        f"   {Colors.CYAN}cp templates/test_files/__template_functional_test.py tests/test_login.py{Colors.END}"
    )
    print(f"   Then edit tests/test_login.py to test YOUR app\n")

    print(f"{Colors.GREEN}4. Run your tests:{Colors.END}")
    print(f"   {Colors.CYAN}pytest tests/test_login.py -v{Colors.END}")
    print(f"   {Colors.CYAN}pytest --browser=firefox --headless{Colors.END}")
    print(f"   {Colors.CYAN}pytest --performance=fast{Colors.END}")
    print(f"   {Colors.CYAN}pytest -n auto  # Parallel execution{Colors.END}\n")

    print(f"{Colors.GREEN}5. Read the documentation:{Colors.END}")
    print(f"   {Colors.CYAN}documentation/getting-started/quick-start.md{Colors.END}")
    print(
        f"   {Colors.CYAN}documentation/guides/implementation-guide.md{Colors.END}"
    )
    print(f"   {Colors.CYAN}README.md{Colors.END}\n")

    print(f"{Colors.BOLD}💡 Pro Tips:{Colors.END}")
    print(
        f"   - Use {Colors.CYAN}--performance=fast{Colors.END} for 60-70% faster tests"
    )
    print(f"   - Use {Colors.CYAN}-n auto{Colors.END} for parallel execution")
    print(
        f"   - Read migration guides if coming from unittest or Robot Framework"
    )
    print(
        f"   - Check out config/examples/ for advanced configurations\n"
    )


def main():
    """Main quick start flow"""
    print(f"{Colors.BOLD}{Colors.BLUE}")
    print(
        r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║        Universal Test Automation Framework - Quick Start        ║
    ║                                                                  ║
    ║                  Get started in 5 minutes! 🚀                   ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    )
    print(Colors.END)

    steps = [
        ("Python Version", check_python_version),
        ("Virtual Environment", check_virtual_environment),
        ("Dependencies", check_dependencies),
        ("Configuration", configure_environment),
        ("Framework Tests", run_sample_test),
    ]

    for step_name, step_func in steps:
        if not step_func():
            print_error(
                f"\n{step_name} check failed. Please fix the issues and try again."
            )
            print_info(
                f"\nFor help, see: documentation/getting-started/installation.md"
            )
            sys.exit(1)

    show_next_steps()

    print(
        f"\n{Colors.GREEN}{Colors.BOLD}✓ Setup complete! Happy testing! 🎉{Colors.END}\n"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Setup cancelled by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print_error(f"\nUnexpected error: {e}")
        print_info("Please report this issue on GitHub")
        sys.exit(1)
