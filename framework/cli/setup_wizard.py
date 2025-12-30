#!/usr/bin/env python3
"""
Setup Wizard - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Interactive setup wizard for framework configuration.
More advanced than quick_start.py - allows choosing specific features.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional


class Colors:
    """ANSI color codes"""

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_header(text: str) -> None:
    """Print colored header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}\n")


def print_success(text: str) -> None:
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_error(text: str) -> None:
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text: str) -> None:
    """Print info message"""
    print(f"{Colors.CYAN}ℹ {text}{Colors.END}")


def ask_yes_no(question: str, default: bool = True) -> bool:
    """Ask yes/no question"""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{Colors.YELLOW}{question} ({default_str}): {Colors.END}").lower()

    if not response:
        return default
    return response in ["y", "yes", "1", "true"]


def ask_choice(question: str, choices: List[str], default: int = 0) -> str:
    """Ask for choice from list"""
    print(f"\n{Colors.BOLD}{question}{Colors.END}")
    for i, choice in enumerate(choices, 1):
        marker = "→" if i - 1 == default else " "
        print(f"  {marker} {i}. {choice}")

    while True:
        response = input(
            f"{Colors.YELLOW}Choose (1-{len(choices)}) [{default + 1}]: {Colors.END}"
        )

        if not response:
            return choices[default]

        try:
            index = int(response) - 1
            if 0 <= index < len(choices):
                return choices[index]
        except ValueError:
            pass

        print_error(f"Invalid choice. Enter 1-{len(choices)}")


def configure_basic_settings() -> Dict[str, str]:
    """Configure basic framework settings"""
    print_header("Basic Configuration")

    settings = {}

    # Application URL
    print(f"\n{Colors.BOLD}1. Application URL{Colors.END}")
    print_info("Enter the URL of the application you want to test")
    print_info("Examples: https://app.example.com, http://localhost:3000")

    url = input(f"{Colors.CYAN}BASE_URL: {Colors.END}").strip()
    settings["BASE_URL"] = url if url else "https://www.google.com"

    # Browser
    print(f"\n{Colors.BOLD}2. Default Browser{Colors.END}")
    browser = ask_choice(
        "Which browser?", ["chrome", "firefox", "edge"], default=0
    )
    settings["BROWSER"] = browser

    # Headless
    print(f"\n{Colors.BOLD}3. Headless Mode{Colors.END}")
    headless = ask_yes_no("Run browser in headless mode?", default=False)
    settings["HEADLESS"] = "true" if headless else "false"

    # Timeouts
    print(f"\n{Colors.BOLD}4. Timeouts{Colors.END}")
    print_info("Default timeout for waits (seconds)")
    timeout = input(f"{Colors.CYAN}TIMEOUT_DEFAULT [10]: {Colors.END}").strip()
    settings["TIMEOUT_DEFAULT"] = timeout if timeout else "10"

    # Log level
    print(f"\n{Colors.BOLD}5. Logging{Colors.END}")
    log_level = ask_choice(
        "Log verbosity?", ["DEBUG", "INFO", "WARNING", "ERROR"], default=1
    )
    settings["LOG_LEVEL"] = log_level

    return settings


def configure_advanced_settings() -> Dict[str, str]:
    """Configure advanced settings"""
    print_header("Advanced Configuration")

    settings = {}

    # Selenium Grid
    use_grid = ask_yes_no("Use Selenium Grid?", default=False)
    if use_grid:
        grid_url = input(
            f"{Colors.CYAN}SELENIUM_HUB_URL [http://localhost:4444/wd/hub]: {Colors.END}"
        ).strip()
        settings["SELENIUM_HUB_URL"] = (
            grid_url if grid_url else "http://localhost:4444/wd/hub"
        )

    # Performance thresholds
    configure_perf = ask_yes_no("Configure performance thresholds?", default=False)
    if configure_perf:
        page_load = input(
            f"{Colors.CYAN}PERF_PAGE_LOAD_THRESHOLD (seconds) [5.0]: {Colors.END}"
        ).strip()
        settings["PERF_PAGE_LOAD_THRESHOLD"] = page_load if page_load else "5.0"

        action = input(
            f"{Colors.CYAN}PERF_ACTION_THRESHOLD (seconds) [2.0]: {Colors.END}"
        ).strip()
        settings["PERF_ACTION_THRESHOLD"] = action if action else "2.0"

    # Parallel execution
    parallel = ask_yes_no("Enable parallel execution by default?", default=True)
    if parallel:
        workers = input(
            f"{Colors.CYAN}Number of parallel workers [auto]: {Colors.END}"
        ).strip()
        settings["PYTEST_XDIST_WORKERS"] = workers if workers else "auto"

    return settings


def generate_env_file(basic: Dict[str, str], advanced: Dict[str, str]) -> None:
    """Generate .env file"""
    print_header("Generating Configuration")

    env_content = f"""# Universal Test Automation Framework Configuration
# Generated by setup wizard

# ============================================================================
# BASIC CONFIGURATION
# ============================================================================

# Application URL
BASE_URL={basic.get('BASE_URL', 'https://www.example.com')}

# Browser Configuration
BROWSER={basic.get('BROWSER', 'chrome')}
HEADLESS={basic.get('HEADLESS', 'false')}

# Timeouts (seconds)
TIMEOUT_DEFAULT={basic.get('TIMEOUT_DEFAULT', '10')}
TIMEOUT_IMPLICIT=5

# Logging
LOG_LEVEL={basic.get('LOG_LEVEL', 'INFO')}

# ============================================================================
# TEST CREDENTIALS
# ============================================================================

# SECURITY: Never commit real credentials to version control!
TEST_USERNAME=
TEST_PASSWORD=

# ============================================================================
# ADVANCED CONFIGURATION
# ============================================================================

"""

    # Add advanced settings if configured
    if advanced:
        if "SELENIUM_HUB_URL" in advanced:
            env_content += f"""# Selenium Grid
SELENIUM_HUB_URL={advanced['SELENIUM_HUB_URL']}

"""

        if "PERF_PAGE_LOAD_THRESHOLD" in advanced:
            env_content += f"""# Performance Thresholds
PERF_PAGE_LOAD_THRESHOLD={advanced['PERF_PAGE_LOAD_THRESHOLD']}
PERF_ACTION_THRESHOLD={advanced.get('PERF_ACTION_THRESHOLD', '2.0')}

"""

        if "PYTEST_XDIST_WORKERS" in advanced:
            env_content += f"""# Parallel Execution
PYTEST_XDIST_WORKERS={advanced['PYTEST_XDIST_WORKERS']}

"""

    env_content += """# ============================================================================
# ENVIRONMENT-SPECIFIC OVERRIDES
# ============================================================================

# Uncomment and set for specific environments:
# TEST_ENV=development  # Options: development, staging, production
# READ_ONLY_MODE=false  # Set true for production testing
"""

    # Write .env file
    try:
        with open(".env", "w") as f:
            f.write(env_content)
        print_success("Configuration saved to .env")
        return True
    except Exception as e:
        print_error(f"Failed to save configuration: {e}")
        return False


def show_next_steps() -> None:
    """Show next steps after setup"""
    print_header("Setup Complete!")

    print(f"{Colors.GREEN}{Colors.BOLD}✓ Framework configured successfully!{Colors.END}\n")

    print(f"{Colors.BOLD}Next Steps:{Colors.END}\n")

    print(f"{Colors.CYAN}1. Set test credentials:{Colors.END}")
    print(f"   Edit .env and set TEST_USERNAME and TEST_PASSWORD\n")

    print(f"{Colors.CYAN}2. Create your first page object:{Colors.END}")
    print(f"   cp templates/page_objects/__template_login_page.py pages/login_page.py")
    print(f"   # Edit pages/login_page.py with YOUR app's locators\n")

    print(f"{Colors.CYAN}3. Create your first test:{Colors.END}")
    print(
        f"   cp templates/test_files/__template_functional_test.py tests/test_login.py"
    )
    print(f"   # Edit tests/test_login.py to test YOUR app\n")

    print(f"{Colors.CYAN}4. Run your tests:{Colors.END}")
    print(f"   pytest tests/test_login.py -v\n")

    print(f"{Colors.BOLD}Documentation:{Colors.END}")
    print(f"   documentation/getting-started/quick-start.md")
    print(f"   documentation/guides/implementation-guide.md")


def main():
    """Main setup wizard flow"""
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print(
        r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║          Universal Test Automation Framework - Setup            ║
    ║                                                                  ║
    ║                     Interactive Configuration                    ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    )
    print(Colors.END)

    print_info("This wizard will help you configure the framework for your needs.\n")

    # Basic configuration
    basic_settings = configure_basic_settings()

    # Ask for advanced configuration
    configure_advanced = ask_yes_no(
        "\nConfigure advanced settings (Grid, performance, etc.)?", default=False
    )

    advanced_settings = {}
    if configure_advanced:
        advanced_settings = configure_advanced_settings()

    # Generate .env file
    success = generate_env_file(basic_settings, advanced_settings)

    if success:
        show_next_steps()
    else:
        print_error("\nSetup failed. Please check errors above.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Setup cancelled by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print_error(f"\nUnexpected error: {e}")
        sys.exit(1)
