"""
Project Configuration - Universal Test Automation Framework
Author: Marc Arevalo
Version: 6.0

Centralized configuration management for all test components.
All configuration values MUST be provided via environment variables.
Universal and reusable across any web application.
"""

import os
from dataclasses import dataclass
from typing import Dict


@dataclass
class Config:
    """
    Centralized configuration for the universal test automation framework.

    All values MUST be provided using environment variables.
    NO defaults are provided for application-specific values.

    Required Environment Variables:
        BASE_URL: Base URL of the application under test

    Optional Environment Variables:
        TIMEOUT_DEFAULT: Default explicit wait timeout (default: 10)
        TIMEOUT_SHORT: Short timeout for quick operations (default: 5)
        TIMEOUT_MEDIUM: Medium timeout (default: 15)
        TIMEOUT_LONG: Long timeout for slow operations (default: 30)
        HEADLESS: Run browser in headless mode (default: false)
        BROWSER: Browser to use (chrome/firefox/edge) (default: chrome)
        LOG_LEVEL: Logging level (DEBUG/INFO/WARNING/ERROR) (default: INFO)
        REPORTS_ROOT: Root directory for reports (default: results)
        SCREENSHOTS_DIR: Directory for screenshots (default: results/screenshots)
        SLOW_MODE_DELAY: Delay between actions for debugging (default: 0)

    Example:
        export BASE_URL="https://your-app.com"
        export BROWSER="firefox"
        export HEADLESS="true"
    """

    # REQUIRED: Must be set by user
    BASE_URL: str = os.getenv("BASE_URL", "")

    # Timeouts (seconds)
    TIMEOUT_DEFAULT: int = int(os.getenv("TIMEOUT_DEFAULT", "10"))
    TIMEOUT_SHORT: int = int(os.getenv("TIMEOUT_SHORT", "5"))
    TIMEOUT_MEDIUM: int = int(os.getenv("TIMEOUT_MEDIUM", "15"))
    TIMEOUT_LONG: int = int(os.getenv("TIMEOUT_LONG", "30"))

    # Browser configuration
    HEADLESS: bool = os.getenv("HEADLESS", "false").lower() == "true"
    BROWSER: str = os.getenv("BROWSER", "chrome").lower()

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # Reports
    REPORTS_ROOT: str = os.getenv("REPORTS_ROOT", "results")
    SCREENSHOTS_DIR: str = os.getenv("SCREENSHOTS_DIR", "results/screenshots")

    # Debugging
    SLOW_MODE_DELAY: float = float(os.getenv("SLOW_MODE_DELAY", "0"))

    def get_timeout_config(self) -> Dict[str, int]:
        """
        Get all timeout configurations as dictionary.

        Returns:
            Dict with timeout values
        """
        return {
            "default": self.TIMEOUT_DEFAULT,
            "short": self.TIMEOUT_SHORT,
            "medium": self.TIMEOUT_MEDIUM,
            "long": self.TIMEOUT_LONG,
        }

    def validate(self) -> None:
        """
        Validate that all required configuration is provided.

        Raises:
            ValueError: If required configuration is missing
        """
        if not self.BASE_URL:
            raise ValueError(
                "BASE_URL is required. Set it via environment variable: "
                "export BASE_URL='https://your-app.com'"
            )

        if self.BROWSER not in ["chrome", "firefox", "edge", "safari"]:
            raise ValueError(
                f"Unsupported browser: {self.BROWSER}. "
                f"Supported browsers: chrome, firefox, edge, safari"
            )

    def __str__(self) -> str:
        """String representation for logging."""
        return (
            f"Config("
            f"BASE_URL={self.BASE_URL}, "
            f"BROWSER={self.BROWSER}, "
            f"HEADLESS={self.HEADLESS}, "
            f"TIMEOUT={self.TIMEOUT_DEFAULT}"
            f")"
        )


# Global configuration instance
config = Config()


if __name__ == "__main__":
    print("=" * 70)
    print("UNIVERSAL TEST AUTOMATION FRAMEWORK - CONFIGURATION")
    print("=" * 70)
    print(f"\nBase URL: {config.BASE_URL or '(NOT SET - REQUIRED)'}")
    print(f"Browser: {config.BROWSER}")
    print(f"Headless Mode: {config.HEADLESS}")
    print(f"Default Timeout: {config.TIMEOUT_DEFAULT}s")
    print(f"Log Level: {config.LOG_LEVEL}")
    print(f"Reports Directory: {config.REPORTS_ROOT}")
    print(f"\nTimeouts: {config.get_timeout_config()}")
    print("\n" + "=" * 70)
    print("REQUIRED: Set BASE_URL environment variable")
    print("Example: export BASE_URL='https://your-app.com'")
    print("=" * 70)
    print("\nUniversal framework - Adapt to any web application")
    print("=" * 70)

    # Validate configuration
    try:
        config.validate()
        print("\n✓ Configuration is valid")
    except ValueError as e:
        print(f"\n✗ Configuration error: {e}")
