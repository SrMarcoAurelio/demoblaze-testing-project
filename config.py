"""
Project Configuration - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 2.0

Centralized configuration management for all test components.
All configuration values can be overridden via environment variables.
"""

import os
from dataclasses import dataclass
from typing import Dict


@dataclass
class Config:
    """
    Centralized configuration for the test automation framework.

    All values can be overridden using environment variables.
    Example: export BASE_URL="https://staging.demoblaze.com"
    """

    BASE_URL: str = os.getenv('BASE_URL', 'https://www.demoblaze.com/')

    TIMEOUT_DEFAULT: int = int(os.getenv('TIMEOUT_DEFAULT', '10'))
    TIMEOUT_SHORT: int = int(os.getenv('TIMEOUT_SHORT', '5'))
    TIMEOUT_MEDIUM: int = int(os.getenv('TIMEOUT_MEDIUM', '15'))
    TIMEOUT_LONG: int = int(os.getenv('TIMEOUT_LONG', '30'))

    HEADLESS: bool = os.getenv('HEADLESS', 'false').lower() == 'true'
    BROWSER: str = os.getenv('BROWSER', 'chrome').lower()

    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO').upper()

    REPORTS_ROOT: str = os.getenv('REPORTS_ROOT', 'results')
    SCREENSHOTS_DIR: str = os.getenv('SCREENSHOTS_DIR', 'results/screenshots')

    SLOW_MODE_DELAY: float = float(os.getenv('SLOW_MODE_DELAY', '0'))

    def get_timeout_config(self) -> Dict[str, int]:
        """
        Get all timeout configurations as dictionary.

        Returns:
            Dict with timeout values
        """
        return {
            'default': self.TIMEOUT_DEFAULT,
            'short': self.TIMEOUT_SHORT,
            'medium': self.TIMEOUT_MEDIUM,
            'long': self.TIMEOUT_LONG
        }

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


config = Config()


if __name__ == '__main__':
    print("=" * 70)
    print("DEMOBLAZE TEST AUTOMATION - CONFIGURATION")
    print("=" * 70)
    print(f"\nBase URL: {config.BASE_URL}")
    print(f"Browser: {config.BROWSER}")
    print(f"Headless Mode: {config.HEADLESS}")
    print(f"Default Timeout: {config.TIMEOUT_DEFAULT}s")
    print(f"Log Level: {config.LOG_LEVEL}")
    print(f"Reports Directory: {config.REPORTS_ROOT}")
    print(f"\nTimeouts: {config.get_timeout_config()}")
    print("\n" + "=" * 70)
    print("To override: export BASE_URL='your_url'")
    print("=" * 70)
