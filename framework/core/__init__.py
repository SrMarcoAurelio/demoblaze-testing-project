"""
Universal Test Automation Framework - Core Components
Author: Marc Arevalo
Version: 1.0

Core universal components for test automation.
Import from here for convenience.
"""

from .discovery_engine import DiscoveryEngine
from .element_finder import ElementFinder
from .element_interactor import ElementInteractor
from .wait_handler import WaitHandler

__all__ = [
    "DiscoveryEngine",
    "ElementFinder",
    "ElementInteractor",
    "WaitHandler",
]
