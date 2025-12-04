"""
Real Security Testing System
Advanced vulnerability detection with HTTP interception and response analysis.

Author: Marc Arévalo
Version: 1.0
"""

from .http_interceptor import HTTPInterceptor
from .payload_library import PayloadLibrary
from .response_analyzer import ResponseAnalyzer, VulnerabilityDetection
from .security_report import SecurityReport, SecurityReportGenerator
from .vulnerability_scanner import VulnerabilityScanner

__all__ = [
    "HTTPInterceptor",
    "PayloadLibrary",
    "ResponseAnalyzer",
    "VulnerabilityDetection",
    "SecurityReport",
    "SecurityReportGenerator",
    "VulnerabilityScanner",
]
