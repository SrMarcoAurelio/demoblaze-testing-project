"""
HTTP Interceptor
Captures and analyzes HTTP traffic for security testing.

Author: Marc Arévalo
Version: 1.0
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """Represents an HTTP request."""

    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""

    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPTransaction:
    """Represents a complete HTTP request-response transaction."""

    request: HTTPRequest
    response: HTTPResponse
    test_type: str = "unknown"
    payload_used: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "test_type": self.test_type,
            "payload_used": self.payload_used,
        }


class HTTPInterceptor:
    """
    Intercepts and captures HTTP traffic using Selenium wire.

    Captures all HTTP requests and responses during test execution
    for security analysis.
    """

    def __init__(self):
        """Initialize HTTP interceptor."""
        self.transactions: List[HTTPTransaction] = []
        self.enabled = False

    def start(self) -> None:
        """Start capturing HTTP traffic."""
        self.enabled = True
        self.transactions = []
        logger.info("HTTP interceptor started")

    def stop(self) -> None:
        """Stop capturing HTTP traffic."""
        self.enabled = False
        logger.info(
            f"HTTP interceptor stopped. Captured {len(self.transactions)} transactions"
        )

    def capture_from_driver(
        self, driver, test_type: str = "unknown", payload: Optional[str] = None
    ) -> None:
        """
        Capture HTTP traffic from Selenium WebDriver.

        Args:
            driver: Selenium WebDriver instance with wire enabled
            test_type: Type of test being performed
            payload: Payload used in request (if applicable)
        """
        if not self.enabled:
            return

        try:
            # Get requests from selenium-wire
            if hasattr(driver, "requests"):
                for request in driver.requests:
                    if request.response:
                        # Build request object
                        http_request = HTTPRequest(
                            method=request.method,
                            url=request.url,
                            headers=dict(request.headers),
                            body=(
                                request.body.decode("utf-8")
                                if request.body
                                else None
                            ),
                        )

                        # Build response object
                        http_response = HTTPResponse(
                            status_code=request.response.status_code,
                            headers=dict(request.response.headers),
                            body=(
                                request.response.body.decode(
                                    "utf-8", errors="ignore"
                                )
                                if request.response.body
                                else ""
                            ),
                            elapsed_ms=(
                                request.response.time * 1000
                                if hasattr(request.response, "time")
                                else 0
                            ),
                        )

                        # Create transaction
                        transaction = HTTPTransaction(
                            request=http_request,
                            response=http_response,
                            test_type=test_type,
                            payload_used=payload,
                        )

                        self.transactions.append(transaction)

                # Clear requests to avoid memory issues
                del driver.requests

        except Exception as e:
            logger.warning(f"Error capturing HTTP traffic: {e}")

    def get_transactions(
        self, test_type: Optional[str] = None
    ) -> List[HTTPTransaction]:
        """
        Get captured transactions.

        Args:
            test_type: Filter by test type (optional)

        Returns:
            List of HTTP transactions
        """
        if test_type:
            return [t for t in self.transactions if t.test_type == test_type]
        return self.transactions

    def get_responses_with_status(
        self, status_code: int
    ) -> List[HTTPResponse]:
        """
        Get all responses with specific status code.

        Args:
            status_code: HTTP status code

        Returns:
            List of responses
        """
        return [
            t.response
            for t in self.transactions
            if t.response.status_code == status_code
        ]

    def get_error_responses(self) -> List[HTTPTransaction]:
        """
        Get transactions with error responses (4xx, 5xx).

        Returns:
            List of error transactions
        """
        return [t for t in self.transactions if t.response.status_code >= 400]

    def clear(self) -> None:
        """Clear all captured transactions."""
        self.transactions = []
        logger.debug("HTTP interceptor transactions cleared")

    def save_to_file(self, filepath: str) -> None:
        """
        Save captured transactions to JSON file.

        Args:
            filepath: Output file path
        """
        from pathlib import Path

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        data = {
            "total_transactions": len(self.transactions),
            "transactions": [t.to_dict() for t in self.transactions],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(
            f"Saved {len(self.transactions)} transactions to {filepath}"
        )

    def __len__(self) -> int:
        """Return number of captured transactions."""
        return len(self.transactions)
