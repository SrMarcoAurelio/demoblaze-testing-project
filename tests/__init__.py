"""
Universal Test Automation Framework - Test Suite
Author: Arévalo, Marc
Version: 6.2.0

Test Organization:
- unit/: Framework unit tests (utilities, helpers, core modules)
- framework/: Framework feature tests (auto-config, security, performance)
- examples/: Example tests demonstrating framework capabilities
  - api/: API testing examples
  - database/: Database testing examples

Test Types (Markers):
- @pytest.mark.unit: Unit tests (no browser required)
- @pytest.mark.functional: Functional/integration tests
- @pytest.mark.security: Security and vulnerability tests
- @pytest.mark.api: API testing examples
- @pytest.mark.database: Database testing examples

Note: This is a UNIVERSAL framework. Application-specific tests
should be placed in tests/ root directory (not in subdirectories).
"""
