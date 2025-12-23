"""
Universal Functional Test Template

INSTRUCTIONS:
1. Copy this file to your tests/ directory
2. Rename it to: test_YOUR_FEATURE_functional.py
3. Replace ALL_CAPS placeholders with YOUR test logic
4. Remove pytest.skip() decorators when ready to use
5. Adapt fixtures to YOUR application's needs

Example test structure:
- test_valid_scenario: Tests expected/happy path
- test_invalid_scenario: Tests error handling
- test_edge_case: Tests boundary conditions

Pytest markers:
- @pytest.mark.functional: Marks test as functional test
- @pytest.mark.smoke: Marks critical tests for smoke testing
- @pytest.mark.regression: Marks tests for regression suite
"""

import pytest

from pages.YOUR_PAGE import YourPage  # Replace with YOUR page object

# MARK THIS FILE WITH PYTEST MARKERS
pytestmark = [
    pytest.mark.functional,  # This is a functional test
    # pytest.mark.smoke,  # Uncomment if this is a smoke test
]


class TestYourFeature:
    """
    Functional tests for YOUR_FEATURE.

    Replace this docstring with description of what feature you're testing.

    Test coverage:
    - Valid scenarios
    - Invalid scenarios
    - Edge cases
    - Error handling
    """

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_valid_scenario_success(self, browser, base_url):
        """
        Test YOUR_FEATURE with valid data succeeds.

        Steps:
        1. Navigate to YOUR page
        2. Perform YOUR action with valid data
        3. Verify expected result

        Expected result:
        - YOUR expected outcome

        Replace this entire test with YOUR actual test logic.
        """
        # Arrange - Set up test data
        page = YourPage(browser, base_url)
        test_data = {
            "field1": "valid_value",  # Replace with YOUR test data
            "field2": "valid_value",
        }

        # Act - Perform the action being tested
        page.navigate()
        result = page.perform_action(test_data)  # Replace with YOUR action

        # Assert - Verify expected outcome
        assert result is True, "Expected action to succeed"
        assert page.is_success_visible(), "Success indicator not visible"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_invalid_data_shows_error(self, browser, base_url):
        """
        Test YOUR_FEATURE with invalid data shows appropriate error.

        Steps:
        1. Navigate to YOUR page
        2. Perform YOUR action with invalid data
        3. Verify error message is displayed

        Expected result:
        - Error message: "YOUR expected error message"

        Replace this entire test with YOUR actual test logic.
        """
        # Arrange
        page = YourPage(browser, base_url)
        invalid_data = {
            "field1": "",  # Replace with YOUR invalid test data
            "field2": "invalid",
        }

        # Act
        page.navigate()
        result = page.perform_action(invalid_data)

        # Assert
        assert result is False, "Expected action to fail with invalid data"
        error = page.get_error_message()
        assert (
            "error" in error.lower()
        ), f"Expected error message, got: {error}"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_edge_case_boundary_value(self, browser, base_url):
        """
        Test YOUR_FEATURE with boundary/edge case values.

        Steps:
        1. Navigate to YOUR page
        2. Perform YOUR action with edge case data
        3. Verify appropriate handling

        Expected result:
        - YOUR expected behavior for edge cases

        Examples of edge cases:
        - Empty strings
        - Maximum length inputs
        - Special characters
        - Null/None values
        - Very large numbers
        - Very small numbers

        Replace this entire test with YOUR actual test logic.
        """
        # Arrange
        page = YourPage(browser, base_url)
        edge_case_data = {
            "field1": "a" * 1000,  # Replace with YOUR edge case
            "field2": "",
        }

        # Act
        page.navigate()
        result = page.perform_action(edge_case_data)

        # Assert
        # Adapt assertions to YOUR expected behavior
        assert result is not None, "Expected some result"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    @pytest.mark.parametrize(
        "test_input,expected",
        [
            ("valid_input_1", True),
            ("valid_input_2", True),
            ("invalid_input", False),
        ],
    )
    def test_multiple_scenarios_parametrized(
        self, browser, base_url, test_input, expected
    ):
        """
        Test YOUR_FEATURE with multiple input scenarios.

        This is a parametrized test - it runs multiple times with different inputs.

        Args:
            test_input: Input value to test
            expected: Expected result (True/False)

        Replace parameters with YOUR test scenarios.
        """
        # Arrange
        page = YourPage(browser, base_url)

        # Act
        page.navigate()
        result = page.perform_action(test_input)

        # Assert
        assert (
            result == expected
        ), f"For input '{test_input}', expected {expected}, got {result}"


# ADAPTATION CHECKLIST:
# [ ] Copied to tests/YOUR_FEATURE/test_YOUR_FEATURE_functional.py
# [ ] Renamed class to TestYourActualFeature
# [ ] Removed @pytest.mark.skip() decorators
# [ ] Imported YOUR actual page objects
# [ ] Replaced test_data with YOUR actual test data
# [ ] Replaced assertions with YOUR expected results
# [ ] Added YOUR application-specific test cases
# [ ] Verified tests pass with YOUR application
# [ ] Added appropriate pytest markers
# [ ] Updated docstrings with YOUR test documentation
# [ ] Removed this checklist when done
