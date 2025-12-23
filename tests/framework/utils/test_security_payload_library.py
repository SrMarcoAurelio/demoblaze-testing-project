"""
Security Payload Library Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for PayloadLibrary:
- Payload dataclass
- Getting payloads by category
- Payload categories
- Payload counts
- Payload structure validation
"""

import pytest

from utils.security.payload_library import Payload, PayloadLibrary


@pytest.mark.unit
@pytest.mark.security
class TestPayloadDataclass:
    """Test Payload dataclass"""

    def test_create_payload_SEC_PL_001(self):
        """Test creating a Payload instance"""
        payload = Payload(
            value="' OR '1'='1",
            name="SQL Injection",
            description="Test payload",
            category="sql_injection",
            expected_indicators=["sql", "error"],
        )
        assert payload.value == "' OR '1'='1"
        assert payload.name == "SQL Injection"
        assert payload.description == "Test payload"
        assert payload.category == "sql_injection"
        assert payload.expected_indicators == ["sql", "error"]


@pytest.mark.unit
@pytest.mark.security
class TestPayloadLibraryInitialization:
    """Test PayloadLibrary initialization"""

    def test_init_payload_library_SEC_PL_002(self):
        """Test PayloadLibrary initializes correctly"""
        library = PayloadLibrary()
        assert library is not None
        assert library._payloads is not None
        assert isinstance(library._payloads, dict)

    def test_library_has_all_categories_SEC_PL_003(self):
        """Test library contains all expected categories"""
        library = PayloadLibrary()
        expected_categories = [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "ldap_injection",
            "xml_injection",
            "ssti",
        ]
        actual_categories = library.get_all_categories()
        for category in expected_categories:
            assert (
                category in actual_categories
            ), f"Missing category: {category}"


@pytest.mark.unit
@pytest.mark.security
class TestGetPayloads:
    """Test getting payloads by category"""

    def test_get_sql_injection_payloads_SEC_PL_004(self):
        """Test getting SQL injection payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("sql_injection")
        assert len(payloads) > 0
        assert all(p.category == "sql_injection" for p in payloads)
        assert any("OR" in p.value for p in payloads)

    def test_get_xss_payloads_SEC_PL_005(self):
        """Test getting XSS payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("xss")
        assert len(payloads) > 0
        assert all(p.category == "xss" for p in payloads)
        assert any("script" in p.value.lower() for p in payloads)

    def test_get_command_injection_payloads_SEC_PL_006(self):
        """Test getting command injection payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("command_injection")
        assert len(payloads) > 0
        assert all(p.category == "command_injection" for p in payloads)

    def test_get_path_traversal_payloads_SEC_PL_007(self):
        """Test getting path traversal payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("path_traversal")
        assert len(payloads) > 0
        assert all(p.category == "path_traversal" for p in payloads)
        assert any(".." in p.value for p in payloads)

    def test_get_ldap_injection_payloads_SEC_PL_008(self):
        """Test getting LDAP injection payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("ldap_injection")
        assert len(payloads) > 0
        assert all(p.category == "ldap_injection" for p in payloads)

    def test_get_xml_injection_payloads_SEC_PL_009(self):
        """Test getting XML injection payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("xml_injection")
        assert len(payloads) > 0
        assert all(p.category == "xml_injection" for p in payloads)
        assert any("xml" in p.value.lower() for p in payloads)

    def test_get_ssti_payloads_SEC_PL_010(self):
        """Test getting SSTI payloads"""
        library = PayloadLibrary()
        payloads = library.get_payloads("ssti")
        assert len(payloads) > 0
        assert all(p.category == "ssti" for p in payloads)

    def test_get_invalid_category_SEC_PL_011(self):
        """Test getting payloads for invalid category"""
        library = PayloadLibrary()
        payloads = library.get_payloads("nonexistent_category")
        assert payloads == []


@pytest.mark.unit
@pytest.mark.security
class TestPayloadCounts:
    """Test payload counting methods"""

    def test_get_total_payload_count_SEC_PL_012(self):
        """Test getting total payload count"""
        library = PayloadLibrary()
        total = library.get_payload_count()
        assert total > 0
        assert isinstance(total, int)

    def test_get_category_payload_count_SEC_PL_013(self):
        """Test getting payload count for specific category"""
        library = PayloadLibrary()
        sql_count = library.get_payload_count("sql_injection")
        assert sql_count > 0
        assert isinstance(sql_count, int)

    def test_get_invalid_category_count_SEC_PL_014(self):
        """Test getting count for invalid category"""
        library = PayloadLibrary()
        count = library.get_payload_count("invalid_category")
        assert count == 0


@pytest.mark.unit
@pytest.mark.security
class TestPayloadStructure:
    """Test payload structure validation"""

    def test_all_payloads_have_required_fields_SEC_PL_015(self):
        """Test all payloads have required fields"""
        library = PayloadLibrary()
        for category in library.get_all_categories():
            payloads = library.get_payloads(category)
            for payload in payloads:
                assert payload.value is not None
                assert payload.name is not None
                assert payload.description is not None
                assert payload.category is not None
                assert payload.expected_indicators is not None
                assert isinstance(payload.expected_indicators, list)
