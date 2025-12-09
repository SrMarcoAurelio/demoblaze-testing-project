"""
Security Response Analyzer Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for ResponseAnalyzer:
- Analyzing SQL injection responses
- Analyzing XSS responses
- Analyzing command injection responses
- Analyzing path traversal responses
- Analyzing authentication bypass responses
- VulnerabilityDetection dataclass
"""

import pytest

from utils.security.response_analyzer import (
    ResponseAnalyzer,
    VulnerabilityDetection,
    VulnerabilitySeverity,
)


@pytest.mark.unit
@pytest.mark.security
class TestVulnerabilityDetection:
    """Test VulnerabilityDetection dataclass"""

    def test_create_vulnerability_detection_SEC_RA_001(self):
        """Test creating VulnerabilityDetection instance"""
        vuln = VulnerabilityDetection(
            vulnerability_type="SQL Injection",
            severity=VulnerabilitySeverity.HIGH,
            description="Test vulnerability",
            payload_used="' OR '1'='1",
            evidence=["SQL error detected"],
            url="https://example.com",
            method="POST",
            status_code=200,
            response_body="Error: SQL syntax",
        )
        assert vuln.vulnerability_type == "SQL Injection"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.payload_used == "' OR '1'='1"

    def test_vulnerability_to_dict_SEC_RA_002(self):
        """Test converting vulnerability to dictionary"""
        vuln = VulnerabilityDetection(
            vulnerability_type="XSS",
            severity=VulnerabilitySeverity.MEDIUM,
            description="Test XSS",
            payload_used="<script>alert(1)</script>",
            evidence=["Script tag found"],
            url="https://example.com",
            method="GET",
            status_code=200,
            response_body="<script>alert(1)</script>",
        )
        vuln_dict = vuln.to_dict()
        assert isinstance(vuln_dict, dict)
        assert vuln_dict["vulnerability_type"] == "XSS"
        assert vuln_dict["severity"] == "medium"
        assert "evidence" in vuln_dict


@pytest.mark.unit
@pytest.mark.security
class TestResponseAnalyzerInitialization:
    """Test ResponseAnalyzer initialization"""

    def test_init_response_analyzer_SEC_RA_003(self):
        """Test ResponseAnalyzer initializes correctly"""
        analyzer = ResponseAnalyzer()
        assert analyzer is not None
        assert analyzer.sql_error_patterns is not None
        assert analyzer.xss_patterns is not None
        assert analyzer.command_injection_patterns is not None


@pytest.mark.unit
@pytest.mark.security
class TestAnalyzeSQLInjection:
    """Test SQL injection analysis"""

    def test_analyze_sql_error_detection_SEC_RA_004(self):
        """Test detecting SQL errors in response"""
        analyzer = ResponseAnalyzer()
        response_body = "Error: SQL syntax error near 'OR'"
        vuln = analyzer.analyze_sql_injection(
            response_body=response_body,
            status_code=500,
            url="https://example.com/login",
            method="POST",
            payload="' OR '1'='1",
        )
        assert vuln is not None
        assert vuln.vulnerability_type == "SQL Injection"
        assert len(vuln.evidence) > 0

    def test_analyze_no_sql_injection_SEC_RA_005(self):
        """Test no SQL injection detected in safe response"""
        analyzer = ResponseAnalyzer()
        response_body = "Login successful"
        vuln = analyzer.analyze_sql_injection(
            response_body=response_body,
            status_code=200,
            url="https://example.com/login",
            method="POST",
            payload="validuser",
        )
        assert vuln is None


@pytest.mark.unit
@pytest.mark.security
class TestAnalyzeXSS:
    """Test XSS analysis"""

    def test_analyze_xss_reflected_payload_SEC_RA_006(self):
        """Test detecting reflected XSS payload"""
        analyzer = ResponseAnalyzer()
        payload = "<script>alert('XSS')</script>"
        response_body = f"Welcome {payload}"
        vuln = analyzer.analyze_xss(
            response_body=response_body,
            status_code=200,
            url="https://example.com/profile",
            method="GET",
            payload=payload,
        )
        assert vuln is not None
        assert vuln.vulnerability_type == "Cross-Site Scripting (XSS)"
        assert len(vuln.evidence) > 0

    def test_analyze_no_xss_SEC_RA_007(self):
        """Test no XSS detected when payload is encoded"""
        analyzer = ResponseAnalyzer()
        payload = "<script>alert('XSS')</script>"
        response_body = "Welcome &lt;script&gt;alert('XSS')&lt;/script&gt;"
        vuln = analyzer.analyze_xss(
            response_body=response_body,
            status_code=200,
            url="https://example.com/profile",
            method="GET",
            payload=payload,
        )
        # Payload is not reflected unencoded, so no vulnerability
        assert vuln is None


@pytest.mark.unit
@pytest.mark.security
class TestAnalyzeCommandInjection:
    """Test command injection analysis"""

    def test_analyze_command_injection_passwd_SEC_RA_008(self):
        """Test detecting command injection via /etc/passwd output"""
        analyzer = ResponseAnalyzer()
        response_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        vuln = analyzer.analyze_command_injection(
            response_body=response_body,
            status_code=200,
            url="https://example.com/api",
            method="POST",
            payload="; cat /etc/passwd",
        )
        assert vuln is not None
        assert vuln.vulnerability_type == "Command Injection"
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert len(vuln.evidence) > 0

    def test_analyze_no_command_injection_SEC_RA_009(self):
        """Test no command injection in safe response"""
        analyzer = ResponseAnalyzer()
        response_body = "Request processed successfully"
        vuln = analyzer.analyze_command_injection(
            response_body=response_body,
            status_code=200,
            url="https://example.com/api",
            method="POST",
            payload="normal input",
        )
        assert vuln is None


@pytest.mark.unit
@pytest.mark.security
class TestAnalyzePathTraversal:
    """Test path traversal analysis"""

    def test_analyze_path_traversal_file_disclosure_SEC_RA_010(self):
        """Test detecting path traversal via file disclosure"""
        analyzer = ResponseAnalyzer()
        response_body = "root:x:0:0:root:/root:/bin/bash"
        vuln = analyzer.analyze_path_traversal(
            response_body=response_body,
            status_code=200,
            url="https://example.com/download",
            method="GET",
            payload="../../../etc/passwd",
        )
        assert vuln is not None
        assert vuln.vulnerability_type == "Path Traversal / File Disclosure"
        assert len(vuln.evidence) > 0

    def test_analyze_no_path_traversal_SEC_RA_011(self):
        """Test no path traversal in safe response"""
        analyzer = ResponseAnalyzer()
        response_body = "File not found"
        vuln = analyzer.analyze_path_traversal(
            response_body=response_body,
            status_code=404,
            url="https://example.com/download",
            method="GET",
            payload="valid_file.txt",
        )
        assert vuln is None


@pytest.mark.unit
@pytest.mark.security
class TestAnalyzeAuthenticationBypass:
    """Test authentication bypass analysis"""

    def test_analyze_auth_bypass_SEC_RA_012(self):
        """Test detecting authentication bypass"""
        analyzer = ResponseAnalyzer()
        response_body = "Welcome to dashboard! You are logged in as admin."
        vuln = analyzer.analyze_authentication_bypass(
            response_body=response_body,
            status_code=200,
            url="https://example.com/login",
            method="POST",
            payload="' OR '1'='1",
            original_status=401,
        )
        assert vuln is not None
        assert vuln.vulnerability_type == "Authentication Bypass"
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert len(vuln.evidence) > 0
