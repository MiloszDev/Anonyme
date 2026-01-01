import pytest
from anonyme.detectors.regex import RegexDetector
from anonyme.models.findings import Finding


class TestRegexDetector:
    
    @pytest.fixture
    def detector(self):
        return RegexDetector()
    
    def test_ssn_detection(self, detector):
        text = "My SSN is 123-45-6789"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "SSN" for f in findings)
        assert all(f.confidence == 1.0 for f in findings if f.subtype == "SSN")
    
    def test_email_detection(self, detector):
        text = "Contact me at john.doe@example.com"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "Email" for f in findings)
    
    def test_phone_detection_us(self, detector):
        text = "Call me at (555) 123-4567"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "Phone" for f in findings)
    
    def test_phone_detection_international(self, detector):
        text = "My number is +48 575 030 520"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "Phone" for f in findings)
    
    def test_credit_card_detection(self, detector):
        text = "Card number: 1234-5678-9012-3456"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "Credit Card" for f in findings)
    
    def test_credit_card_detection_spaces(self, detector):
        text = "Card: 1234 5678 9012 3456"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "Credit Card" for f in findings)
    
    def test_api_key_detection(self, detector):
        text = "API key: xK9mP2nQ8wR7tY5uI1oP4sG6hJ3fL0dA"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "API Key or Token" for f in findings)
        assert all(f.confidence == 0.8 for f in findings if f.subtype == "API Key or Token")
    
    def test_no_false_positives_on_safe_text(self, detector):
        text = "Hello world, this is a normal sentence"
        findings = detector.detect(text)
        
        assert len(findings) == 0
    
    def test_multiple_findings(self, detector):
        text = "Contact alice@example.com or call 555-123-4567"
        findings = detector.detect(text)
        
        assert len(findings) >= 2
        types = {f.subtype for f in findings}
        assert "Email" in types
        assert "Phone" in types
    
    def test_finding_structure(self, detector):
        text = "test@example.com"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        finding = findings[0]
        assert hasattr(finding, 'type')
        assert hasattr(finding, 'subtype')
        assert hasattr(finding, 'confidence')
        assert hasattr(finding, 'source')
        assert finding.source == "regex"
    
    def test_api_key_heuristic_high_entropy(self, detector):
        text = "Secret: aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW"
        findings = detector.detect(text)
        
        has_api_key = any(f.subtype == "API Key or Token" for f in findings)
        assert has_api_key
    
    def test_api_key_heuristic_low_entropy(self, detector):
        text = "A simple word like conversation"
        findings = detector.detect(text)
        
        has_api_key = any(f.subtype == "API Key or Token" for f in findings)
        assert not has_api_key
