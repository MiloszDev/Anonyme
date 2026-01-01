import pytest
from anonyme.analyze import analyze, AnalyzeResult


class TestAnalyzeIntegration:
    
    def test_safe_text_returns_allow(self):
        result = analyze("Hello world", [])
        
        assert isinstance(result, AnalyzeResult)
        assert result.action == "ALLOW"
        assert result.risk_score == 0.0
        assert len(result.reasons) == 0
    
    def test_email_detected_and_blocked(self):
        result = analyze("Contact me at test@example.com", [])
        
        assert result.action == "BLOCK"
        assert result.risk_score >= 0.8
        assert any("Email" in reason for reason in result.reasons)
    
    def test_phone_detected(self):
        result = analyze("Call me at +48 575 030 520", [])
        
        assert result.action in ["BLOCK", "REDACT"]
        assert result.risk_score > 0
        assert any("Phone" in reason for reason in result.reasons)
    
    def test_ssn_detected(self):
        result = analyze("My SSN is 123-45-6789", [])
        
        assert result.action == "BLOCK"
        assert result.risk_score >= 0.8
        assert any("SSN" in reason for reason in result.reasons)
    
    def test_person_entity_detected(self):
        result = analyze("Tell me about Alice Johnson", [])
        
        assert result.risk_score > 0
        assert any("PERSON" in reason for reason in result.reasons)
    
    def test_combined_detection_regex_and_ner(self):
        result = analyze("Alice's email is alice@example.com", [])
        
        assert result.risk_score > 1.0
        assert len(result.reasons) >= 2
    
    def test_api_key_detected(self):
        result = analyze("API key: xK9mP2nQ8wR7tY5uI1oP4sG6hJ3fL0dA", [])
        
        assert result.risk_score > 0
        assert any("API Key" in reason for reason in result.reasons)
    
    def test_result_structure(self):
        result = analyze("test", [])
        
        assert hasattr(result, 'action')
        assert hasattr(result, 'risk_score')
        assert hasattr(result, 'reasons')
        assert hasattr(result, 'metadata')
        assert result.action in ["ALLOW", "BLOCK", "REDACT"]
        assert isinstance(result.risk_score, float)
        assert isinstance(result.reasons, list)
        assert isinstance(result.metadata, dict)
    
    def test_multiple_pii_types(self):
        result = analyze(
            "Alice Johnson's SSN is 123-45-6789 and email is alice@test.com",
            []
        )
        
        assert result.action == "BLOCK"
        assert result.risk_score > 2.0
        finding_types = {reason.split()[0] for reason in result.reasons}
        assert len(finding_types) >= 2
    
    def test_context_parameter_accepted(self):
        context = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"}
        ]
        result = analyze("Test message", context)
        
        assert isinstance(result, AnalyzeResult)
    
    def test_empty_context(self):
        result = analyze("Test", [])
        assert isinstance(result, AnalyzeResult)
    
    def test_redact_action_threshold(self):
        result = analyze("PERSON mentioned", [])
        
        if 0.5 <= result.risk_score < 0.8:
            assert result.action == "REDACT"
