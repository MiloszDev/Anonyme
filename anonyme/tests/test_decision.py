import pytest
from anonyme.decision import decide
from anonyme.models.findings import Finding


class TestDecisionFunction:
    
    def test_allow_with_no_findings(self):
        findings = []
        result = decide(findings, {})
        
        assert result["action"] == "ALLOW"
        assert result["risk_score"] == 0.0
        assert result["reasons"] == []
    
    def test_block_with_high_risk(self):
        findings = [
            Finding(type="PII", subtype="SSN", confidence=1.0, source="regex")
        ]
        result = decide(findings, {})
        
        assert result["action"] == "BLOCK"
        assert result["risk_score"] >= 0.8
        assert len(result["reasons"]) > 0
    
    def test_redact_with_medium_risk(self):
        findings = [
            Finding(type="PII", subtype="Phone", confidence=0.6, source="regex")
        ]
        result = decide(findings, {})
        
        assert result["action"] == "REDACT"
        assert 0.5 <= result["risk_score"] < 0.8
    
    def test_multiple_findings_accumulate_risk(self):
        findings = [
            Finding(type="PII", subtype="Email", confidence=1.0, source="regex"),
            Finding(type="PII", subtype="PERSON", confidence=0.9, source="ner")
        ]
        result = decide(findings, {})
        
        assert result["risk_score"] == 1.9
        assert result["action"] == "BLOCK"
        assert len(result["reasons"]) == 2
    
    def test_reasons_format(self):
        findings = [
            Finding(type="PII", subtype="Email", confidence=1.0, source="regex")
        ]
        result = decide(findings, {})
        
        assert "Email via regex" in result["reasons"]
    
    def test_risk_threshold_boundaries(self):
        findings_allow = [
            Finding(type="PII", subtype="test", confidence=0.4, source="test")
        ]
        findings_redact = [
            Finding(type="PII", subtype="test", confidence=0.5, source="test")
        ]
        findings_block = [
            Finding(type="PII", subtype="test", confidence=0.8, source="test")
        ]
        
        assert decide(findings_allow, {})["action"] == "ALLOW"
        assert decide(findings_redact, {})["action"] == "REDACT"
        assert decide(findings_block, {})["action"] == "BLOCK"
    
    def test_return_structure(self):
        findings = []
        result = decide(findings, {})
        
        assert "action" in result
        assert "risk_score" in result
        assert "reasons" in result
        assert isinstance(result["action"], str)
        assert isinstance(result["risk_score"], (int, float))
        assert isinstance(result["reasons"], list)
