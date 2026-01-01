import pytest
from anonyme.detectors.ner import NerDetector


class TestNerDetector:
    
    @pytest.fixture
    def detector(self):
        return NerDetector()
    
    def test_person_detection(self, detector):
        text = "Tell me about Alice Johnson"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "PERSON" for f in findings)
        assert all(f.source == "ner" for f in findings)
    
    def test_organization_detection(self, detector):
        text = "Microsoft is hiring new employees"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "ORG" for f in findings)
    
    def test_gpe_detection(self, detector):
        text = "I visited Warsaw last summer"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "GPE" for f in findings)
    
    def test_date_detection(self, detector):
        text = "The meeting is on January 15th, 2024"
        findings = detector.detect(text)
        
        assert len(findings) > 0
        assert any(f.subtype == "DATE" for f in findings)
    
    def test_confidence_level(self, detector):
        text = "Alice Johnson works at Microsoft"
        findings = detector.detect(text)
        
        assert all(f.confidence == 0.9 for f in findings)
    
    def test_no_findings_on_generic_text(self, detector):
        text = "The quick brown fox jumps over the lazy dog"
        findings = detector.detect(text)
        
        assert len(findings) == 0
    
    def test_multiple_entities(self, detector):
        text = "Alice Johnson works at Microsoft in Warsaw"
        findings = detector.detect(text)
        
        assert len(findings) >= 2
        entity_types = {f.subtype for f in findings}
        assert "PERSON" in entity_types or "ORG" in entity_types
    
    def test_lazy_loading(self, detector):
        assert detector.model is None
        
        detector.detect("Test")
        assert detector.model is not None
    
    def test_finding_structure(self, detector):
        text = "Alice works here"
        findings = detector.detect(text)
        
        if len(findings) > 0:
            finding = findings[0]
            assert finding.type == "PII"
            assert finding.subtype in ["PERSON", "ORG", "GPE", "DATE"]
            assert finding.confidence == 0.9
            assert finding.source == "ner"
