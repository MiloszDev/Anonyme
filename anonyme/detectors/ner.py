import spacy

from anonyme.detectors.base import Detector
from anonyme.models.findings import Finding


class NerDetector(Detector):
    def __init__(self):
        self.model = None
        self.entity_types = ["PERSON", "ORG", "GPE", "DATE"]
    
    def _load_model(self):
        if self.model is None:
            try:
                self.model = spacy.load("en_core_web_sm")
            except OSError:
                raise RuntimeError(
                    "spaCy model 'en_core_web_sm' not found. "
                    "Install it with: python -m spacy download en_core_web_sm"
                )

    def detect(self, text: str) -> list:
        self._load_model()
        
        doc = self.model(text)
        findings = []
        
        for ent in doc.ents:
            if ent.label_ in self.entity_types:
                findings.append(
                    Finding(
                        type="PII",
                        subtype=ent.label_,
                        confidence=0.9,
                        source="ner"
                    )
                )
        
        return findings