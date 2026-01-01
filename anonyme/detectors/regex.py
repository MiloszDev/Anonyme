import re

from anonyme.detectors.base import Detector
from anonyme.models.findings import Finding


class RegexDetector(Detector):
    def __init__(self):
        self.patterns = {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Credit Card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "Phone": r"(?:\+\d{1,3}\s?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{0,4}",
        }
        
        self.api_key_pattern = r"\b[A-Za-z0-9_\-]{20,}\b"

    def _looks_like_api_key(self, text: str) -> bool:
        if len(text) < 20:
            return False
        
        has_upper = any(c.isupper() for c in text)
        has_lower = any(c.islower() for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_special = any(c in "_-" for c in text)
        
        char_variety = sum([has_upper, has_lower, has_digit, has_special])
        
        digit_ratio = sum(c.isdigit() for c in text) / len(text)
        upper_ratio = sum(c.isupper() for c in text) / len(text)
        
        if char_variety >= 2 and (digit_ratio > 0.2 or upper_ratio > 0.3):
            return True
        
        return False

    def detect(self, text: str) -> list:
        findings = []
        
        for name, pattern in self.patterns.items():
            if re.search(pattern, text):
                findings.append(
                    Finding(
                        type="PII",
                        subtype=name,
                        confidence=1.0,
                        source="regex"
                    )
                )
        
        potential_keys = re.findall(self.api_key_pattern, text)
        for key in potential_keys:
            if self._looks_like_api_key(key):
                findings.append(
                    Finding(
                        type="SECRET",
                        subtype="API Key or Token",
                        confidence=0.8,
                        source="regex"
                    )
                )
        
        return findings