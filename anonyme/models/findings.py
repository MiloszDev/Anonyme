from dataclasses import dataclass

@dataclass
class Finding:
    type: str
    subtype: str
    confidence: float
    source: str
