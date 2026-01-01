from typing import List, Dict, Literal
from anonyme.logging.audit import get_logger
from pydantic import BaseModel

from anonyme.detectors.regex import RegexDetector
from anonyme.detectors.ner import NerDetector
from anonyme.decision import decide

logger = get_logger(__name__)

class AnalyzeResult(BaseModel):
    action: Literal["ALLOW", "BLOCK", "REDACT"]
    risk_score: float
    reasons: List[str]
    metadata: Dict[str, str]

regex_detector = RegexDetector()
ner_detector = NerDetector()

def analyze(prompt: str, context: List[Dict[str, str]]) -> AnalyzeResult:
    logger.info("Analyzing prompt: %s", prompt)
    logger.info("Context: %s", context)
    
    findings = []
    findings.extend(regex_detector.detect(prompt))
    findings.extend(ner_detector.detect(prompt))
    
    decision = decide(findings, context)
    
    return AnalyzeResult(
        action=decision["action"],
        risk_score=decision["risk_score"],
        reasons=decision["reasons"],
        metadata={}
    )