import numpy as np
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    role: str
    content: str
    embedding: Optional[np.ndarray]
    timestamp: datetime
    findings: List
    risk_score: float


class EmbeddingBasedContext:
    def __init__(self, session_id: str, model_name: str = "all-MiniLM-L6-v2"):
        self.session_id = session_id
        self.model_name = model_name
        self.model = None
        
        self.messages: List[Message] = []
        self.max_history = 20
        
        self.sensitive_topics = {
            "authentication": ["password", "login", "credentials", "auth"],
            "pii": ["ssn", "social security", "driver license", "passport"],
            "financial": ["credit card", "bank account", "salary", "payment"],
            "medical": ["diagnosis", "medication", "health record", "patient"],
            "confidential": ["secret", "confidential", "private", "classified"]
        }
        
        self.topic_embeddings = {}
        self.entity_memory = {}
        self.risk_trend = []
        
    def _load_model(self):
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer(self.model_name)
                self._precompute_topic_embeddings()
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers not installed. "
                    "Install with: pip install sentence-transformers"
                )
    
    def _precompute_topic_embeddings(self):
        for topic, keywords in self.sensitive_topics.items():
            topic_text = " ".join(keywords)
            self.topic_embeddings[topic] = self.model.encode(topic_text)
    
    def _embed_text(self, text: str) -> np.ndarray:
        self._load_model()
        return self.model.encode(text)
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        dot_product = np.dot(vec1, vec2)
        norm_product = np.linalg.norm(vec1) * np.linalg.norm(vec2)
        return dot_product / norm_product if norm_product > 0 else 0.0
    
    def add_message(self, role: str, content: str, findings: List, risk_score: float):
        embedding = self._embed_text(content)
        
        message = Message(
            role=role,
            content=content,
            embedding=embedding,
            timestamp=datetime.now(),
            findings=findings,
            risk_score=risk_score
        )
        
        self.messages.append(message)
        
        if len(self.messages) > self.max_history:
            self.messages.pop(0)
        
        self.risk_trend.append(risk_score)
        if len(self.risk_trend) > 10:
            self.risk_trend.pop(0)
        
        self._update_entity_memory(findings)
    
    def _update_entity_memory(self, findings: List):
        for finding in findings:
            entity_key = f"{finding.type}:{finding.subtype}"
            if entity_key not in self.entity_memory:
                self.entity_memory[entity_key] = {
                    "count": 0,
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now()
                }
            self.entity_memory[entity_key]["count"] += 1
            self.entity_memory[entity_key]["last_seen"] = datetime.now()
    
    def detect_topic_context(self, current_text: str) -> Dict[str, float]:
        current_embedding = self._embed_text(current_text)
        
        topic_scores = {}
        for topic, topic_embedding in self.topic_embeddings.items():
            similarity = self._cosine_similarity(current_embedding, topic_embedding)
            topic_scores[topic] = similarity
        
        return topic_scores
    
    def find_reference_chain(self, current_text: str, threshold: float = 0.7) -> List[Tuple[Message, float]]:
        if not self.messages:
            return []
        
        current_embedding = self._embed_text(current_text)
        references = []
        
        for msg in reversed(self.messages[-5:]):
            if msg.embedding is not None:
                similarity = self._cosine_similarity(current_embedding, msg.embedding)
                if similarity > threshold:
                    references.append((msg, similarity))
        
        return references
    
    def detect_entity_coreference(self, current_findings: List) -> bool:
        current_types = {f.subtype for f in current_findings}
        
        for msg in reversed(self.messages[-3:]):
            past_types = {f.subtype for f in msg.findings}
            
            if "PERSON" in past_types and "Email" in current_types:
                return True
            if "ORG" in past_types and ("Email" in current_types or "Phone" in current_types):
                return True
            if "PERSON" in past_types and "Phone" in current_types:
                return True
            if any(t in past_types for t in ["SSN", "Credit Card"]) and "PERSON" in current_types:
                return True
        
        return False
    
    def calculate_context_risk_modifier(self, current_text: str, current_findings: List) -> Tuple[float, List[str]]:
        modifier = 0.0
        reasons = []
        
        topic_scores = self.detect_topic_context(current_text)
        max_topic_score = max(topic_scores.values()) if topic_scores else 0.0
        
        if max_topic_score > 0.6:
            top_topic = max(topic_scores.items(), key=lambda x: x[1])[0]
            modifier += 0.2
            reasons.append(f"Sensitive topic detected: {top_topic} (confidence: {max_topic_score:.2f})")
        
        references = self.find_reference_chain(current_text, threshold=0.7)
        if references:
            avg_similarity = np.mean([sim for _, sim in references])
            modifier += 0.15 * len(references)
            reasons.append(f"References to {len(references)} previous message(s)")
        
        if self.detect_entity_coreference(current_findings):
            modifier += 0.3
            reasons.append("Entity coreference detected (asking about previously mentioned entity)")
        
        if len(self.risk_trend) >= 3:
            recent_avg = np.mean(self.risk_trend[-3:])
            if recent_avg > 0.5:
                modifier += 0.25
                reasons.append(f"Escalating risk pattern (avg: {recent_avg:.2f})")
        
        entity_concentration = len(self.entity_memory)
        if entity_concentration > 5:
            modifier += 0.15
            reasons.append(f"High entity concentration ({entity_concentration} unique entities)")
        
        return modifier, reasons
    
    def get_conversation_summary(self) -> Dict:
        return {
            "session_id": self.session_id,
            "message_count": len(self.messages),
            "unique_entities": len(self.entity_memory),
            "avg_risk": np.mean(self.risk_trend) if self.risk_trend else 0.0,
            "max_risk": max(self.risk_trend) if self.risk_trend else 0.0,
            "entities": dict(self.entity_memory)
        }
    
    def clear_history(self):
        self.messages.clear()
        self.entity_memory.clear()
        self.risk_trend.clear()


class ConversationContext:
    def __init__(self):
        self.__session_id = None
        self.conversation = []

