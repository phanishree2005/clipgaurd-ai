import yaml
import re
import math
from typing import List, Dict, Any, Tuple
from presidio_analyzer import AnalyzerEngine

class NLPAnalyzer:
    def __init__(self, config_path: str):
        self.analyzer = AnalyzerEngine()
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.rules = self.config.get('rules', {})
        self.engine_config = self.config.get('engine', {})
        self.entropy_threshold = self.engine_config.get('entropy_threshold', 4.5)
        self.entropy_weight = self.engine_config.get('entropy_weight', 5)

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze(self, text: str) -> Dict[str, Any]:
        """Analyzes text for PII using NLP (Presidio), Regex fallbacks, and Entropy."""
        findings = []
        total_risk_score = 0
        
        # 1. NLP Analysis (Presidio)
        # Using built-in entities like CREDIT_CARD, CRYPTO, EMAIL_ADDRESS, IBAN_CODE, IP_ADDRESS, US_SSN
        nlp_results = self.analyzer.analyze(text=text, entities=[], language='en')
        for result in nlp_results:
            findings.append({
                "type": result.entity_type,
                "confidence": result.score,
                "source": "NLP",
                "start": result.start,
                "end": result.end
            })
            total_risk_score += (result.score * 10) # Base weight for NLP findings
            
        # 2. Regex Fallback Analysis from config
        for rule_name, rule_data in self.rules.items():
            pattern = rule_data.get('pattern', '')
            weight = rule_data.get('weight', 0)
            rule_type = rule_data.get('type', 'Unknown')
            
            for match in re.finditer(pattern, text):
                findings.append({
                    "type": rule_type,
                    "confidence": 1.0,
                    "source": "Regex",
                    "start": match.start(),
                    "end": match.end(),
                    "rule_name": rule_name
                })
                total_risk_score += weight
                
        # 3. Entropy Analysis for obfuscated secrets/keys
        entropy = self.calculate_entropy(text)
        if entropy > self.entropy_threshold:
            findings.append({
                "type": "HighEntropy",
                "confidence": 1.0,
                "source": "Heuristic",
                "start": 0,
                "end": len(text),
                "entropy_score": entropy
            })
            total_risk_score += self.entropy_weight

        # Redact original text for safety
        redacted_text = self.redact_findings(text, findings)

        return {
            "findings": findings,
            "risk_score": min(total_risk_score, 100), # Cap at 100
            "entropy": entropy,
            "redacted_text": redacted_text,
            "is_sensitive": len(findings) > 0
        }

    def redact_findings(self, text: str, findings: List[Dict]) -> str:
        """Replaces sensitive parts of text with asterisks."""
        if not findings:
            return text
            
        redacted = list(text)
        for finding in findings:
            start = finding.get('start', 0)
            end = finding.get('end', len(text))
            for i in range(start, end):
                if i < len(redacted):
                    redacted[i] = '*'
        return "".join(redacted)
