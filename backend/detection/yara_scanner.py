import yara
import os
import logging

class YaraScanner:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self.load_rules()

    def load_rules(self):
        """Loads and compiles YARA rules from the specified file."""
        if not os.path.exists(self.rules_path):
            logging.error(f"YARA rules file not found at: {self.rules_path}")
            return
            
        try:
            self.rules = yara.compile(filepath=self.rules_path)
            logging.info(f"Successfully loaded YARA rules from {self.rules_path}")
        except yara.SyntaxError as e:
            logging.error(f"Failed to compile YARA rules: {e}")
        except Exception as e:
            logging.error(f"Unexpected error loading YARA rules: {e}")

    def scan(self, text: str) -> dict:
        """Scans the provided text against the loaded YARA rules."""
        if not self.rules or not text:
            return {"matches": [], "is_malicious": False, "highest_weight": 0}
            
        try:
            matches = self.rules.match(data=text)
            
            findings = []
            highest_weight = 0
            
            for match in matches:
                # Extract meta information
                meta = match.meta
                weight = meta.get('weight', 5)
                description = meta.get('description', 'Unknown threat')
                
                if weight > highest_weight:
                    highest_weight = weight
                    
                findings.append({
                    "rule": match.rule,
                    "description": description,
                    "weight": weight,
                    "source": "YARA"
                })
                
            return {
                "matches": findings,
                "is_malicious": len(findings) > 0,
                "highest_weight": highest_weight
            }
            
        except Exception as e:
            logging.error(f"Error during YARA scan: {e}")
            return {"matches": [], "is_malicious": False, "highest_weight": 0}
