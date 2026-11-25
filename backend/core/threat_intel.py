import re

class ThreatIntel:
    def __init__(self):
        # Simulated database of known malicious indicators
        self.malicious_ips = {
            "185.15.24.12": "Known Ransomware C2",
            "192.168.1.100": "Suspicious Internal Scanner"
        }
        
        self.malicious_wallets = {
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Lazarus Group Associated",
            "0x000000000000000000000000000000000000dead": "Burn Address / Phishing"
        }

    def check_indicators(self, text: str) -> list:
        """Extracts IPs/Wallets and checks them against threat intelligence."""
        findings = []
        
        # Very basic IP extraction for simulation
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, text):
            if ip in self.malicious_ips:
                findings.append({
                    "indicator": ip,
                    "type": "Malicious IP",
                    "description": self.malicious_ips[ip],
                    "source": "ThreatIntel"
                })
                
        # Basic Crypto extraction for simulation
        crypto_pattern = r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[a-fA-F0-9]{40}\b'
        for match in re.finditer(crypto_pattern, text):
            wallet = match.group(0)
            if wallet in self.malicious_wallets:
                findings.append({
                    "indicator": wallet,
                    "type": "Malicious Crypto Wallet",
                    "description": self.malicious_wallets[wallet],
                    "source": "ThreatIntel"
                })
                
        return findings
