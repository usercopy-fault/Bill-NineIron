#!/usr/bin/env python3
"""
Nuclei Template Mutation Engine
Generates polymorphic payload variants to evade WAF/IDS
"""

import base64
import urllib.parse
import random
import string
import hashlib
from typing import List, Dict, Any

class MutationEngine:
    """Generates payload mutations for WAF evasion"""
    
    def __init__(self, base_payload: str):
        self.base_payload = base_payload
        self.mutations = []
    
    def base64_encode(self) -> str:
        """Encode payload in base64"""
        return base64.b64encode(self.base_payload.encode()).decode()
    
    def url_encode(self, double: bool = False) -> str:
        """URL encode payload"""
        encoded = urllib.parse.quote(self.base_payload)
        if double:
            encoded = urllib.parse.quote(encoded)
        return encoded
    
    def unicode_encode(self) -> str:
        """Unicode escape encode"""
        return ''.join([f'\\u{ord(c):04x}' for c in self.base_payload])
    
    def hex_encode(self) -> str:
        """Hex encode"""
        return self.base_payload.encode().hex()
    
    def octal_encode(self) -> str:
        """Octal escape encode"""
        return ''.join([f'\\{ord(c):03o}' for c in self.base_payload])
    
    def html_entity_encode(self) -> str:
        """HTML entity encode"""
        return ''.join([f'&#{ord(c)};' for c in self.base_payload])
    
    def comment_injection(self) -> str:
        """Inject comments between payload"""
        chars = list(self.base_payload)
        result = []
        for char in chars:
            if random.random() > 0.5:
                result.append(f"/**/{ char}")
            else:
                result.append(char)
        return ''.join(result)
    
    def case_flip(self) -> str:
        """Random case mutation"""
        result = []
        for char in self.base_payload:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def null_byte_insertion(self) -> str:
        """Insert null bytes"""
        chars = list(self.base_payload)
        for i in range(0, len(chars), random.randint(2, 5)):
            chars.insert(i, '%00')
        return ''.join(chars)
    
    def add_random_params(self, endpoint: str) -> str:
        """Add random parameters to URL"""
        params = []
        for _ in range(random.randint(1, 3)):
            key = ''.join(random.choices(string.ascii_lowercase, k=8))
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            params.append(f"{key}={value}")
        
        separator = '&' if '?' in endpoint else '?'
        return endpoint + separator + '&'.join(params)
    
    def randomize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Randomize header order and add noise headers"""
        mutated = dict(headers)
        
        # Add noise headers
        noise_headers = {
            'X-' + ''.join(random.choices(string.ascii_letters, k=8)): ''.join(random.choices(string.ascii_letters, k=10))
            for _ in range(random.randint(1, 3))
        }
        mutated.update(noise_headers)
        
        # Randomize User-Agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        ]
        mutated['User-Agent'] = random.choice(user_agents)
        
        return mutated
    
    def generate_all_mutations(self) -> Dict[str, str]:
        """Generate all mutation variants"""
        mutations = {
            'base': self.base_payload,
            'base64': self.base64_encode(),
            'url_encoded': self.url_encode(),
            'double_url_encoded': self.url_encode(double=True),
            'unicode': self.unicode_encode(),
            'hex': self.hex_encode(),
            'octal': self.octal_encode(),
            'html_entity': self.html_entity_encode(),
            'comment_injection': self.comment_injection(),
            'case_flip': self.case_flip(),
            'null_bytes': self.null_byte_insertion(),
        }
        return mutations

def generate_random_ip() -> str:
    """Generate random IP for X-Forwarded-For"""
    return '.'.join([str(random.randint(0, 255)) for _ in range(4)])

def generate_random_user_agent() -> str:
    """Generate random User-Agent"""
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'curl/7.68.0',
        'Python-Requests/2.26.0',
    ]
    return random.choice(agents)

if __name__ == '__main__':
    # Example usage
    payload = '<script>alert(1)</script>'
    engine = MutationEngine(payload)
    
    mutations = engine.generate_all_mutations()
    print("Generated Mutations:")
    for encoding, variant in mutations.items():
        print(f"{encoding}: {variant[:60]}...")
    
    print(f"\nRandom IP: {generate_random_ip()}")
    print(f"Random UA: {generate_random_user_agent()}")
