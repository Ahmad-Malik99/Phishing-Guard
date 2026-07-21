"""
URL Feature Extraction for Phishing Detection with Accurate Analysis
"""

import re
from urllib.parse import urlparse

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    @staticmethod
    def extract_features(url):
        """Extract features from URL - BALANCED phishing detection"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # 1. URL Length - suspicious if very long
            url_length = min(len(url) / 120.0, 1.0)
            
            # 2. Special characters - phishing indicator
            special = sum(1 for c in url if c in '!@#$%^&*()_+-=[]{}|;:,')
            special_chars = min((special / max(len(url), 1)) * 2.5, 1.0)
            
            # 3. IP address check - MAJOR red flag
            has_ip = 1.0 if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain) else 0.0
            
            # 4. Subdomains - excessive subdomains = phishing
            subdomain_count = domain.count('.')
            subdomains = min(max(subdomain_count - 2, 0) / 3.5, 1.0)
            
            # 5. HTTPS - missing HTTPS is suspicious but not critical
            https_score = 0.0 if url.startswith('https') else 0.4
            
            # 6. Dots count - many dots can mask real domain
            dots = min(url.count('.') / 10.0, 1.0)
            
            # 7. Dashes - phishing tactic
            dashes = min(url.count('-') / 7.0, 1.0)
            
            return [url_length, special_chars, has_ip, subdomains, https_score, dots, dashes]
        except:
            return [0.4, 0.25, 0.0, 0.3, 0.4, 0.4, 0.3]
    
    @staticmethod
    def analyze_url_structure(url):
        """Analyze URL structure and return findings + risk score"""
        findings = []
        risk_score = 0.15  # Base risk for any URL
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for IP address - CRITICAL
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
                findings.append({
                    'type': 'danger',
                    'title': 'IP Address Used',
                    'description': f'URL uses IP address instead of domain name',
                    'risk': 'HIGH'
                })
                risk_score += 0.50
            
            # Check for @ symbol - CRITICAL
            if '@' in url:
                findings.append({
                    'type': 'danger',
                    'title': 'Special Character @ in URL',
                    'description': 'URL contains @ which is used for phishing attacks',
                    'risk': 'HIGH'
                })
                risk_score += 0.50
            
            # Check for URL shorteners - SUSPICIOUS
            shorteners = ['bit.ly', 'tinyurl', 'ow.ly', 'short.link', 'goo.gl', 'shortened']
            if any(s in domain for s in shorteners):
                findings.append({
                    'type': 'warning',
                    'title': 'URL Shortener Detected',
                    'description': 'URL uses a shortening service which could hide malicious destination',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.40
            
            # Check for suspicious keywords in domain
            suspicious_keywords = ['login', 'verify', 'confirm', 'secure', 'account', 'update', 'payment', 'paypal', 'amazon', 'apple', 'google', 'bank', 'adobe', 'microsoft']
            domain_lower = domain.lower()
            if any(keyword in domain_lower for keyword in suspicious_keywords):
                findings.append({
                    'type': 'warning',
                    'title': 'Suspicious Keywords in Domain',
                    'description': f'Domain contains common phishing keywords',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.30
            
            # Check for HTTP (not HTTPS) - penalize heavily
            if url.startswith('http://'):
                findings.append({
                    'type': 'warning',
                    'title': 'Not HTTPS Secure',
                    'description': 'Website does not use HTTPS encryption - MAJOR RISK',
                    'risk': 'HIGH'
                })
                risk_score += 0.45
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                findings.append({
                    'type': 'warning',
                    'title': 'Excessive Subdomains',
                    'description': f'URL has many subdomains ({subdomain_count}), typical of phishing',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.25
            
            # Check for many dots/dashes in domain
            dots_in_domain = domain.count('.')
            if dots_in_domain > 4:
                findings.append({
                    'type': 'warning',
                    'title': 'Many Dots in Domain',
                    'description': 'Domain contains excessive dots, masking real domain',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.20
            
            dashes_in_url = url.count('-')
            if dashes_in_url > 3:
                findings.append({
                    'type': 'warning',
                    'title': 'Many Dashes in URL',
                    'description': 'URL contains excessive dashes, typical of phishing',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.20
            
            # Very long URL
            if len(url) > 150:
                findings.append({
                    'type': 'warning',
                    'title': 'Very Long URL',
                    'description': 'URL is unusually long, typical of phishing',
                    'risk': 'MEDIUM'
                })
                risk_score += 0.15
            
            # No findings = site looks clean
            if not findings:
                findings.append({
                    'type': 'success',
                    'title': 'URL Structure Safe',
                    'description': 'URL appears to follow normal domain structure',
                    'risk': 'LOW'
                })
        
        except:
            pass
        
        return findings, min(risk_score, 1.0)
