"""Quick test of the analysis logic"""
from feature_extraction import URLFeatureExtractor
import requests
from bs4 import BeautifulSoup

def check_website_content(url):
    """Analyze website content - ONLY flag CONFIRMED phishing with multiple indicators"""
    headers = {'User-Agent': 'Mozilla/5.0'}
    findings = []
    risk = 0.0
    
    try:
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        text = soup.get_text().lower()
        
        # ONLY flag if MULTIPLE critical keywords present
        critical_keywords = [
            'verify your account',
            'confirm your password', 
            'unusual activity',
            'click here immediately'
        ]
        found_keywords = [w for w in critical_keywords if w in text]
        
        # Multiple indicators needed
        has_phishing_text = len(found_keywords) >= 2
        pass_fields = len(soup.find_all('input', {'type': 'password'})) > 0
        
        # Only flag if BOTH phishing text AND forms
        if has_phishing_text and pass_fields:
            risk = 0.70
            findings.append({
                'type': 'danger',
                'title': 'Multiple Phishing Indicators',
                'description': f'Phishing keywords + password form: {", ".join(found_keywords[:2])}',
                'risk': 'HIGH'
            })
        else:
            # Normal site
            findings.append({
                'type': 'success',
                'title': 'Website Content Safe',
                'description': 'No phishing patterns detected',
                'risk': 'LOW'
            })
        
        # HTTPS status
        if url.startswith('https'):
            findings.append({
                'type': 'success',
                'title': 'HTTPS Secure',
                'description': 'Website uses HTTPS encryption',
                'risk': 'LOW'
            })
        
        return risk, findings
        
    except Exception as e:
        # Network errors = NOT suspicious
        findings.append({
            'type': 'info',
            'title': 'Content Not Fully Analyzed',
            'description': f'Website content could not be accessed: {str(e)}',
            'risk': 'LOW'
        })
        return 0.0, findings

# Test
test_urls = ['google.com', 'facebook.com', 'amazon.com']

for url in test_urls:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n=== Testing {url} ===")
    features = URLFeatureExtractor.extract_features(url)
    print(f"Features: {features}")
    
    content_risk, content_findings = check_website_content(url)
    print(f"Content Risk: {content_risk}")
    print(f"Content Findings: {len(content_findings)} findings")
    for f in content_findings:
        print(f"  - {f['title']} ({f['risk']})")
    
    # Calculate final score
    url_risk = 0.0
    final_score = content_risk
    status = 'Safe' if final_score < 0.60 else ('Suspicious' if final_score < 0.80 else 'Phishing')
    print(f"Final Score: {final_score}")
    print(f"Status: {status}")
