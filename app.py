"""
PhishGuard - Phishing Detection System
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from feature_extraction import URLFeatureExtractor
import os

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_SCRAPER = True
    print("[OK] Scraper dependencies loaded", flush=True)
except:
    HAS_SCRAPER = False
    print("[ERROR] Scraper dependencies NOT found", flush=True)

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'index.html')
        print(f"[HOME] Loading: {file_path}", flush=True)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"[HOME] Loaded {len(content)} bytes", flush=True)
            return content
    except Exception as e:
        print(f"[HOME_ERROR] {str(e)}", flush=True)
        return f'Error loading page: {str(e)}'

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.json.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        # Store original URL for protocol checking
        original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"ANALYZE: {url}", flush=True)
        
        # URL Analysis
        features = URLFeatureExtractor.extract_features(url)
        url_findings, url_risk = URLFeatureExtractor.analyze_url_structure(url)
        if not isinstance(url_findings, list):
            url_findings = []
        if url_risk is None:
            url_risk = 0.0
        
        # Content Analysis
        content_risk = 0.0
        content_findings = []
        
        if HAS_SCRAPER:
            try:
                content_risk, content_findings = check_website_content(url)
                if not isinstance(content_findings, list):
                    content_findings = []
                print(f"CONTENT_RISK: {content_risk}", flush=True)
            except Exception as e:
                print(f"CONTENT_ERROR: {str(e)}", flush=True)
                content_findings = []
        else:
            print("NO_SCRAPER", flush=True)
        
        # Combine scores - URL risk is DOMINANT
        # URL analysis: 70% weight, Content analysis: 30% weight
        final_score = (url_risk * 0.7) + (content_risk * 0.3)
        
        print(f"SCORES - URL: {url_risk:.2f}, Content: {content_risk:.2f}, Final: {final_score:.2f}", flush=True)
        
        # Combine findings
        all_findings = url_findings + content_findings
        if not all_findings:
            all_findings = [{'type': 'success', 'title': 'Website Analysis', 'description': 'Website appears to be legitimate', 'risk': 'LOW'}]
        
        # Determine verdict based on combined risk
        if final_score >= 0.40:
            status = 'Phishing'
        elif final_score >= 0.25:
            status = 'Suspicious'
        else:
            status = 'Safe'
        
        print(f"VERDICT: {status} score={final_score}", flush=True)
        
        # Summary
        high_count = len([f for f in all_findings if f.get('risk') == 'HIGH'])
        medium_count = len([f for f in all_findings if f.get('risk') == 'MEDIUM'])
        
        if status == 'Phishing':
            summary = f"🚨 PHISHING DETECTED - {high_count} critical phishing patterns. DO NOT enter personal data."
        elif status == 'Suspicious':
            summary = f"⚠️ SUSPICIOUS - {medium_count} concerns detected. Use caution."
        else:
            summary = "✅ SAFE - Website looks legitimate."
        
        return jsonify({
            'status': status,
            'score': int(final_score * 100),
            'confidence': min(int(abs(final_score - 0.5) * 200), 100),
            'url_risk': int(url_risk * 100),
            'content_risk': int(content_risk * 100),
            'summary': summary,
            'findings': all_findings,
            'details': {}
        })
    
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500

def calculate_url_risk(features):
    """Calculate URL risk - DIRECT analysis"""
    # Ignore features, analyze URL directly in analyze_url_structure
    # This function just normalizes the URL findings
    return 0.0  # Let analyze_url_structure handle all URL risk

def check_website_content(url):
    """Analyze website content for phishing indicators"""
    headers = {'User-Agent': 'Mozilla/5.0'}
    findings = []
    risk = 0.0
    
    try:
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        text = soup.get_text().lower()
        
        # Check for phishing keywords
        critical_keywords = [
            'verify your account',
            'confirm your password', 
            'unusual activity',
            'click here immediately',
            'verify identity',
            'update payment',
            'confirm account',
            'urgent action required'
        ]
        found_keywords = [w for w in critical_keywords if w in text]
        
        # Check for suspicious forms
        pass_fields = len(soup.find_all('input', {'type': 'password'})) > 0
        email_fields = len(soup.find_all('input', {'type': 'email'}))
        
        # Check for other phishing indicators
        has_suspicious_forms = pass_fields or (email_fields > 0)
        
        # Risk calculation: ANY phishing keyword + forms = phishing
        # Multiple keywords = increase risk
        if found_keywords and has_suspicious_forms:
            risk = 0.75 + (len(found_keywords) * 0.05)  # 75% + 5% per keyword
            findings.append({
                'type': 'danger',
                'title': 'Phishing Content Detected',
                'description': f'Found phishing indicators: {", ".join(found_keywords[:3])}',
                'risk': 'HIGH'
            })
        elif found_keywords:
            # Phishing text without forms - still suspicious
            risk = 0.50
            findings.append({
                'type': 'warning',
                'title': 'Suspicious Content',
                'description': f'Found suspicious keywords: {", ".join(found_keywords[:2])}',
                'risk': 'MEDIUM'
            })
        elif pass_fields and not found_keywords:
            # Password form without phishing text - slight concern
            risk = 0.30
            findings.append({
                'type': 'info',
                'title': 'Unexpected Login Form',
                'description': 'Website has password input field',
                'risk': 'LOW'
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
        # Network/connection errors = SUSPICIOUS (phishing sites often block scrapers)
        findings.append({
            'type': 'warning',
            'title': 'Content Not Fully Analyzed',
            'description': 'Website could not be accessed',
            'risk': 'MEDIUM'
        })
        return 0.40, findings

if __name__ == '__main__':
    print('[SERVER] PhishGuard Starting...')
    print('[SERVER] Open: http://localhost:8000')
    app.run(host='127.0.0.1', port=8000, debug=False)

