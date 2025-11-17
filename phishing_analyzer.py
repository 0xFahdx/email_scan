#!/usr/bin/env python3
"""
Phishing Analyzer Module
Handles phishing indicator detection and analysis
"""

import re
from urllib.parse import urlparse

class PhishingAnalyzer:
    def __init__(self):
        """Initialize phishing analyzer"""
        # Common phishing keywords
        self.phishing_keywords = [
            'urgent', 'verify', 'suspend', 'limited time', 'click here',
            'confirm identity', 'update payment', 'account locked',
            'immediate action', 'expires today', 'winner', 'congratulations',
            'lottery', 'inheritance', 'prince', 'funds', 'transfer',
            'refund', 'tax refund', 'irs', 'paypal', 'amazon', 'microsoft',
            'apple', 'google', 'security alert', 'unusual activity',
            'account suspended', 'verify your account', 'security update',
            'password expired', 'login attempt', 'unusual login',
            'account verification', 'payment confirmation', 'invoice',
            'bank transfer', 'credit card', 'social security', 'tax return'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.stream', '.science', '.racing', '.cricket', '.party',
            '.xyz', '.online', '.site', '.website', '.space', '.tech',
            '.digital', '.cloud', '.app', '.dev', '.io', '.co'
        ]
        
        # URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'is.gd', 'v.gd', 'ow.ly', 'su.pr', 'twurl.nl', 'snipurl.com',
            'short.to', 'BudURL.com', 'ping.fm', 'tr.im', 'zip.net',
            'snurl.com', 'adjix.com', 'redir.ec', 'rb.gy', 'tiny.cc'
        ]
    
    def analyze_phishing_indicators(self, msg, headers, urls, body):
        """Analyze various phishing indicators"""
        indicators = []
        
        # Subject analysis
        subject = headers.get('Subject', '')
        if subject:
            if any(keyword in subject.lower() for keyword in self.phishing_keywords):
                indicators.append({
                    'type': 'Subject',
                    'indicator': 'Suspicious keywords in subject',
                    'value': subject[:100],
                    'severity': 'Medium'
                })
        
        # Sender analysis
        from_addr = headers.get('From', '')
        if from_addr != "x@outlook.com":  # Only analyze if not anonymized
            if re.search(r'[0-9]{3,}', from_addr):
                indicators.append({
                    'type': 'Sender',
                    'indicator': 'Numeric characters in sender address',
                    'value': from_addr,
                    'severity': 'Medium'
                })
            
            # Check for display name vs email mismatch
            if '<' in from_addr and '>' in from_addr:
                display_name = from_addr.split('<')[0].strip()
                email_part = from_addr.split('<')[1].split('>')[0]
                if display_name and '@' in display_name and display_name != email_part:
                    indicators.append({
                        'type': 'Sender',
                        'indicator': 'Display name vs email mismatch',
                        'value': from_addr,
                        'severity': 'Medium'
                    })
        
        # Reply-To analysis
        reply_to = headers.get('Reply-To', '')
        if reply_to and reply_to != from_addr and reply_to != "x@outlook.com":
            indicators.append({
                'type': 'Reply-To',
                'indicator': 'Reply-To different from From address',
                'value': f"From: {from_addr}, Reply-To: {reply_to}",
                'severity': 'Medium'
            })
        
        # URL analysis
        for url in urls:
            parsed = urlparse(url)
            
            # Check for suspicious TLDs
            if any(tld in parsed.netloc.lower() for tld in self.suspicious_tlds):
                indicators.append({
                    'type': 'URL',
                    'indicator': 'Suspicious TLD',
                    'value': url,
                    'severity': 'High'
                })
            
            # Check for URL shorteners
            if any(shortener in parsed.netloc.lower() for shortener in self.url_shorteners):
                indicators.append({
                    'type': 'URL',
                    'indicator': 'URL shortener detected',
                    'value': url,
                    'severity': 'Medium'
                })
            
            # Check for suspicious patterns
            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', parsed.netloc):
                indicators.append({
                    'type': 'URL',
                    'indicator': 'IP address in URL',
                    'value': url,
                    'severity': 'High'
                })
            
            # Check for brand impersonation
            brand_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix', 'spotify']
            for brand in brand_keywords:
                if brand in parsed.netloc.lower() and brand not in parsed.netloc.split('.')[0]:
                    indicators.append({
                        'type': 'URL',
                        'indicator': 'Potential brand impersonation',
                        'value': url,
                        'severity': 'High'
                    })
        
        # Authentication analysis
        auth_results = headers.get('Authentication-Results', '')
        if 'spf=fail' in auth_results.lower():
            indicators.append({
                'type': 'Authentication',
                'indicator': 'SPF authentication failed',
                'value': auth_results,
                'severity': 'High'
            })
        
        if 'dkim=fail' in auth_results.lower():
            indicators.append({
                'type': 'Authentication',
                'indicator': 'DKIM authentication failed',
                'value': auth_results,
                'severity': 'High'
            })
        
        if 'dmarc=fail' in auth_results.lower():
            indicators.append({
                'type': 'Authentication',
                'indicator': 'DMARC authentication failed',
                'value': auth_results,
                'severity': 'High'
            })
        
        # Body content analysis
        if body:
            # Check for urgency indicators
            urgency_words = ['urgent', 'immediate', 'now', 'today', 'expires', 'limited time']
            urgency_count = sum(1 for word in urgency_words if word in body.lower())
            if urgency_count >= 2:
                indicators.append({
                    'type': 'Content',
                    'indicator': 'Multiple urgency indicators in body',
                    'value': f"Found {urgency_count} urgency words",
                    'severity': 'Medium'
                })
            
            # Check for action words
            action_words = ['click', 'verify', 'confirm', 'update', 'login', 'sign in']
            action_count = sum(1 for word in action_words if word in body.lower())
            if action_count >= 3:
                indicators.append({
                    'type': 'Content',
                    'indicator': 'Multiple action words in body',
                    'value': f"Found {action_count} action words",
                    'severity': 'Medium'
                })
        
        return indicators
    
    def calculate_risk_score(self, indicators):
        """Calculate overall risk score based on indicators"""
        score = 0
        for indicator in indicators:
            if indicator['severity'] == 'High':
                score += 3
            elif indicator['severity'] == 'Medium':
                score += 2
            else:
                score += 1
        
        if score >= 10:
            return 'HIGH'
        elif score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW' 