#!/usr/bin/env python3

import requests
import dns.resolver
import time

class ThreatIntelligence:
    def __init__(self, config_manager):
        """Initialize threat intelligence with configuration"""
        self.config = config_manager
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingAnalyzer/1.0 (SOC Analysis Tool)'
        })
    
    def check_virustotal_url(self, url):
        """Check URL against VirusTotal"""
        api_key = self.config.get_api_key('virustotal')
        if not api_key:
            return None
        
        try:
            vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {
                'apikey': api_key,
                'resource': url
            }
            
            response = self.session.get(vt_url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return {
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'scan_date': data.get('scan_date', ''),
                        'permalink': data.get('permalink', '')
                    }
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
        
        return None
    
    def check_virustotal_ip(self, ip):
        """Check IP against VirusTotal"""
        api_key = self.config.get_api_key('virustotal')
        if not api_key:
            return None
        
        try:
            vt_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {
                'apikey': api_key,
                'ip': ip
            }
            
            response = self.session.get(vt_url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return {
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'country': data.get('country', ''),
                        'as_owner': data.get('as_owner', ''),
                        'permalink': data.get('permalink', '')
                    }
        except Exception as e:
            print(f"VirusTotal IP API error: {str(e)}")
        
        return None
    
    def check_virustotal_domain(self, domain):
        """Check domain against VirusTotal"""
        api_key = self.config.get_api_key('virustotal')
        if not api_key:
            return None
        
        try:
            vt_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {
                'apikey': api_key,
                'domain': domain
            }
            
            response = self.session.get(vt_url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return {
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'country': data.get('country', ''),
                        'permalink': data.get('permalink', '')
                    }
        except Exception as e:
            print(f"VirusTotal Domain API error: {str(e)}")
        
        return None
    
    def check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB"""
        api_key = self.config.get_api_key('abuseipdb')
        if not api_key:
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = self.session.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_confidence': data.get('data', {}).get('abuseConfidencePercentage', 0),
                    'country': data.get('data', {}).get('countryCode', ''),
                    'usage_type': data.get('data', {}).get('usageType', ''),
                    'reports': data.get('data', {}).get('totalReports', 0)
                }
        except Exception as e:
            print(f"AbuseIPDB API error: {str(e)}")
        
        return None
    
    def check_mxtoolbox_blacklist(self, domain):
        """Check domain against MXToolbox blacklist"""
        api_key = self.config.get_api_key('mxtoolbox')
        if not api_key:
            return None
        
        try:
            url = f'https://api.mxtoolbox.com/api/v1/lookup/blacklist/{domain}'
            headers = {
                'Authorization': api_key
            }
            
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'blacklisted': any(item.get('IsBlacklisted', False) for item in data.get('Passed', [])),
                    'details': data.get('Passed', [])
                }
        except Exception as e:
            print(f"MXToolbox API error: {str(e)}")
        
        return None
    
    def check_mxtoolbox_mx(self, domain):
        """Check MX records using MXToolbox API"""
        api_key = self.config.get_api_key('mxtoolbox')
        if not api_key:
            return None
        
        try:
            url = f'https://api.mxtoolbox.com/api/v1/lookup/mx/{domain}'
            headers = {
                'Authorization': api_key
            }
            
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"MXToolbox MX API error: {str(e)}")
        
        return None
    
    def check_mxtoolbox_dmarc(self, domain):
        """Check DMARC using MXToolbox API"""
        api_key = self.config.get_api_key('mxtoolbox')
        if not api_key:
            return None
        
        try:
            url = f'https://api.mxtoolbox.com/api/v1/lookup/dmarc/{domain}'
            headers = {
                'Authorization': api_key
            }
            
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"MXToolbox DMARC API error: {str(e)}")
        
        return None
    
    def check_mxtoolbox_dns(self, domain):
        """Check DNS using MXToolbox API"""
        api_key = self.config.get_api_key('mxtoolbox')
        if not api_key:
            return None
        
        try:
            url = f'https://api.mxtoolbox.com/api/v1/lookup/dns/{domain}'
            headers = {
                'Authorization': api_key
            }
            
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"MXToolbox DNS API error: {str(e)}")
        
        return None
    
    def perform_dns_analysis(self, domain):
        """Perform DNS analysis using dnspython"""
        dns_info = {}
        
        try:
            # MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(record) for record in mx_records]
        except:
            dns_info['mx_records'] = []
        
        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            dns_info['a_records'] = [str(record) for record in a_records]
        except:
            dns_info['a_records'] = []
        
        try:
            # TXT records (for SPF/DKIM)
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(record) for record in txt_records]
        except:
            dns_info['txt_records'] = []
        
        try:
            # SPF record
            spf_records = dns.resolver.resolve(domain, 'TXT')
            dns_info['spf_records'] = [str(record) for record in spf_records if 'v=spf1' in str(record)]
        except:
            dns_info['spf_records'] = []
        
        return dns_info 