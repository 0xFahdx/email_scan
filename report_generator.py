#!/usr/bin/env python3

import csv
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir=None):
        """Initialize report generator"""
        self.output_dir = output_dir or os.path.expanduser('~/Desktop/phishscan result')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_csv_report(self, headers, indicators, urls, ips, analysis_results):
        """Generate comprehensive CSV report"""
        csv_file = os.path.join(self.output_dir, "indicator_phishing.csv")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Timestamp', 'Type', 'Indicator', 'Value', 'Severity',
                'API_Source', 'API_Result', 'Recommendation'
            ])
            
            # Write basic indicators
            for indicator in indicators:
                writer.writerow([
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    indicator['type'],
                    indicator['indicator'],
                    indicator['value'],
                    indicator['severity'],
                    '',
                    '',
                    'Manual review required'
                ])
            
            # Write URL analysis results
            for url, result in analysis_results.get('urls', {}).items():
                if result:
                    severity = 'High' if result.get('positives', 0) > 0 else 'Low'
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'URL',
                        'VirusTotal scan result',
                        url,
                        severity,
                        'VirusTotal',
                        f"Detections: {result.get('positives', 0)}/{result.get('total', 0)}",
                        'Block if detections > 0'
                    ])
            
            # Write IP analysis results (AbuseIPDB)
            for ip, result in analysis_results.get('ips', {}).items():
                if result:
                    confidence = result.get('abuse_confidence', 0)
                    severity = 'High' if confidence > 50 else 'Medium' if confidence > 25 else 'Low'
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'IP',
                        'AbuseIPDB reputation check',
                        ip,
                        severity,
                        'AbuseIPDB',
                        f"Abuse confidence: {confidence}%",
                        'Block if confidence > 50%'
                    ])
            
            # Write VirusTotal IP results
            for ip, result in analysis_results.get('vt_ips', {}).items():
                if result:
                    severity = 'High' if result.get('positives', 0) > 0 else 'Low'
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'IP',
                        'VirusTotal IP scan result',
                        ip,
                        severity,
                        'VirusTotal',
                        f"Detections: {result.get('positives', 0)}/{result.get('total', 0)}",
                        'Block if detections > 0'
                    ])
            
            # Write VirusTotal domain results
            for domain, result in analysis_results.get('vt_domains', {}).items():
                if result:
                    severity = 'High' if result.get('positives', 0) > 0 else 'Low'
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'Domain',
                        'VirusTotal domain scan result',
                        domain,
                        severity,
                        'VirusTotal',
                        f"Detections: {result.get('positives', 0)}/{result.get('total', 0)}",
                        'Block if detections > 0'
                    ])
            
            # Write MXToolbox blacklist results
            for domain, result in analysis_results.get('mxtoolbox_blacklist', {}).items():
                if result:
                    severity = 'High' if result.get('blacklisted', False) else 'Low'
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'Domain',
                        'MXToolbox blacklist check',
                        domain,
                        severity,
                        'MXToolbox',
                        f"Blacklisted: {result.get('blacklisted', False)}",
                        'Block if blacklisted'
                    ])
            
            # Write MXToolbox MX results
            for domain, result in analysis_results.get('mxtoolbox_mx', {}).items():
                if result:
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'Domain',
                        'MXToolbox MX check',
                        domain,
                        'Info',
                        'MXToolbox',
                        f"MX records found: {len(result.get('Passed', []))}",
                        'Review MX configuration'
                    ])
            
            # Write MXToolbox DMARC results
            for domain, result in analysis_results.get('mxtoolbox_dmarc', {}).items():
                if result:
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'Domain',
                        'MXToolbox DMARC check',
                        domain,
                        'Info',
                        'MXToolbox',
                        f"DMARC records found: {len(result.get('Passed', []))}",
                        'Review DMARC configuration'
                    ])
        
        print(f"Report saved to: {csv_file}")
        return csv_file
    
    def generate_summary_report(self, indicators, analysis_results, risk_level):
        """Generate a summary text report"""
        summary_file = os.path.join(self.output_dir, "analysis_summary.txt")
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("PHISHING EMAIL ANALYSIS SUMMARY\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            # Risk Level
            f.write(f"OVERALL RISK LEVEL: {risk_level}\n\n")
            
            # Indicator Summary
            f.write("INDICATOR SUMMARY:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Indicators: {len(indicators)}\n")
            
            high_count = sum(1 for i in indicators if i['severity'] == 'High')
            medium_count = sum(1 for i in indicators if i['severity'] == 'Medium')
            low_count = sum(1 for i in indicators if i['severity'] == 'Low')
            
            f.write(f"High Severity: {high_count}\n")
            f.write(f"Medium Severity: {medium_count}\n")
            f.write(f"Low Severity: {low_count}\n\n")
            
            # API Analysis Summary
            f.write("API ANALYSIS SUMMARY:\n")
            f.write("-" * 20 + "\n")
            f.write(f"URLs Analyzed (VirusTotal): {len(analysis_results.get('urls', {}))}\n")
            f.write(f"IPs Analyzed (AbuseIPDB): {len(analysis_results.get('ips', {}))}\n")
            f.write(f"IPs Analyzed (VirusTotal): {len(analysis_results.get('vt_ips', {}))}\n")
            f.write(f"Domains Analyzed (VirusTotal): {len(analysis_results.get('vt_domains', {}))}\n")
            f.write(f"Domains Analyzed (MXToolbox Blacklist): {len(analysis_results.get('mxtoolbox_blacklist', {}))}\n")
            f.write(f"Domains Analyzed (MXToolbox MX): {len(analysis_results.get('mxtoolbox_mx', {}))}\n")
            f.write(f"Domains Analyzed (MXToolbox DMARC): {len(analysis_results.get('mxtoolbox_dmarc', {}))}\n\n")
            
            # Detailed Indicators
            f.write("DETAILED INDICATORS:\n")
            f.write("-" * 20 + "\n")
            for i, indicator in enumerate(indicators, 1):
                f.write(f"{i}. [{indicator['severity']}] {indicator['type']}: {indicator['indicator']}\n")
                f.write(f"   Value: {indicator['value']}\n\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS:\n")
            f.write("-" * 20 + "\n")
            if risk_level == 'HIGH':
                f.write("- IMMEDIATE ACTION REQUIRED\n")
                f.write("- Block all associated IPs and domains\n")
                f.write("- Quarantine the email\n")
                f.write("- Report to security team\n")
            elif risk_level == 'MEDIUM':
                f.write("- Manual review recommended\n")
                f.write("- Monitor for similar emails\n")
                f.write("- Consider blocking suspicious indicators\n")
            else:
                f.write("- Low risk, standard monitoring\n")
                f.write("- No immediate action required\n")
        
        print(f"Summary report saved to: {summary_file}")
        return summary_file 