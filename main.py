#!/usr/bin/env python3
import argparse
import sys
import os
import glob
import concurrent.futures
from urllib.parse import urlparse

# Import our modules
from config_manager import ConfigManager
from email_parser import EmailParser
from phishing_analyzer import PhishingAnalyzer
from threat_intelligence import ThreatIntelligence
from report_generator import ReportGenerator

class PhishScan:
    def __init__(self, config_file='config.json'):
        
        self.config_manager = ConfigManager(config_file)
        self.email_parser = EmailParser()
        self.phishing_analyzer = PhishingAnalyzer()
        self.threat_intelligence = ThreatIntelligence(self.config_manager)
        self.report_generator = ReportGenerator()
    
    def select_eml_file(self):
        """Interactive EML file selection or input path"""
        print("PhishScan - Phishing Email Analysis Tool")
        print("=" * 50)
        
        # Find all EML files in current directory
        eml_files = glob.glob("*.eml")
        
        if not eml_files:
            print("No .eml files found in current directory.")
            print("\nTo analyze an email, you need a .eml file.")
            print("You can:")
            print("1. Place a .eml file in this directory")
            print("2. Provide the full path to a .eml file")
            print("3. Use: ./phishscan --eml_file /path/to/email.eml")
            print()
            
            while True:
                eml_file = input("Enter the path to your .eml file (or 'quit' to exit): ").strip()
                
                if eml_file.lower() in ['quit', 'exit', 'q']:
                    return None
                
                # Remove leading/trailing quotes if present
                if (eml_file.startswith("'") and eml_file.endswith("'")) or (eml_file.startswith('"') and eml_file.endswith('"')):
                    eml_file = eml_file[1:-1].strip()
                
                # Check if file exists
                if not os.path.exists(eml_file):
                    print(f"❌ File not found: {eml_file}")
                    print("Please check the path and try again.")
                    continue
                
                # Check if it's an .eml file
                if not eml_file.lower().endswith('.eml'):
                    print(f"❌ File is not an .eml file: {eml_file}")
                    print("Please provide a file with .eml extension.")
                    continue
                
                # File is valid
                print(f"✅ Found valid EML file: {eml_file}")
                return eml_file
        
        if len(eml_files) == 1:
            print(f"Found EML file: {eml_files[0]}")
            return eml_files[0]
        
        print("Found multiple EML files:")
        for i, file in enumerate(eml_files, 1):
            print(f"  {i}. {file}")
        
        while True:
            try:
                choice = input(f"\nSelect EML file (1-{len(eml_files)}) or 'q' to quit: ")
                
                if choice.lower() in ['quit', 'exit', 'q']:
                    return None
                
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(eml_files):
                    return eml_files[choice_idx]
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a valid number or 'q' to quit.")
    
    def analyze_email(self, eml_file):
        """Main analysis function with threaded API checks"""
        print(f"Analyzing email: {eml_file}")
        print("=" * 50)
        
        # Extract headers
        msg, headers = self.email_parser.extract_headers(eml_file)
        if not msg:
            return None
        
        # Extract URLs and body
        urls, body = self.email_parser.extract_urls(msg)
        print(f"Found {len(urls)} URLs")
        
        # Extract IPs
        ips = self.email_parser.extract_ips(headers)
        print(f"Found {len(ips)} unique public IPs")
        
        # Analyze phishing indicators
        indicators = self.phishing_analyzer.analyze_phishing_indicators(msg, headers, urls, body)
        print(f"Found {len(indicators)} potential indicators")
        
        # Prepare domain list
        domains = list(set([urlparse(url).netloc for url in urls]))
        
        # Initialize analysis results
        analysis_results = {
            'urls': {}, 'ips': {}, 'vt_ips': {}, 'vt_domains': {},
            'mxtoolbox_blacklist': {}, 'mxtoolbox_mx': {}, 'mxtoolbox_dmarc': {}
        }
        
        # Threaded API checks
        print("\nPerforming threat intelligence checks...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # VirusTotal URL checks
            vt_url_futures = {executor.submit(self.threat_intelligence.check_virustotal_url, url): url for url in urls[:5]}
            
            # AbuseIPDB IP checks
            abuseipdb_futures = {executor.submit(self.threat_intelligence.check_abuseipdb, ip): ip for ip in ips[:5]}
            
            # VirusTotal IP checks
            vt_ip_futures = {executor.submit(self.threat_intelligence.check_virustotal_ip, ip): ip for ip in ips[:3]}
            
            # VirusTotal Domain checks
            vt_domain_futures = {executor.submit(self.threat_intelligence.check_virustotal_domain, domain): domain for domain in domains[:3]}
            
            # MXToolbox Blacklist checks
            mxtoolbox_blacklist_futures = {executor.submit(self.threat_intelligence.check_mxtoolbox_blacklist, domain): domain for domain in domains[:3]}
            
            # MXToolbox MX checks
            mxtoolbox_mx_futures = {executor.submit(self.threat_intelligence.check_mxtoolbox_mx, domain): domain for domain in domains[:3]}
            
            # MXToolbox DMARC checks
            mxtoolbox_dmarc_futures = {executor.submit(self.threat_intelligence.check_mxtoolbox_dmarc, domain): domain for domain in domains[:3]}
            
            # Process VirusTotal URL results
            print("Processing VirusTotal URL results...")
            for future in concurrent.futures.as_completed(vt_url_futures):
                url = vt_url_futures[future]
                result = future.result()
                if result:
                    analysis_results['urls'][url] = result
                    print(f"  {url}: {result['positives']}/{result['total']} detections")
            
            # Process AbuseIPDB results
            print("Processing AbuseIPDB results...")
            for future in concurrent.futures.as_completed(abuseipdb_futures):
                ip = abuseipdb_futures[future]
                result = future.result()
                if result:
                    analysis_results['ips'][ip] = result
                    print(f"  {ip}: {result['abuse_confidence']}% abuse confidence")
            
            # Process VirusTotal IP results
            print("Processing VirusTotal IP results...")
            for future in concurrent.futures.as_completed(vt_ip_futures):
                ip = vt_ip_futures[future]
                result = future.result()
                if result:
                    analysis_results['vt_ips'][ip] = result
                    print(f"  {ip}: {result['positives']}/{result['total']} detections")
            
            # Process VirusTotal Domain results
            print("Processing VirusTotal Domain results...")
            for future in concurrent.futures.as_completed(vt_domain_futures):
                domain = vt_domain_futures[future]
                result = future.result()
                if result:
                    analysis_results['vt_domains'][domain] = result
                    print(f"  {domain}: {result['positives']}/{result['total']} detections")
            
            # Process MXToolbox Blacklist results
            print("Processing MXToolbox Blacklist results...")
            for future in concurrent.futures.as_completed(mxtoolbox_blacklist_futures):
                domain = mxtoolbox_blacklist_futures[future]
                result = future.result()
                if result:
                    analysis_results['mxtoolbox_blacklist'][domain] = result
                    print(f"  {domain}: {'Blacklisted' if result['blacklisted'] else 'Clean'}")
            
            # Process MXToolbox MX results
            print("Processing MXToolbox MX results...")
            for future in concurrent.futures.as_completed(mxtoolbox_mx_futures):
                domain = mxtoolbox_mx_futures[future]
                result = future.result()
                if result:
                    analysis_results['mxtoolbox_mx'][domain] = result
                    print(f"  {domain}: {len(result.get('Passed', []))} MX records")
            
            # Process MXToolbox DMARC results
            print("Processing MXToolbox DMARC results...")
            for future in concurrent.futures.as_completed(mxtoolbox_dmarc_futures):
                domain = mxtoolbox_dmarc_futures[future]
                result = future.result()
                if result:
                    analysis_results['mxtoolbox_dmarc'][domain] = result
                    print(f"  {domain}: {len(result.get('Passed', []))} DMARC records")
        
        # Calculate risk level
        risk_level = self.phishing_analyzer.calculate_risk_score(indicators)
        
        # Generate reports
        csv_file = self.report_generator.generate_csv_report(headers, indicators, urls, ips, analysis_results)
        summary_file = self.report_generator.generate_summary_report(indicators, analysis_results, risk_level)
        
        # Print summary
        print("\n" + "=" * 50)
        print("ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"Total Indicators: {len(indicators)}")
        print(f"URLs Analyzed: {len(analysis_results['urls'])}")
        print(f"IPs Analyzed (AbuseIPDB): {len(analysis_results['ips'])}")
        print(f"IPs Analyzed (VirusTotal): {len(analysis_results['vt_ips'])}")
        print(f"Domains Analyzed (VirusTotal): {len(analysis_results['vt_domains'])}")
        print(f"Domains Analyzed (MXToolbox Blacklist): {len(analysis_results['mxtoolbox_blacklist'])}")
        print(f"Domains Analyzed (MXToolbox MX): {len(analysis_results['mxtoolbox_mx'])}")
        print(f"Domains Analyzed (MXToolbox DMARC): {len(analysis_results['mxtoolbox_dmarc'])}")
        print(f"\nRISK LEVEL: {risk_level}")
        
        return {
            'csv_file': csv_file,
            'summary_file': summary_file,
            'risk_level': risk_level,
            'indicators': indicators,
            'analysis_results': analysis_results
        }

def main():
    parser = argparse.ArgumentParser(description='PhishScan - Phishing Email Analysis Tool')
    parser.add_argument('--eml_file', help='Path to EML file to analyze (optional)')
    parser.add_argument('--config', default='config.json', help='Config file path')
    
    args = parser.parse_args()
    
    phishscan = PhishScan(args.config)
    
    # Get EML file
    if args.eml_file:
        eml_file = args.eml_file
        if not os.path.exists(eml_file):
            print(f"❌ Error: EML file '{eml_file}' not found")
            print("Please check the file path and try again.")
            sys.exit(1)
        if not eml_file.lower().endswith('.eml'):
            print(f"❌ Error: File '{eml_file}' is not an .eml file")
            print("Please provide a file with .eml extension.")
            sys.exit(1)
    else:
        eml_file = phishscan.select_eml_file()
        if not eml_file:
            print("\nNo EML file selected. Exiting.")
            print("To analyze an email, run:")
            print("  python3 main.py --eml_file /path/to/email.eml")
            print("  or")
            print("  ./phishscan --eml_file /path/to/email.eml")
            sys.exit(0)
    
    # Perform analysis
    print(f"\nStarting analysis of: {eml_file}")
    result = phishscan.analyze_email(eml_file)
    
    if result:
        print(f"\n✅ Analysis complete! Results saved to:")
        print(f"  📊 CSV Report: {result['csv_file']}")
        print(f"  📋 Summary Report: {result['summary_file']}")
        print(f"  📧 Headers: {os.path.join(phishscan.email_parser.output_dir, 'header.txt')}")
        print(f"\n🎯 Risk Level: {result['risk_level']}")
    else:
        print("❌ Analysis failed. Please check the EML file and try again.")

if __name__ == "__main__":
    main() 