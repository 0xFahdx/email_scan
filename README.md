# PhishScan - Modular Phishing Email Analysis Tool

A comprehensive phishing email analysis tool with modular architecture, threaded API checks, and enhanced accuracy.

## 🏗️ Modular Architecture

The tool is now separated into logical modules:

### 📁 File Structure
```
├── main.py                 # Main application orchestrator
├── config_manager.py       # Configuration and API key management
├── email_parser.py         # Email parsing and header extraction
├── phishing_analyzer.py    # Phishing indicator detection
├── threat_intelligence.py  # API checks (VirusTotal, AbuseIPDB, MXToolbox)
├── report_generator.py     # Report generation (CSV, summary)
├── phishscan              # Command-line wrapper script
├── config.json            # API configuration file
└── README.md              # This file
```

## 🚀 Features

### ✨ Enhanced Accuracy
- **Improved regex patterns** for URL and IP extraction
- **Extended phishing keywords** and suspicious TLD detection
- **Brand impersonation detection**
- **Display name vs email mismatch detection**
- **Reply-To analysis**
- **Content analysis** for urgency and action words

### ⚡ Threaded Performance
- **Parallel API checks** using ThreadPoolExecutor
- **No more waiting** for sequential API calls
- **Faster analysis** with concurrent requests

### 🔍 Comprehensive Threat Intelligence
- **VirusTotal**: URL, IP, and domain checks
- **AbuseIPDB**: IP reputation analysis
- **MXToolbox**: Blacklist, MX, DMARC, and DNS checks
- **DNS Analysis**: MX, A, TXT, and SPF records

### 📊 Enhanced Reporting
- **CSV Report**: Detailed indicators and API results
- **Summary Report**: Human-readable analysis summary
- **Header Analysis**: Complete email header breakdown
- **Risk Scoring**: Automated risk level calculation

## 🛠️ Installation

1. **Clone or download** the files to your desired directory
2. **Make the script executable**:
   ```bash
   chmod +x phishscan
   ```
3. **Install dependencies**:
   ```bash
   pip3 install requests dnspython
   ```
4. **Configure API keys** in `config.json` (created automatically on first run)

## 📋 Usage

### Command Line Interface

**Interactive mode** (recommended):
```bash
./phishscan
```

**Direct file analysis**:
```bash
./phishscan --eml_file /path/to/email.eml
```

**Custom config file**:
```bash
./phishscan --config my_config.json --eml_file email.eml
```

### Programmatic Usage

```python
from main import PhishScan

# Initialize the tool
phishscan = PhishScan('config.json')

# Analyze an email
result = phishscan.analyze_email('email.eml')

# Access results
print(f"Risk Level: {result['risk_level']}")
print(f"Indicators: {len(result['indicators'])}")
```

## 📁 Output Files

All results are saved to `~/Desktop/phishscan result/`:

- **`indicator_phishing.csv`**: Detailed CSV report with all findings
- **`analysis_summary.txt`**: Human-readable summary with recommendations
- **`header.txt`**: Complete email header analysis

## 🔧 Configuration

The `config.json` file contains API keys for threat intelligence services:

```json
{
  "virustotal": {
    "api_key": "your_virustotal_api_key"
  },
  "abuseipdb": {
    "api_key": "your_abuseipdb_api_key"
  },
  "mxtoolbox": {
    "api_key": "your_mxtoolbox_api_key"
  }
}
```

## 🎯 API Services Used

### VirusTotal
- URL reputation checking
- IP address analysis
- Domain reputation analysis

### AbuseIPDB
- IP abuse confidence scoring
- Geographic location
- Usage type classification

### MXToolbox
- Domain blacklist checking
- MX record analysis
- DMARC policy checking
- DNS record analysis

## 🔍 Phishing Indicators Detected

### High Severity
- Suspicious TLDs (.tk, .ml, .ga, etc.)
- IP addresses in URLs
- Brand impersonation attempts
- Authentication failures (SPF, DKIM, DMARC)

### Medium Severity
- URL shorteners
- Numeric characters in sender addresses
- Display name vs email mismatches
- Reply-To address differences
- Multiple urgency indicators
- Multiple action words

### Low Severity
- Suspicious keywords in subject
- General phishing patterns

## 🚨 Risk Levels

- **HIGH**: Score ≥ 10 - Immediate action required
- **MEDIUM**: Score 5-9 - Manual review recommended
- **LOW**: Score < 5 - Standard monitoring

## 🔄 Migration from Old Version

If you're upgrading from the old single-file version:

1. **Backup** your existing `phising.py` file
2. **Copy** your `config.json` if you have one
3. **Use** the new modular structure
4. **Enjoy** faster, more accurate analysis!

## 🤝 Contributing

The modular structure makes it easy to:
- Add new threat intelligence APIs
- Implement additional phishing indicators
- Create custom report formats
- Extend email parsing capabilities

This Example from https://github.com/rf-peixoto/phishing_pot/tree/main/email 

<img width="1470" height="956" alt="Screenshot 2025-11-17 at 2 08 53 PM" src="https://github.com/user-attachments/assets/9b584dd8-361e-40f6-9658-c33d613a0cf9" />
