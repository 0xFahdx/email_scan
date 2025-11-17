#!/usr/bin/env python3
"""
Email Parser Module
Handles email parsing, header extraction, URL extraction, and IP extraction
"""

import email
import re
import os
from datetime import datetime
from urllib.parse import urlparse
from email.header import decode_header

class EmailParser:
    def __init__(self, output_dir=None):
        """Initialize email parser"""
        self.output_dir = output_dir or os.path.expanduser('~/Desktop/phishscan result')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def decode_email_header(self, header):
        """Decode email header handling various encodings"""
        if not header:
            return ""
        
        decoded_parts = decode_header(header)
        decoded_string = ""
        
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    decoded_string += part.decode(encoding or 'utf-8')
                except (UnicodeDecodeError, LookupError):
                    decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += part
        
        return decoded_string
    
    def anonymize_email(self, email_address):
        """Replace sensitive email addresses with x@outlook.com"""
        if email_address and '@' in email_address:
            return "x@outlook.com"
        return email_address
    
    def extract_headers(self, eml_file):
        """Extract and save email headers to header.txt file"""
        try:
            with open(eml_file, 'rb') as f:
                msg = email.message_from_bytes(f.read())
            
            # Extract key headers
            headers = {
                'Message-ID': self.decode_email_header(msg.get('Message-ID', '')),
                'Date': self.decode_email_header(msg.get('Date', '')),
                'From': self.decode_email_header(msg.get('From', '')),  # Keep sender unchanged
                'To': self.anonymize_email(self.decode_email_header(msg.get('To', ''))),  # Only anonymize receiver
                'Subject': self.decode_email_header(msg.get('Subject', '')),
                'Reply-To': self.decode_email_header(msg.get('Reply-To', '')),  # Keep unchanged
                'Return-Path': self.decode_email_header(msg.get('Return-Path', '')),  # Keep unchanged
                'Received': [],
                'X-Originating-IP': self.decode_email_header(msg.get('X-Originating-IP', '')),
                'X-Sender-IP': self.decode_email_header(msg.get('X-Sender-IP', '')),
                'Authentication-Results': self.decode_email_header(msg.get('Authentication-Results', '')),
                'DKIM-Signature': self.decode_email_header(msg.get('DKIM-Signature', '')),
                'SPF': self.decode_email_header(msg.get('Received-SPF', '')),
                'DMARC': self.decode_email_header(msg.get('DMARC', ''))
            }
            
            # Extract all Received headers
            for received in msg.get_all('Received', []):
                headers['Received'].append(self.decode_email_header(received))
            
            # Save headers to header.txt file
            header_path = os.path.join(self.output_dir, 'header.txt')
            with open(header_path, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("EMAIL HEADER ANALYSIS\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"EML File: {eml_file}\n")
                f.write("=" * 60 + "\n\n")
                
                for key, value in headers.items():
                    if key == 'Received':
                        f.write(f"{key}:\n")
                        for i, received in enumerate(value, 1):
                            f.write(f"  [{i}] {received}\n")
                        f.write("\n")
                    else:
                        f.write(f"{key}: {value}\n")
                
                f.write("\n" + "=" * 60 + "\n")
            
            print(f"Headers saved to: {header_path}")
            return msg, headers
            
        except Exception as e:
            print(f"Error extracting headers: {str(e)}")
            return None, None
    
    def extract_urls(self, msg):
        """Extract URLs from email content with improved regex"""
        urls = set()
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        
        # Improved URL regex
        url_pattern = r'(https?://|www\.)[\w\-]+(\.[\w\-]+)+([/?#][^\s"<>]*)?'
        found_urls = re.findall(url_pattern, body)
        
        for match in found_urls:
            url = ''.join(match)
            if not url.startswith('http'):
                url = 'http://' + url
            urls.add(url)
        
        return list(urls), body
    
    def extract_ips(self, headers):
        """Extract IP addresses from headers with improved regex"""
        ips = set()
        ip_pattern = r'(?<![\d.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![\d.])'
        
        for received in headers.get('Received', []):
            found_ips = re.findall(ip_pattern, received)
            for ip in found_ips:
                if not self.is_private_ip(ip):
                    ips.add(ip)
        
        for ip_header in ['X-Originating-IP', 'X-Sender-IP']:
            if headers.get(ip_header):
                found_ips = re.findall(ip_pattern, headers[ip_header])
                for ip in found_ips:
                    if not self.is_private_ip(ip):
                        ips.add(ip)
        
        return list(ips)
    
    def is_private_ip(self, ip):
        """Check if IP is private/internal"""
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        
        try:
            parts = [int(part) for part in parts]
        except ValueError:
            return True
        
        # Private IP ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        
        return False 