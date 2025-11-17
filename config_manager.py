#!/usr/bin/env python3
"""
Configuration Management Module
Handles loading and creating configuration files for API keys
"""

import json
import os

class ConfigManager:
    def __init__(self, config_file='config.json'):
        """Initialize configuration manager"""
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Config file {self.config_file} not found. Creating sample config...")
            return self.create_sample_config()
    
    def create_sample_config(self):
        """Create sample configuration file"""
        sample_config = {
            "virustotal": {
                "api_key": "fc974c15d6ad35356583918866ba6f632c372ae3285ca7b4e81a8cb42f02b8d7"
            },
            "abuseipdb": {
                "api_key": "810aba1e4611500f0bf50f3c4f67f2c6fd6d286bf12da5bd55a9c86ca3a3a1fc5d421500f4ef8036"
            },
            "mxtoolbox": {
                "api_key": "619c0ad1-ad04-480b-810c-4a1d94694ec1"
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        
        print(f"Sample config created at {self.config_file}. Please add your API keys.")
        return sample_config
    
    def get_api_key(self, service):
        """Get API key for a specific service"""
        return self.config.get(service, {}).get('api_key')
    
    def get_config(self):
        """Get the entire configuration"""
        return self.config 