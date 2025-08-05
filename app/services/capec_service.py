# app/services/capec_service.py
import csv
import os
import re
from typing import Dict, List
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class CAPECService:
    """Service for handling CAPEC (Common Attack Pattern Enumeration and Classification) data"""
    
    def __init__(self):
        self.capec_data = []
        self.capec_by_cwe = defaultdict(list)
        self.headers_to_show = {
            "'ID", "Name", "Description", "Likelihood Of Attack", 
            "Typical Severity", "Related Weaknesses", "Mitigations",
            "Prerequisites", "Consequences", "Example Instances"
        }
        self._load_capec_data()
        self._build_cwe_index()
    
    def _load_capec_data(self):
        """Load CAPEC CSV data"""
        # PLACEHOLDER: Replace with your actual path
        capec_csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "2000CAPEC.csv")
        
        try:
            with open(capec_csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                self.capec_data = list(reader)
                self.capec_fieldnames = reader.fieldnames
            logger.info(f"Loaded {len(self.capec_data)} CAPEC entries")
        except FileNotFoundError:
            logger.error(f"CAPEC CSV file not found: {capec_csv_path}")
            self.capec_data = []
        except Exception as e:
            logger.error(f"Error loading CAPEC data: {e}")
            self.capec_data = []
    
    def _build_cwe_index(self):
        """Pre-build an index of CAPEC data by CWE for O(1) lookups"""
        logger.info("Building CAPEC-CWE lookup index...")
        
        for row in self.capec_data:
            weakness_data = row.get("Related Weaknesses", "").strip()
            if weakness_data:
                # Extract CWE numbers
                cwe_numbers = re.findall(r'::(\d+)::', weakness_data)
                for cwe_id in cwe_numbers:
                    self.capec_by_cwe[cwe_id].append({
                        "capec_data": {header: row.get(header, "") for header in self.headers_to_show},
                        "taxonomy_mappings": row.get("Taxonomy Mappings", "")
                    })
        
        logger.info(f"Built CAPEC index for {len(self.capec_by_cwe)} CWEs")
    
    async def get_capec_for_cwes(self, cwe_ids: List[str]) -> List[Dict]:
        """Get CAPEC entries related to the given CWE IDs"""
        capec_entries = []
        seen_capec_ids = set()
        
        for cwe_id in cwe_ids:
            related_capec = self.capec_by_cwe.get(cwe_id, [])
            
            for capec_info in related_capec:
                capec_data = capec_info["capec_data"]
                capec_id = capec_data.get("'ID", "")
                
                # Avoid duplicates
                if capec_id and capec_id not in seen_capec_ids:
                    seen_capec_ids.add(capec_id)
                    
                    # Format CAPEC entry for database storage
                    formatted_entry = {
                        "id": capec_id.replace("'", ""),  # Remove quote if present
                        "name": capec_data.get("Name", ""),
                        "description": capec_data.get("Description", ""),
                        "likelihood": capec_data.get("Likelihood Of Attack", ""),
                        "severity": capec_data.get("Typical Severity", ""),
                        "prerequisites": capec_data.get("Prerequisites", ""),
                        "consequences": capec_data.get("Consequences", ""),
                        "mitigations": capec_data.get("Mitigations", ""),
                        "example_instances": capec_data.get("Example Instances", ""),
                        "related_cwes": [cwe_id],  # Track which CWE this came from
                        "taxonomy_mappings": capec_info["taxonomy_mappings"]
                    }
                    
                    capec_entries.append(formatted_entry)
        
        logger.info(f"Found {len(capec_entries)} unique CAPEC entries for {len(cwe_ids)} CWEs")
        return capec_entries
    
    def find_related_capec_fast(self, cwe_id: str) -> List[Dict]:
        """Fast CAPEC lookup using pre-built index (for backward compatibility)"""
        return self.capec_by_cwe.get(cwe_id, [])