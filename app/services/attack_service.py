# app/services/attack_service.py
import os
import re
from typing import Dict, List
from functools import lru_cache
from mitreattack.stix20 import MitreAttackData
import logging

logger = logging.getLogger(__name__)

class AttackService:
    """Service for handling MITRE ATT&CK data"""
    
    def __init__(self):
        self.attack_data = None
        self._load_attack_data()
    
    def _load_attack_data(self):
        """Load MITRE ATT&CK data"""
        # PLACEHOLDER: Replace with your actual path
        attack_json_path = os.path.join(os.path.dirname(__file__), "..", "data", "enterprise-attack.json")
        
        try:
            self.attack_data = MitreAttackData(attack_json_path)
            logger.info("Loaded MITRE ATT&CK data successfully")
        except FileNotFoundError:
            logger.error(f"ATT&CK JSON file not found: {attack_json_path}")
            self.attack_data = None
        except Exception as e:
            logger.error(f"Error loading ATT&CK data: {e}")
            self.attack_data = None
    
    @lru_cache(maxsize=500)
    def extract_attack_ids(self, taxonomy_data: str) -> tuple:
        """Extract MITRE ATT&CK technique IDs with caching"""
        if not taxonomy_data:
            return tuple()
            
        found_entry_ids = re.findall(r'ENTRY ID:([^:]+)', taxonomy_data)
        return tuple(f"T{entry_id}" for entry_id in found_entry_ids)
    
    async def get_attack_techniques_from_capec(self, capec_entries: List[Dict]) -> List[Dict]:
        """Extract ATT&CK techniques from CAPEC entries"""
        if not self.attack_data:
            logger.warning("ATT&CK data not available")
            return []
        
        attack_techniques = []
        seen_technique_ids = set()
        
        for capec_entry in capec_entries:
            taxonomy_mappings = capec_entry.get("taxonomy_mappings", "")
            attack_ids = self.extract_attack_ids(taxonomy_mappings)
            
            for attack_id in attack_ids:
                if attack_id not in seen_technique_ids:
                    seen_technique_ids.add(attack_id)
                    
                    # Get technique details from ATT&CK data
                    technique = self.attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
                    
                    if technique:
                        # Extract external references
                        external_id = None
                        url = None
                        for ref in technique.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                external_id = ref.get("external_id")
                                url = ref.get("url")
                                break
                        
                        # Extract tactics
                        tactics = [phase.get("phase_name") for phase in technique.get("kill_chain_phases", [])]
                        platforms = technique.get('x_mitre_platforms', [])
                        
                        formatted_technique = {
                            "id": attack_id,
                            "external_id": external_id,
                            "name": technique.get('name', ''),
                            "description": technique.get('description', ''),
                            "tactics": tactics,
                            "platforms": platforms,
                            "url": url,
                            "related_capec_ids": [capec_entry.get("id")]  # Track which CAPEC this came from
                        }
                        
                        attack_techniques.append(formatted_technique)
                    else:
                        logger.warning(f"ATT&CK technique {attack_id} not found in dataset")
        
        logger.info(f"Found {len(attack_techniques)} unique ATT&CK techniques")
        return attack_techniques
    
    def get_technique_by_id(self, technique_id: str) -> Dict:
        """Get a specific ATT&CK technique by ID"""
        if not self.attack_data:
            return {}
        
        return self.attack_data.get_object_by_attack_id(technique_id, "attack-pattern") or {}