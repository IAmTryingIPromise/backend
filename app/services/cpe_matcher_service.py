# app/services/cpe_matcher_service.py
import json
import os
import re
from typing import Dict, List, Set
from collections import defaultdict
from fuzzywuzzy import fuzz
import logging

logger = logging.getLogger(__name__)

class CPEMatcherService:
    """Enhanced CPE matcher with fuzzy logic and indexing"""
    
    def __init__(self):
        self.devices_data = []
        self.vendor_index = defaultdict(list)
        self.model_index = defaultdict(list)
        self.token_index = defaultdict(set)
        self.normalized_devices = []
        self._load_cpe_data()
        self._build_indexes()
    
    def _load_cpe_data(self):
        """Load CPE data from JSON file"""
        # PLACEHOLDER: Replace with your actual path
        cpe_file_path = os.path.join(os.path.dirname(__file__), "..", "data", "hardware_devices.json")
        
        try:
            with open(cpe_file_path, 'r', encoding='utf-8') as f:
                self.devices_data = json.load(f)
            logger.info(f"Loaded {len(self.devices_data)} CPE entries")
        except FileNotFoundError:
            logger.error(f"CPE data file not found: {cpe_file_path}")
            self.devices_data = []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing CPE JSON file: {e}")
            self.devices_data = []
    
    def _build_indexes(self):
        """Build search indexes for faster CPE matching"""
        logger.info("Building CPE matching index...")
        
        for idx, device in enumerate(self.devices_data):
            normalized_device = self._normalize_device(device)
            self.normalized_devices.append(normalized_device)
            
            # Index by vendor
            vendor_norm = normalized_device['vendor_normalized']
            if vendor_norm:
                self.vendor_index[vendor_norm].append(idx)
            
            # Index by model components
            model_components = normalized_device['model_components']
            if model_components['base_model']:
                self.model_index[model_components['base_model']].append(idx)
            
            # Index by tokens
            all_tokens = normalized_device['all_tokens']
            for token in all_tokens:
                if len(token) > 2:
                    self.token_index[token].add(idx)
        
        logger.info(f"Index built: {len(self.vendor_index)} vendors, {len(self.model_index)} models, {len(self.token_index)} tokens")
    
    def _normalize_text(self, text: str) -> str:
        """Enhanced text normalization that handles escaped characters"""
        if not text:
            return ""
        
        text = text.lower()
        text = text.replace('\\/', '/').replace('\\_', '_').replace('\\-', '-')
        text = text.replace('-', ' ').replace('/', ' ').replace('_', ' ')
        text = text.replace('(', ' ').replace(')', ' ')
        text = text.replace('[', ' ').replace(']', ' ')
        text = text.replace(',', ' ').replace('.', ' ')
        text = ' '.join(text.split())
        
        return text
    
    def _extract_model_components(self, model: str) -> Dict[str, any]:
        """Extract components from model string for better matching"""
        if not model:
            return {"base_model": "", "modifiers": [], "full_normalized": "", "original": ""}
        
        normalized = self._normalize_text(model)
        tokens = normalized.split()
        
        base_model = ""
        modifiers = []
        
        for i, token in enumerate(tokens):
            if re.match(r'^[0-9]+[a-z0-9]*$', token):
                base_model = token
                modifiers = tokens[i+1:]
                break
        
        if not base_model and tokens:
            base_model = tokens[0]
            modifiers = tokens[1:]
        
        return {
            "base_model": base_model,
            "modifiers": modifiers,
            "full_normalized": normalized,
            "original": model.lower()
        }
    
    def _normalize_device(self, device: Dict) -> Dict:
        """Pre-normalize device data for faster searching"""
        vendor = device.get('vendor', '')
        model = device.get('model', '')
        title = device.get('title', '')
        device_type = device.get('type', '')
        
        vendor_normalized = self._normalize_text(vendor)
        model_normalized = self._normalize_text(model)
        title_normalized = self._normalize_text(title)
        type_normalized = self._normalize_text(device_type)
        
        model_components = self._extract_model_components(model)
        
        # Create searchable combinations
        searchable_strings = []
        
        if vendor: searchable_strings.append((vendor.lower(), 0.7))
        if model: searchable_strings.append((model.lower(), 1.0))
        if title: searchable_strings.append((title.lower(), 0.9))
        if device_type: searchable_strings.append((device_type.lower(), 0.6))
        
        if vendor_normalized: searchable_strings.append((vendor_normalized, 0.7))
        if model_normalized: searchable_strings.append((model_normalized, 1.0))
        if title_normalized: searchable_strings.append((title_normalized, 0.9))
        if type_normalized: searchable_strings.append((type_normalized, 0.6))
        
        if vendor and model:
            searchable_strings.extend([
                (f"{vendor.lower()} {model.lower()}", 1.0),
                (f"{vendor_normalized} {model_normalized}", 1.0),
            ])
        
        # Collect all tokens for indexing
        all_tokens = set()
        for text in [vendor_normalized, model_normalized, title_normalized, type_normalized]:
            if text:
                all_tokens.update(text.split())
        
        return {
            'original_device': device,
            'vendor_normalized': vendor_normalized,
            'model_normalized': model_normalized,
            'title_normalized': title_normalized,
            'type_normalized': type_normalized,
            'model_components': model_components,
            'searchable_strings': searchable_strings,
            'all_tokens': all_tokens
        }
    
    def _get_candidate_devices(self, search_query: str) -> Set[int]:
        """Get candidate device indices using indexes for faster filtering"""
        search_normalized = self._normalize_text(search_query)
        search_tokens = set(search_normalized.split())
        search_components = self._extract_model_components(search_query)
        
        candidates = set()
        
        # Search by base model
        if search_components['base_model']:
            base_model = search_components['base_model']
            if base_model in self.model_index:
                candidates.update(self.model_index[base_model])
        
        # Search by vendor
        vendor_candidates = set()
        for token in search_tokens:
            if token in self.vendor_index:
                vendor_candidates.update(self.vendor_index[token])
        
        # Search by token overlap
        token_candidates = set()
        for token in search_tokens:
            if token in self.token_index:
                token_candidates.update(self.token_index[token])
        
        # Combine candidates
        if candidates:
            if vendor_candidates:
                candidates = candidates.intersection(vendor_candidates)
            if not candidates and token_candidates:
                candidates = token_candidates
        else:
            candidates = token_candidates
        
        if not candidates:
            candidates = vendor_candidates
        
        if not candidates and len(search_tokens) > 1:
            for token in search_tokens:
                if len(token) > 3:
                    if token in self.token_index:
                        candidates.update(list(self.token_index[token])[:1000])
        
        return candidates
    
    def _calculate_model_similarity(self, search_components: Dict, device_components: Dict) -> float:
        """Calculate similarity between search query and device model components"""
        search_base = search_components["base_model"]
        search_mods = set(search_components["modifiers"])
        device_base = device_components["base_model"]
        device_mods = set(device_components["modifiers"])
        
        if not search_base or not device_base:
            base_score = 0
        else:
            base_score = fuzz.ratio(search_base, device_base)
        
        if base_score < 80:
            return 0
        
        if not search_mods and not device_mods:
            modifier_score = 100
        elif not search_mods or not device_mods:
            modifier_score = 60
        else:
            common_mods = search_mods.intersection(device_mods)
            total_search_mods = len(search_mods)
            
            if total_search_mods == 0:
                modifier_score = 100
            else:
                modifier_score = (len(common_mods) / total_search_mods) * 100
                if search_mods == device_mods:
                    modifier_score += 20
        
        final_score = (base_score * 0.6) + (modifier_score * 0.4)
        return min(final_score, 100)
    
    async def find_matching_cpe(self, device_name: str, threshold: int = 70) -> List[str]:
        """Find matching CPE using advanced fuzzy logic"""
        device_name_lower = device_name.lower().strip()
        device_name_norm = self._normalize_text(device_name_lower)
        device_tokens = set(device_name_norm.split())
        
        search_components = self._extract_model_components(device_name)
        
        logger.info(f"Searching for CPE matching: '{device_name}'")
        
        # Get candidate devices using indexes
        candidate_indices = self._get_candidate_devices(device_name)
        logger.info(f"Filtering {len(candidate_indices)} candidates from {len(self.devices_data)} total devices")
        
        if not candidate_indices:
            logger.warning("No candidates found, falling back to broader search...")
            candidate_indices = set(range(min(5000, len(self.devices_data))))
        
        best_matches = []
        
        for idx in candidate_indices:
            if idx >= len(self.normalized_devices):
                continue
                
            normalized_device = self.normalized_devices[idx]
            device = normalized_device['original_device']
            
            # Quick vendor validation
            vendor_tokens = set(normalized_device['vendor_normalized'].split()) if normalized_device['vendor_normalized'] else set()
            vendor_match = bool(vendor_tokens.intersection(device_tokens)) if vendor_tokens else True
            
            # Calculate model component similarity
            device_components = normalized_device['model_components']
            model_similarity = self._calculate_model_similarity(search_components, device_components)
            
            device_score = 0
            
            # Test against pre-computed searchable strings
            for search_string, weight in normalized_device['searchable_strings']:
                search_string_norm = self._normalize_text(search_string)
                search_tokens = set(search_string_norm.split())
                
                # Token overlap score
                token_overlap = len(device_tokens.intersection(search_tokens))
                total_tokens = len(device_tokens.union(search_tokens))
                token_overlap_score = (token_overlap / total_tokens * 100) if total_tokens > 0 else 0
                
                # Fuzzy scores
                fuzzy_scores = [
                    fuzz.ratio(device_name_norm, search_string_norm),
                    fuzz.token_sort_ratio(device_name_norm, search_string_norm),
                    token_overlap_score
                ]
                
                max_fuzzy_score = max(fuzzy_scores)
                combined_score = (max_fuzzy_score * 0.6) + (model_similarity * 0.4)
                weighted_score = combined_score * weight
                
                # Vendor bonus/penalty
                if vendor_tokens:
                    if vendor_match:
                        weighted_score += 10
                    else:
                        weighted_score -= 15
                
                if weighted_score > device_score:
                    device_score = weighted_score
            
            if device_score >= threshold:
                cpe = device.get('cpeName', '').replace("\\/", "/")
                if cpe:
                    best_matches.append((cpe, device_score))
        
        # Sort matches by score
        best_matches.sort(key=lambda x: x[1], reverse=True)
        
        # Return CPEs of best matches
        matched_cpes = [cpe for cpe, score in best_matches]
        
        if matched_cpes:
            logger.info(f"Found {len(matched_cpes)} matching CPEs")
        else:
            logger.warning(f"No CPE found matching '{device_name}' with threshold {threshold}")
        
        return matched_cpes