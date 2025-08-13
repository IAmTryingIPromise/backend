# app/services/security_analysis_service.py
import asyncio
import aiohttp
import json
import os
import re
from typing import Dict, List, Optional, Any, Set
from functools import lru_cache
from collections import defaultdict
import logging
from fuzzywuzzy import fuzz
from mitreattack.stix20 import MitreAttackData
import csv

from sqlalchemy.orm import Session
from app.database import get_db

logger = logging.getLogger(__name__)

class SecurityAnalysisService:
    """Main service for device security analysis"""
    
    def __init__(self, db: Session):
        self.db = db
        # PLACEHOLDER: Replace with your actual NVD API key
        self.nvd_api_key = "YOUR_NVD_API_KEY_HERE"
        
        # Load static data
        self._load_static_data()
        
        # Initialize CPE matcher
        self.cpe_matcher = CPEMatcher(self.cpes)
        
    def _load_static_data(self):
        """Load static data files"""
        script_dir = os.path.dirname(__file__)
        data_dir = os.path.join(script_dir, "..", "data")  # Adjust path as needed
        
        # Load CPE data
        cpe_file = os.path.join(data_dir, "hardware_devices.json")
        try:
            with open(cpe_file, 'r', encoding='utf-8') as f:
                self.cpes = json.load(f)
            logger.info(f"Loaded {len(self.cpes)} CPE entries")
        except FileNotFoundError:
            logger.error(f"CPE file not found: {cpe_file}")
            self.cpes = []
        
        # Load CAPEC data
        capec_file = os.path.join(data_dir, "2000CAPEC.csv")
        self.capec_data = []
        self.capec_by_cwe = defaultdict(list)
        try:
            with open(capec_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.capec_data = list(reader)
                self._build_capec_index()
            logger.info(f"Loaded {len(self.capec_data)} CAPEC entries")
        except FileNotFoundError:
            logger.error(f"CAPEC file not found: {capec_file}")
        
        # Load ATT&CK data
        attack_file = os.path.join(data_dir, "enterprise-attack.json")
        try:
            self.attack_data = MitreAttackData(attack_file)
            logger.info("Loaded MITRE ATT&CK data")
        except FileNotFoundError:
            logger.error(f"ATT&CK file not found: {attack_file}")
            self.attack_data = None
    
    def _build_capec_index(self):
        """Build CAPEC-CWE lookup index"""
        headers_to_show = {
            "'ID", "Name", "Description", "Likelihood Of Attack", 
            "Typical Severity", "Related Weaknesses", "Mitigations",
            "Prerequisites", "Consequences", "Example Instances"
        }
        
        for row in self.capec_data:
            weakness_data = row.get("Related Weaknesses", "").strip()
            if weakness_data:
                cwe_numbers = re.findall(r'::(\d+)::', weakness_data)
                for cwe_id in cwe_numbers:
                    self.capec_by_cwe[cwe_id].append({
                        "capec_data": {header: row.get(header, "") for header in headers_to_show},
                        "taxonomy_mappings": row.get("Taxonomy Mappings", "")
                    })
    
    async def analyze_device(self, device_name: str) -> Dict[str, Any]:
        """Main analysis method - returns results and stores in database"""
        try:
            # Step 1: Find CPE
            cpe_matches = self.cpe_matcher.find_matching_cpe(device_name)
            if not cpe_matches:
                return {
                    "success": False,
                    "message": "No matching CPE found",
                    "device_name": device_name
                }
            
            best_cpe = cpe_matches[0]
            logger.info(f"Using CPE: {best_cpe}")
            
            # Step 2: Get CVEs from NVD
            async with SecurityDataFetcher(self.nvd_api_key) as fetcher:
                nvd_data = await fetcher.fetch_nvd_data(best_cpe)
                
                if not nvd_data.get("vulnerabilities"):
                    return {
                        "success": True,
                        "message": "No vulnerabilities found",
                        "device_name": device_name,
                        "cpe": best_cpe
                    }
                
                # Step 3: Filter vulnerable CVEs
                vulnerable_cves = self._filter_vulnerable_cves(
                    nvd_data["vulnerabilities"], best_cpe
                )
                
                if not vulnerable_cves:
                    return {
                        "success": True,
                        "message": "Device not vulnerable to any CVEs",
                        "device_name": device_name,
                        "cpe": best_cpe,
                        "total_cves": len(nvd_data["vulnerabilities"])
                    }
                
                logger.info(f"Found {len(vulnerable_cves)} vulnerable CVEs")
                
                # Step 4: Process vulnerable CVEs
                return await self._process_vulnerable_cves(
                    device_name, best_cpe, vulnerable_cves, fetcher
                )
                
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "success": False,
                "message": f"Analysis failed: {str(e)}",
                "device_name": device_name
            }
    
    def _filter_vulnerable_cves(self, vulnerabilities: List[Dict], cpe_name: str) -> List[Dict]:
        """Filter CVEs where device is actually vulnerable"""
        vulnerable = []
        cpe_normalized = cpe_name.replace('-', '*')
        
        for cve_item in vulnerabilities:
            if self._is_device_vulnerable(cve_item, cpe_normalized):
                vulnerable.append(cve_item)
        
        return vulnerable
    
    def _is_device_vulnerable(self, cve_item: Dict, cpe_name: str) -> bool:
        """Check if device is vulnerable to CVE"""
        for config in cve_item["cve"]["configurations"]:
            for node in config["nodes"]:
                for cpe_match in node["cpeMatch"]:
                    if (cpe_match.get("criteria") == cpe_name and 
                        cpe_match.get("vulnerable") == True):
                        return True
        return False
    
    async def _process_vulnerable_cves(self, device_name: str, cpe: str, 
                                     vulnerable_cves: List[Dict], 
                                     fetcher) -> Dict[str, Any]:
        """Process vulnerable CVEs and related data"""
        
        # Extract CVE data
        processed_cves = []
        all_cwe_ids = set()
        
        for cve_item in vulnerable_cves:
            cve_data = self._extract_cve_data(cve_item)
            processed_cves.append(cve_data)
            all_cwe_ids.update(cve_data["cwe_ids"])
        
        # Get EPSS scores
        cve_ids = [cve["cve_id"] for cve in processed_cves]
        epss_scores = await fetcher.fetch_epss_scores_batch(cve_ids)
        
        # Get CWE details
        cwe_details = await fetcher.fetch_cwe_details_batch(list(all_cwe_ids))
        
        # Get CAPEC data
        capec_data = self._get_capec_for_cwes(list(all_cwe_ids))
        
        # Get ATT&CK techniques
        attack_data = self._get_attack_from_capec(capec_data)
        
        # Store in database using your existing CRUD operations
        device_id = await self._store_results(
            device_name, cpe, processed_cves, epss_scores, 
            cwe_details, capec_data, attack_data
        )
        
        return {
            "success": True,
            "message": "Analysis completed",
            "device_name": device_name,
            "device_id": device_id,
            "cpe": cpe,
            "vulnerable_cves": len(processed_cves),
            "unique_cwes": len(all_cwe_ids),
            "capec_entries": len(capec_data),
            "attack_techniques": len(attack_data)
        }
    
    def _extract_cve_data(self, cve_item: Dict) -> Dict:
        """Extract CVE data"""
        cve_id = cve_item["cve"]["id"]
        description = cve_item["cve"]["descriptions"][0]["value"]
        
        # Extract metrics
        metrics = cve_item.get("cve", {}).get("metrics", {})
        cvss_data = {"cvss": 0, "impact": 0, "exploitability": 0}
        
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                metric_data = metrics[version][0]
                cvss_data = {
                    "cvss": metric_data["cvssData"]["baseScore"],
                    "impact": metric_data["impactScore"],
                    "exploitability": metric_data["exploitabilityScore"]
                }
                break
        
        # Extract CWEs
        cwe_ids = []
        for weakness in cve_item["cve"].get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "").split("-")[-1]
                if cwe_id and cwe_id != "noinfo":
                    cwe_ids.append(cwe_id)
        
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": cve_item["cve"].get("published", ""),
            **cvss_data,
            "cwe_ids": list(set(cwe_ids))
        }
    
    def _get_capec_for_cwes(self, cwe_ids: List[str]) -> List[Dict]:
        """Get CAPEC entries for CWEs"""
        capec_entries = []
        seen_ids = set()
        
        for cwe_id in cwe_ids:
            for capec_info in self.capec_by_cwe.get(cwe_id, []):
                capec_data = capec_info["capec_data"]
                capec_id = capec_data.get("'ID", "").replace("'", "")
                
                if capec_id and capec_id not in seen_ids:
                    seen_ids.add(capec_id)
                    capec_entries.append({
                        "capec_id": capec_id,
                        "name": capec_data.get("Name", ""),
                        "description": capec_data.get("Description", ""),
                        "likelihood": capec_data.get("Likelihood Of Attack", ""),
                        "severity": capec_data.get("Typical Severity", ""),
                        "taxonomy_mappings": capec_info["taxonomy_mappings"],
                        "related_cwes": [cwe_id]
                    })
        
        return capec_entries
    
    @lru_cache(maxsize=500)
    def _extract_attack_ids(self, taxonomy_data: str) -> tuple:
        """Extract ATT&CK IDs from taxonomy mappings"""
        found_entry_ids = re.findall(r'ENTRY ID:([^:]+)', taxonomy_data)
        return tuple(f"T{entry_id}" for entry_id in found_entry_ids)
    
    def _get_attack_from_capec(self, capec_entries: List[Dict]) -> List[Dict]:
        """Get ATT&CK techniques from CAPEC entries"""
        if not self.attack_data:
            return []
        
        attack_techniques = []
        seen_ids = set()
        
        for capec_entry in capec_entries:
            attack_ids = self._extract_attack_ids(capec_entry["taxonomy_mappings"])
            
            for attack_id in attack_ids:
                if attack_id not in seen_ids:
                    seen_ids.add(attack_id)
                    technique = self.attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
                    
                    if technique:
                        # Extract URL
                        url = None
                        for ref in technique.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                url = ref.get("url")
                                break
                        
                        attack_techniques.append({
                            "technique_id": attack_id,
                            "name": technique.get('name', ''),
                            "description": technique.get('description', ''),
                            "tactics": [p.get("phase_name") for p in technique.get("kill_chain_phases", [])],
                            "platforms": technique.get('x_mitre_platforms', []),
                            "url": url,
                            "related_capec_ids": [capec_entry["capec_id"]]
                        })
        
        return attack_techniques
    
    async def _store_results(self, device_name: str, cpe: str, cves: List[Dict], 
                           epss_scores: Dict, cwe_details: Dict, 
                           capec_data: List[Dict], attack_data: List[Dict]) -> int:
        """Store results using your existing CRUD operations"""
        # PLACEHOLDER: Replace with your actual CRUD imports and calls
        from app.crud import device_crud, cve_crud, cwe_crud, capec_crud, attack_crud
        
        # Create/get device
        device = device_crud.create_or_get_device(self.db, device_name, cpe)
        device_id = device.id
        
        # Store CVEs
        for cve_data in cves:
            epss_score = epss_scores.get(cve_data["cve_id"], 0.0)
            risk_level = (epss_score * 1000 * cve_data["impact"] * 
                         cve_data["exploitability"]) if epss_score else 0
            
            cve = cve_crud.create_or_update_cve(
                self.db,
                cve_id=cve_data["cve_id"],
                description=cve_data["description"],
                cvss=cve_data["cvss"],
                impact=cve_data["impact"],
                exploitability=cve_data["exploitability"],
                epss_score=epss_score,
                risk_level=risk_level,
                published_date=cve_data["published_date"]
            )
            
            # Link device to CVE
            device_crud.link_device_cve(self.db, device_id, cve.id)
            
            # Link CVE to CWEs
            for cwe_id in cve_data["cwe_ids"]:
                if cwe_id in cwe_details and cwe_details[cwe_id]:
                    weakness = cwe_details[cwe_id]["Weaknesses"][0]
                    cwe = cwe_crud.create_or_update_cwe(
                        self.db,
                        cwe_id=cwe_id,
                        name=weakness["Name"],
                        description=weakness["Description"]
                    )
                    cve_crud.link_cve_cwe(self.db, cve.id, cwe.id)
        
        # Store CAPEC entries
        for capec_entry in capec_data:
            capec = capec_crud.create_or_update_capec(
                self.db,
                capec_id=capec_entry["capec_id"],
                name=capec_entry["name"],
                description=capec_entry["description"],
                likelihood=capec_entry["likelihood"],
                severity=capec_entry["severity"]
            )
            
            # Link to CWEs
            for cwe_id in capec_entry["related_cwes"]:
                cwe = cwe_crud.get_by_cwe_id(self.db, cwe_id)
                if cwe:
                    capec_crud.link_capec_cwe(self.db, capec.id, cwe.id)
        
        # Store ATT&CK techniques
        for attack_technique in attack_data:
            attack = attack_crud.create_or_update_attack(
                self.db,
                technique_id=attack_technique["technique_id"],
                name=attack_technique["name"],
                description=attack_technique["description"],
                tactics=json.dumps(attack_technique["tactics"]),
                platforms=json.dumps(attack_technique["platforms"]),
                url=attack_technique["url"]
            )
            
            # Link to CAPEC
            for capec_id in attack_technique["related_capec_ids"]:
                capec = capec_crud.get_by_capec_id(self.db, capec_id)
                if capec:
                    attack_crud.link_attack_capec(self.db, attack.id, capec.id)
        
        return device_id


class CPEMatcher:
    """CPE matching logic extracted from original script"""
    
    def __init__(self, devices_data: List[Dict]):
        self.devices_data = devices_data
        self.vendor_index = defaultdict(list)
        self.model_index = defaultdict(list)
        self.token_index = defaultdict(set)
        self.normalized_devices = []
        self._build_indexes()
    
    def _build_indexes(self):
        """Build search indexes"""
        for idx, device in enumerate(self.devices_data):
            normalized_device = self._normalize_device(device)
            self.normalized_devices.append(normalized_device)
            
            vendor_norm = normalized_device['vendor_normalized']
            if vendor_norm:
                self.vendor_index[vendor_norm].append(idx)
            
            model_components = normalized_device['model_components']
            if model_components['base_model']:
                self.model_index[model_components['base_model']].append(idx)
            
            for token in normalized_device['all_tokens']:
                if len(token) > 2:
                    self.token_index[token].add(idx)
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for matching"""
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
        """Extract model components"""
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
        """Normalize device data"""
        vendor = device.get('vendor', '')
        model = device.get('model', '')
        title = device.get('title', '')
        device_type = device.get('type', '')
        
        vendor_normalized = self._normalize_text(vendor)
        model_normalized = self._normalize_text(model)
        title_normalized = self._normalize_text(title)
        type_normalized = self._normalize_text(device_type)
        
        model_components = self._extract_model_components(model)
        
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
    
    def find_matching_cpe(self, device_name: str, threshold: int = 70) -> List[str]:
        """Find matching CPEs"""
        device_name_lower = device_name.lower().strip()
        device_name_norm = self._normalize_text(device_name_lower)
        device_tokens = set(device_name_norm.split())
        
        search_components = self._extract_model_components(device_name)
        
        # Get candidate devices
        candidate_indices = self._get_candidate_devices(device_name)
        
        if not candidate_indices:
            candidate_indices = set(range(min(5000, len(self.devices_data))))
        
        best_matches = []
        
        for idx in candidate_indices:
            if idx >= len(self.normalized_devices):
                continue
                
            normalized_device = self.normalized_devices[idx]
            device = normalized_device['original_device']
            
            vendor_tokens = set(normalized_device['vendor_normalized'].split()) if normalized_device['vendor_normalized'] else set()
            vendor_match = bool(vendor_tokens.intersection(device_tokens)) if vendor_tokens else True
            
            device_components = normalized_device['model_components']
            model_similarity = self._calculate_model_similarity(search_components, device_components)
            
            device_score = 0
            
            for search_string, weight in normalized_device['searchable_strings']:
                search_string_norm = self._normalize_text(search_string)
                search_tokens = set(search_string_norm.split())
                
                token_overlap = len(device_tokens.intersection(search_tokens))
                total_tokens = len(device_tokens.union(search_tokens))
                token_overlap_score = (token_overlap / total_tokens * 100) if total_tokens > 0 else 0
                
                fuzzy_scores = [
                    fuzz.ratio(device_name_norm, search_string_norm),
                    fuzz.token_sort_ratio(device_name_norm, search_string_norm),
                    token_overlap_score
                ]
                
                max_fuzzy_score = max(fuzzy_scores)
                combined_score = (max_fuzzy_score * 0.6) + (model_similarity * 0.4)
                weighted_score = combined_score * weight
                
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
        
        best_matches.sort(key=lambda x: x[1], reverse=True)
        return [cpe for cpe, score in best_matches]
    
    def _get_candidate_devices(self, search_query: str) -> Set[int]:
        """Get candidate device indices"""
        search_normalized = self._normalize_text(search_query)
        search_tokens = set(search_normalized.split())
        search_components = self._extract_model_components(search_query)
        
        candidates = set()
        
        if search_components['base_model']:
            base_model = search_components['base_model']
            if base_model in self.model_index:
                candidates.update(self.model_index[base_model])
        
        vendor_candidates = set()
        for token in search_tokens:
            if token in self.vendor_index:
                vendor_candidates.update(self.vendor_index[token])
        
        token_candidates = set()
        for token in search_tokens:
            if token in self.token_index:
                token_candidates.update(self.token_index[token])
        
        if candidates:
            if vendor_candidates:
                candidates = candidates.intersection(vendor_candidates)
            if not candidates and token_candidates:
                candidates = token_candidates
        else:
            candidates = token_candidates
        
        if not candidates:
            candidates = vendor_candidates
        
        return candidates
    
    def _calculate_model_similarity(self, search_components: Dict, device_components: Dict) -> float:
        """Calculate model similarity"""
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


class SecurityDataFetcher:
    """Handles external API calls"""
    
    def __init__(self, api_key: str, max_concurrent: int = 25):
        self.api_key = api_key
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.cwe_cache: Dict[str, Any] = {}
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=50,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=20, connect=5)
        self.session = aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={'User-Agent': 'SecurityScanner/1.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_nvd_data(self, cpe_name: str) -> Dict:
        """Fetch CVE data from NVD"""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "cpeName": cpe_name,
            "startIndex": 0,
            "resultsPerPage": 2000,
        }
        headers = {"apiKey": self.api_key}
        
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"NVD API Error: {response.status}")
                        return {}
            except Exception as e:
                logger.error(f"Error fetching NVD data: {e}")
                return {}

    async def fetch_epss_scores_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for multiple CVEs"""
        batch_size = 50
        all_results = {}
        
        tasks = []
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            task = self._fetch_epss_batch(batch)
            tasks.append(task)
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if isinstance(result, dict):
                all_results.update(result)
        
        return all_results

    async def _fetch_epss_batch(self, cve_batch: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for a batch of CVEs"""
        url = "https://api.first.org/data/v1/epss"
        params = {"cve": ",".join(cve_batch)}
        
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = {}
                        for item in data.get("data", []):
                            results[item["cve"]] = float(item["epss"])
                        return results
            except Exception as e:
                logger.error(f"Error fetching EPSS batch: {e}")
            
            return {}

    async def fetch_cwe_details_batch(self, cwe_ids: List[str]) -> Dict[str, Any]:
        """Fetch multiple CWE details concurrently"""
        uncached_cwe_ids = [cwe_id for cwe_id in cwe_ids if cwe_id not in self.cwe_cache]
        
        if not uncached_cwe_ids:
            return {cwe_id: self.cwe_cache[cwe_id] for cwe_id in cwe_ids}
        
        tasks = []
        for cwe_id in uncached_cwe_ids:
            task = self._fetch_single_cwe(cwe_id)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for cwe_id, result in zip(uncached_cwe_ids, results):
            if isinstance(result, Exception):
                self.cwe_cache[cwe_id] = None
            else:
                self.cwe_cache[cwe_id] = result
        
        return {cwe_id: self.cwe_cache[cwe_id] for cwe_id in cwe_ids}

    async def _fetch_single_cwe(self, cwe_id: str) -> Optional[Dict]:
        """Fetch a single CWE"""
        url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
        
        async with self.semaphore:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
            except Exception:
                return None