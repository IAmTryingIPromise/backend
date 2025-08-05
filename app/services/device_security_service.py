# app/services/device_security_service.py
import asyncio
import aiohttp
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from functools import lru_cache
from collections import defaultdict
import logging
from fuzzywuzzy import fuzz

from app.services.cpe_matcher_service import CPEMatcherService
from app.services.nvd_service import NVDService
from app.services.cwe_service import CWEService
from app.services.capec_service import CAPECService
from app.services.attack_service import AttackService
from app.models.cve import CVE
from app.models.cwe import CWE
from app.models.capec import CAPEC
from app.models.attack import Attack
from app.crud.cve import CVECrud
from app.crud.cwe import CWECrud
from app.crud.capec import CAPECCrud
from app.crud.attack import AttackCrud
from app.crud.asset import DeviceCrud
from app.database import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

class DeviceSecurityAnalysisService:
    """Main service orchestrating the security analysis workflow"""
    
    def __init__(self, db: Session):
        self.db = db
        self.cpe_matcher = CPEMatcherService()
        self.nvd_service = NVDService()
        self.cwe_service = CWEService()
        self.capec_service = CAPECService()
        self.attack_service = AttackService()
        
        # CRUD operations
        self.cve_crud = CVECrud(db)
        self.cwe_crud = CWECrud(db)
        self.capec_crud = CAPECCrud(db)
        self.attack_crud = AttackCrud(db)
        self.device_crud = DeviceCrud(db)
    
    async def analyze_device_security(self, device_name: str) -> Dict[str, Any]:
        """
        Main method to analyze device security
        Returns analysis results and stores in database
        """
        try:
            logger.info(f"Starting security analysis for device: {device_name}")
            
            # Step 1: Find matching CPE
            cpe_matches = await self.cpe_matcher.find_matching_cpe(device_name)
            if not cpe_matches:
                return {
                    "success": False,
                    "message": "No matching CPE found for the device",
                    "device_name": device_name
                }
            
            best_cpe = cpe_matches[0]
            logger.info(f"Found CPE: {best_cpe}")
            
            # Step 2: Get CVEs from NVD
            nvd_data = await self.nvd_service.fetch_nvd_data(best_cpe)
            if not nvd_data.get("vulnerabilities"):
                return {
                    "success": True,
                    "message": "No vulnerabilities found for this device",
                    "device_name": device_name,
                    "cpe": best_cpe,
                    "vulnerabilities_count": 0
                }
            
            vulnerabilities = nvd_data["vulnerabilities"]
            logger.info(f"Found {len(vulnerabilities)} total vulnerabilities")
            
            # Step 3: Filter vulnerable CVEs
            vulnerable_cves = self._filter_vulnerable_cves(vulnerabilities, best_cpe)
            if not vulnerable_cves:
                return {
                    "success": True,
                    "message": "Device is not vulnerable to any CVEs",
                    "device_name": device_name,
                    "cpe": best_cpe,
                    "total_cves": len(vulnerabilities),
                    "vulnerable_cves": 0
                }
            
            logger.info(f"Device is vulnerable to {len(vulnerable_cves)} CVEs")
            
            # Step 4: Process the vulnerable CVEs and get related data
            analysis_result = await self._process_vulnerable_cves(
                device_name, best_cpe, vulnerable_cves
            )
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in security analysis: {str(e)}")
            return {
                "success": False,
                "message": f"Analysis failed: {str(e)}",
                "device_name": device_name
            }
    
    def _filter_vulnerable_cves(self, vulnerabilities: List[Dict], cpe_name: str) -> List[Dict]:
        """Filter CVEs where the device is actually vulnerable"""
        vulnerable_cves = []
        cpe_name_normalized = cpe_name.replace('-', '*')
        
        for cve_item in vulnerabilities:
            if self._is_device_vulnerable(cve_item, cpe_name_normalized):
                vulnerable_cves.append(cve_item)
        
        return vulnerable_cves
    
    def _is_device_vulnerable(self, cve_item: Dict, cpe_name: str) -> bool:
        """Check if device is vulnerable to the given CVE"""
        for configs in cve_item["cve"]["configurations"]:
            for node in configs["nodes"]:
                for cpe_match in node["cpeMatch"]:
                    if (cpe_match.get("criteria") == cpe_name and 
                        cpe_match.get("vulnerable") == True):
                        return True
        return False
    
    async def _process_vulnerable_cves(self, device_name: str, cpe: str, vulnerable_cves: List[Dict]) -> Dict[str, Any]:
        """Process vulnerable CVEs and get all related security data"""
        
        # Extract all CVE data
        processed_cves = []
        all_cwe_ids = set()
        
        for cve_item in vulnerable_cves:
            cve_data = self._extract_cve_data(cve_item)
            processed_cves.append(cve_data)
            all_cwe_ids.update(cve_data["cwe_ids"])
        
        # Get EPSS scores for all CVEs
        cve_ids = [cve["cve_id"] for cve in processed_cves]
        epss_scores = await self.nvd_service.fetch_epss_scores_batch(cve_ids)
        
        # Get CWE details
        cwe_details = await self.cwe_service.fetch_cwe_details_batch(list(all_cwe_ids))
        
        # Get CAPEC data
        capec_data = await self.capec_service.get_capec_for_cwes(list(all_cwe_ids))
        
        # Get ATT&CK techniques
        attack_data = await self.attack_service.get_attack_techniques_from_capec(capec_data)
        
        # Store everything in database
        device_id = await self._store_analysis_results(
            device_name, cpe, processed_cves, epss_scores, 
            cwe_details, capec_data, attack_data
        )
        
        return {
            "success": True,
            "message": "Security analysis completed successfully",
            "device_name": device_name,
            "device_id": device_id,
            "cpe": cpe,
            "vulnerable_cves": len(processed_cves),
            "unique_cwes": len(all_cwe_ids),
            "capec_entries": len(capec_data),
            "attack_techniques": len(attack_data),
            "analysis_summary": {
                "highest_cvss": max([cve["cvss"] for cve in processed_cves]),
                "average_cvss": sum([cve["cvss"] for cve in processed_cves]) / len(processed_cves),
                "critical_cves": len([cve for cve in processed_cves if cve["cvss"] >= 9.0]),
                "high_cves": len([cve for cve in processed_cves if 7.0 <= cve["cvss"] < 9.0])
            }
        }
    
    def _extract_cve_data(self, cve_item: Dict) -> Dict:
        """Extract relevant data from CVE item"""
        cve_id = cve_item["cve"]["id"]
        description = cve_item["cve"]["descriptions"][0]["value"]
        
        # Extract metrics
        metrics = self._extract_cve_metrics(cve_item)
        
        # Extract CWEs
        cwe_ids = self._extract_cwes(cve_item)
        
        # Extract published date
        published_date = cve_item["cve"].get("published", "")
        
        return {
            "cve_item": cve_item,
            "cve_id": cve_id,
            "description": description,
            "published_date": published_date,
            "cvss": metrics["cvss"],
            "impact": metrics["impact"],
            "exploitability": metrics["exploitability"],
            "cwe_ids": cwe_ids
        }
    
    def _extract_cve_metrics(self, cve_item: Dict) -> Dict:
        """Extract CVSS metrics from CVE data"""
        metrics = cve_item.get("cve", {}).get("metrics", {})
        
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                metric_data = metrics[version][0]
                return {
                    "cvss": metric_data["cvssData"]["baseScore"],
                    "impact": metric_data["impactScore"],
                    "exploitability": metric_data["exploitabilityScore"]
                }
        
        return {"cvss": 0, "impact": 0, "exploitability": 0}
    
    def _extract_cwes(self, cve_item: Dict) -> List[str]:
        """Extract CWE IDs from CVE data"""
        cwes = []
        for weakness in cve_item["cve"].get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "").split("-")[-1]
                if cwe_id and cwe_id != "noinfo":
                    cwes.append(cwe_id)
        return list(set(cwes))
    
    async def _store_analysis_results(self, device_name: str, cpe: str, cves: List[Dict], 
                                    epss_scores: Dict, cwe_details: Dict, 
                                    capec_data: List[Dict], attack_data: List[Dict]) -> int:
        """Store all analysis results in database"""
        
        # Create or get device
        device = await self.device_crud.create_or_get_device(device_name, cpe)
        device_id = device.id
        
        # Store CVEs
        cve_ids = []
        for cve_data in cves:
            epss_score = epss_scores.get(cve_data["cve_id"], 0.0)
            risk_level = epss_score * 1000 * cve_data["impact"] * cve_data["exploitability"] if epss_score else 0
            
            cve = await self.cve_crud.create_or_update_cve(
                cve_id=cve_data["cve_id"],
                description=cve_data["description"],
                cvss=cve_data["cvss"],
                impact=cve_data["impact"],
                exploitability=cve_data["exploitability"],
                epss_score=epss_score,
                risk_level=risk_level,
                published_date=cve_data["published_date"]
            )
            cve_ids.append(cve.id)
            
            # Link device to CVE
            await self.device_crud.link_device_cve(device_id, cve.id)
        
        # Store CWEs and link to CVEs
        cwe_db_ids = {}
        for cwe_id, cwe_detail in cwe_details.items():
            if cwe_detail:
                weakness = cwe_detail["Weaknesses"][0]
                cwe = await self.cwe_crud.create_or_update_cwe(
                    cwe_id=cwe_id,
                    name=weakness["Name"],
                    description=weakness["Description"],
                    consequences=json.dumps(weakness.get("CommonConsequences", [])),
                    mitigations=json.dumps(weakness.get("PotentialMitigations", []))
                )
                cwe_db_ids[cwe_id] = cwe.id
        
        # Link CVEs to CWEs
        for cve_data in cves:
            cve_db = await self.cve_crud.get_cve_by_cve_id(cve_data["cve_id"])
            for cwe_id in cve_data["cwe_ids"]:
                if cwe_id in cwe_db_ids:
                    await self.cve_crud.link_cve_cwe(cve_db.id, cwe_db_ids[cwe_id])
        
        # Store CAPEC entries
        capec_db_ids = []
        for capec_entry in capec_data:
            capec = await self.capec_crud.create_or_update_capec(
                capec_id=capec_entry["id"],
                name=capec_entry["name"],
                description=capec_entry["description"],
                likelihood=capec_entry.get("likelihood", ""),
                severity=capec_entry.get("severity", ""),
                prerequisites=capec_entry.get("prerequisites", ""),
                consequences=capec_entry.get("consequences", ""),
                mitigations=capec_entry.get("mitigations", "")
            )
            capec_db_ids.append(capec.id)
            
            # Link CAPEC to related CWEs
            for cwe_id in capec_entry.get("related_cwes", []):
                if cwe_id in cwe_db_ids:
                    await self.capec_crud.link_capec_cwe(capec.id, cwe_db_ids[cwe_id])
        
        # Store ATT&CK techniques
        for attack_technique in attack_data:
            attack = await self.attack_crud.create_or_update_attack(
                technique_id=attack_technique["id"],
                name=attack_technique["name"],
                description=attack_technique.get("description", ""),
                tactics=json.dumps(attack_technique.get("tactics", [])),
                platforms=json.dumps(attack_technique.get("platforms", [])),
                url=attack_technique.get("url", "")
            )
            
            # Link ATT&CK to related CAPEC entries
            for capec_id in attack_technique.get("related_capec_ids", []):
                capec_db = await self.capec_crud.get_capec_by_capec_id(capec_id)
                if capec_db:
                    await self.attack_crud.link_attack_capec(attack.id, capec_db.id)
        
        return device_id