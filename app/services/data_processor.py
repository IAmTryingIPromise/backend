from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app.services.external_api import ExternalAPIService
from app.crud import asset as asset_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.crud import relations as relations_crud
from app.schemas.asset import AssetCreate
from app.schemas.cve import CVECreate
from app.schemas.cwe import CWECreate
from app.schemas.capec import CAPECCreate
from app.schemas.attack import AttackCreate
from app.utils.logger import logger

class DataProcessorService:
    def __init__(self):
        self.external_api = ExternalAPIService()
    
    async def process_asset_data(self, db: Session, asset_data: Dict[str, Any]) -> int:
        """
        Process asset data and related security information
        Returns the asset ID
        """
        try:
            # Create asset
            asset_create = AssetCreate(**asset_data)
            asset = asset_crud.create_asset(db, asset_create)
            logger.info(f"Created asset with ID: {asset.id}")
            
            # Fetch and process CVEs
            cve_data_list = await self.external_api.fetch_cve_data(asset_data)
            for cve_data in cve_data_list:
                cve_id = await self._process_cve_data(db, cve_data)
                if cve_id:
                    relations_crud.create_asset_cve_relation(db, asset.id, cve_id)
            
            return asset.id
            
        except Exception as e:
            logger.error(f"Error processing asset data: {e}")
            raise
    
    async def _process_cve_data(self, db: Session, cve_data: Dict[str, Any]) -> int:
        """Process CVE data and return CVE ID"""
        try:
            # Check if CVE already exists
            existing_cve = cve_crud.get_cve_by_cve_id(db, cve_data["cve_id"])
            if existing_cve:
                cve_id = existing_cve.id
            else:
                cve_create = CVECreate(**cve_data)
                cve = cve_crud.create_cve(db, cve_create)
                cve_id = cve.id
            
            # Fetch and process CWEs
            cwe_data_list = await self.external_api.fetch_cwe_data(cve_data["cve_id"])
            for cwe_data in cwe_data_list:
                cwe_id = await self._process_cwe_data(db, cwe_data)
                if cwe_id:
                    relations_crud.create_cve_cwe_relation(db, cve_id, cwe_id)
            
            return cve_id
            
        except Exception as e:
            logger.error(f"Error processing CVE data: {e}")
            return None
    
    async def _process_cwe_data(self, db: Session, cwe_data: Dict[str, Any]) -> int:
        """Process CWE data and return CWE ID"""
        try:
            # Check if CWE already exists
            existing_cwe = cwe_crud.get_cwe_by_cwe_id(db, cwe_data["cwe_id"])
            if existing_cwe:
                cwe_id = existing_cwe.id
            else:
                cwe_create = CWECreate(**cwe_data)
                cwe = cwe_crud.create_cwe(db, cwe_create)
                cwe_id = cwe.id
            
            # Fetch and process CAPECs
            capec_data_list = await self.external_api.fetch_capec_data(cwe_data["cwe_id"])
            for capec_data in capec_data_list:
                capec_id = await self._process_capec_data(db, capec_data)
                if capec_id:
                    relations_crud.create_cwe_capec_relation(db, cwe_id, capec_id)
            
            return cwe_id
            
        except Exception as e:
            logger.error(f"Error processing CWE data: {e}")
            return None
    
    async def _process_capec_data(self, db: Session, capec_data: Dict[str, Any]) -> int:
        """Process CAPEC data and return CAPEC ID"""
        try:
            # Check if CAPEC already exists
            existing_capec = capec_crud.get_capec_by_capec_id(db, capec_data["capec_id"])
            if existing_capec:
                capec_id = existing_capec.id
            else:
                capec_create = CAPECCreate(**capec_data)
                capec = capec_crud.create_capec(db, capec_create)
                capec_id = capec.id
            
            # Fetch and process Attacks
            attack_data_list = await self.external_api.fetch_attack_data(capec_data["capec_id"])
            for attack_data in attack_data_list:
                attack_id = await self._process_attack_data(db, attack_data)
                if attack_id:
                    relations_crud.create_capec_attack_relation(db, capec_id, attack_id)
            
            return capec_id
            
        except Exception as e:
            logger.error(f"Error processing CAPEC data: {e}")
            return None
    
    async def _process_attack_data(self, db: Session, attack_data: Dict[str, Any]) -> int:
        """Process Attack data and return Attack ID"""
        try:
            # Check if Attack already exists
            existing_attack = attack_crud.get_attack_by_technique_id(db, attack_data["technique_id"])
            if existing_attack:
                return existing_attack.id
            else:
                attack_create = AttackCreate(**attack_data)
                attack = attack_crud.create_attack(db, attack_create)
                return attack.id
                
        except Exception as e:
            logger.error(f"Error processing Attack data: {e}")
            return None