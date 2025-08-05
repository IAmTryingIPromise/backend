# Project Structure:
# my_app/
# ├── app/
# │   ├── __init__.py
# │   ├── main.py
# │   ├── config.py
# │   ├── database.py
# │   ├── models/
# │   │   ├── __init__.py
# │   │   ├── device.py
# │   │   ├── cve.py
# │   │   ├── cwe.py
# │   │   ├── capec.py
# │   │   ├── attack.py
# │   │   └── relations.py
# │   ├── schemas/
# │   │   ├── __init__.py
# │   │   ├── device.py
# │   │   ├── cve.py
# │   │   ├── cwe.py
# │   │   ├── capec.py
# │   │   ├── attack.py
# │   │   └── response.py
# │   ├── crud/
# │   │   ├── __init__.py
# │   │   ├── device.py
# │   │   ├── cve.py
# │   │   ├── cwe.py
# │   │   ├── capec.py
# │   │   ├── attack.py
# │   │   └── relations.py
# │   ├── routers/
# │   │   ├── __init__.py
# │   │   ├── devices.py
# │   │   ├── cves.py
# │   │   ├── cwes.py
# │   │   ├── capecs.py
# │   │   └── attacks.py
# │   ├── services/
# │   │   ├── __init__.py
# │   │   ├── external_api.py
# │   │   └── data_processor.py
# │   └── utils/
# │       ├── __init__.py
# │       └── logger.py
# ├── alembic/
# ├── alembic.ini
# ├── requirements.txt
# ├── .env
# └── README.md

# ========================================
# requirements.txt
# ========================================
"""
fastapi==0.104.1
uvicorn==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.13.1
pydantic==2.5.0
python-dotenv==1.0.0
httpx==0.25.2
python-multipart==0.0.6
"""

# ========================================
# .env
# ========================================
"""
DATABASE_URL=postgresql://username:password@localhost:5432/security_db
SECRET_KEY=your-secret-key-here
DEBUG=True
LOG_LEVEL=INFO
"""

# ========================================
# app/config.py
# ========================================

from pydantic import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    database_url: str
    secret_key: str
    debug: bool = False
    log_level: str = "INFO"
    external_api_key: Optional[str] = None
    
    class Config:
        env_file = ".env"

settings = Settings()

# ========================================
# app/utils/logger.py
# ========================================

import logging
from app.config import settings

def setup_logger():
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

logger = setup_logger()

# ========================================
# app/database.py
# ========================================

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.utils.logger import logger

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

# ========================================
# app/models/device.py
# ========================================

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    vendor = Column(String, nullable=True)
    version = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# ========================================
# app/models/cve.py
# ========================================

from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from app.database import Base

class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# ========================================
# app/models/cwe.py
# ========================================

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class CWE(Base):
    __tablename__ = "cwes"
    
    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    weakness_type = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# ========================================
# app/models/capec.py
# ========================================

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class CAPEC(Base):
    __tablename__ = "capecs"
    
    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    attack_pattern = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# ========================================
# app/models/attack.py
# ========================================

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class Attack(Base):
    __tablename__ = "attacks"
    
    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    tactic = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# ========================================
# app/models/relations.py
# ========================================

from sqlalchemy import Column, Integer, ForeignKey, DateTime
from sqlalchemy.sql import func
from app.database import Base

class DeviceCVERelation(Base):
    __tablename__ = "device_cve_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CVECWERelation(Base):
    __tablename__ = "cve_cwe_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    cwe_id = Column(Integer, ForeignKey("cwes.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CWECAPECRelation(Base):
    __tablename__ = "cwe_capec_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(Integer, ForeignKey("cwes.id"), nullable=False)
    capec_id = Column(Integer, ForeignKey("capecs.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CAPECAttackRelation(Base):
    __tablename__ = "capec_attack_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(Integer, ForeignKey("capecs.id"), nullable=False)
    attack_id = Column(Integer, ForeignKey("attacks.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# ========================================
# app/schemas/device.py
# ========================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class DeviceBase(BaseModel):
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

class Device(DeviceBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========================================
# app/schemas/cve.py
# ========================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    published_date: Optional[datetime] = None

class CVECreate(CVEBase):
    pass

class CVE(CVEBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========================================
# app/schemas/cwe.py
# ========================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CWEBase(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = None
    weakness_type: Optional[str] = None

class CWECreate(CWEBase):
    pass

class CWE(CWEBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========================================
# app/schemas/capec.py
# ========================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CAPECBase(BaseModel):
    capec_id: str
    name: str
    description: Optional[str] = None
    attack_pattern: Optional[str] = None

class CAPECCreate(CAPECBase):
    pass

class CAPEC(CAPECBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========================================
# app/schemas/attack.py
# ========================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AttackBase(BaseModel):
    technique_id: str
    name: str
    description: Optional[str] = None
    tactic: Optional[str] = None
    platform: Optional[str] = None

class AttackCreate(AttackBase):
    pass

class Attack(AttackBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========================================
# app/schemas/response.py
# ========================================

from pydantic import BaseModel
from typing import List, Optional
from app.schemas.asset import Device
from app.schemas.cve import CVE
from app.schemas.cwe import CWE
from app.schemas.capec import CAPEC
from app.schemas.attack import Attack

class DeviceFullResponse(BaseModel):
    device: Device
    cves: List[CVE]
    cwes: List[CWE]
    capecs: List[CAPEC]
    attacks: List[Attack]

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None

# ========================================
# app/services/external_api.py
# ========================================

import httpx
from typing import Dict, Any, List
from app.utils.logger import logger

class ExternalAPIService:
    def __init__(self):
        self.timeout = 30.0
        
    async def fetch_cve_data(self, device_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fetch CVE data from external API based on device information
        PLACEHOLDER: Replace with actual API endpoint and logic
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # PLACEHOLDER: Replace with actual CVE API endpoint
                # Example: NVD API, CVE Details API, etc.
                url = "https://api.example.com/cves"
                params = {
                    "vendor": device_info.get("vendor"),
                    "product": device_info.get("name"),
                    "version": device_info.get("version")
                }
                
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                # PLACEHOLDER: Parse actual response format
                return response.json().get("cves", [])
                
        except Exception as e:
            logger.error(f"Error fetching CVE data: {e}")
            return []
    
    async def fetch_cwe_data(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Fetch CWE data from external API based on CVE ID
        PLACEHOLDER: Replace with actual API endpoint and logic
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # PLACEHOLDER: Replace with actual CWE API endpoint
                url = f"https://api.example.com/cwes/{cve_id}"
                
                response = await client.get(url)
                response.raise_for_status()
                
                # PLACEHOLDER: Parse actual response format
                return response.json().get("cwes", [])
                
        except Exception as e:
            logger.error(f"Error fetching CWE data: {e}")
            return []
    
    async def fetch_capec_data(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Fetch CAPEC data from external API based on CWE ID
        PLACEHOLDER: Replace with actual API endpoint and logic
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # PLACEHOLDER: Replace with actual CAPEC API endpoint
                url = f"https://api.example.com/capecs/{cwe_id}"
                
                response = await client.get(url)
                response.raise_for_status()
                
                # PLACEHOLDER: Parse actual response format
                return response.json().get("capecs", [])
                
        except Exception as e:
            logger.error(f"Error fetching CAPEC data: {e}")
            return []
    
    async def fetch_attack_data(self, capec_id: str) -> List[Dict[str, Any]]:
        """
        Fetch MITRE ATT&CK data from external API based on CAPEC ID
        PLACEHOLDER: Replace with actual API endpoint and logic
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # PLACEHOLDER: Replace with actual MITRE ATT&CK API endpoint
                url = f"https://api.example.com/attacks/{capec_id}"
                
                response = await client.get(url)
                response.raise_for_status()
                
                # PLACEHOLDER: Parse actual response format
                return response.json().get("attacks", [])
                
        except Exception as e:
            logger.error(f"Error fetching Attack data: {e}")
            return []

# ========================================
# app/services/data_processor.py
# ========================================

from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app.services.external_api import ExternalAPIService
from app.crud import asset as device_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.crud import relations as relations_crud
from app.schemas.asset import DeviceCreate
from app.schemas.cve import CVECreate
from app.schemas.cwe import CWECreate
from app.schemas.capec import CAPECCreate
from app.schemas.attack import AttackCreate
from app.utils.logger import logger

class DataProcessorService:
    def __init__(self):
        self.external_api = ExternalAPIService()
    
    async def process_device_data(self, db: Session, device_data: Dict[str, Any]) -> int:
        """
        Process device data and related security information
        Returns the device ID
        """
        try:
            # Create device
            device_create = DeviceCreate(**device_data)
            device = device_crud.create_device(db, device_create)
            logger.info(f"Created device with ID: {device.id}")
            
            # Fetch and process CVEs
            cve_data_list = await self.external_api.fetch_cve_data(device_data)
            for cve_data in cve_data_list:
                cve_id = await self._process_cve_data(db, cve_data)
                if cve_id:
                    relations_crud.create_device_cve_relation(db, device.id, cve_id)
            
            return device.id
            
        except Exception as e:
            logger.error(f"Error processing device data: {e}")
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

# ========================================
# app/crud/device.py
# ========================================

from sqlalchemy.orm import Session
from app.models.asset import Device
from app.schemas.asset import DeviceCreate, DeviceUpdate
from typing import Optional, List
from app.utils.logger import logger

def get_device(db: Session, device_id: int) -> Optional[Device]:
    try:
        return db.query(Device).filter(Device.id == device_id).first()
    except Exception as e:
        logger.error(f"Error getting device {device_id}: {e}")
        return None

def get_devices(db: Session, skip: int = 0, limit: int = 100) -> List[Device]:
    try:
        return db.query(Device).offset(skip).limit(limit).all()
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return []

def create_device(db: Session, device: DeviceCreate) -> Device:
    try:
        db_device = Device(**device.dict())
        db.add(db_device)
        db.commit()
        db.refresh(db_device)
        return db_device
    except Exception as e:
        logger.error(f"Error creating device: {e}")
        db.rollback()
        raise

def update_device(db: Session, device_id: int, device: DeviceUpdate) -> Optional[Device]:
    try:
        db_device = db.query(Device).filter(Device.id == device_id).first()
        if db_device:
            for key, value in device.dict(exclude_unset=True).items():
                setattr(db_device, key, value)
            db.commit()
            db.refresh(db_device)
        return db_device
    except Exception as e:
        logger.error(f"Error updating device {device_id}: {e}")
        db.rollback()
        raise

def delete_device(db: Session, device_id: int) -> bool:
    try:
        db_device = db.query(Device).filter(Device.id == device_id).first()
        if db_device:
            db.delete(db_device)
            db.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting device {device_id}: {e}")
        db.rollback()
        raise

# ========================================
# app/crud/cve.py
# ========================================

from sqlalchemy.orm import Session
from app.models.cve import CVE
from app.schemas.cve import CVECreate
from typing import Optional, List
from app.utils.logger import logger

def get_cve(db: Session, cve_id: int) -> Optional[CVE]:
    try:
        return db.query(CVE).filter(CVE.id == cve_id).first()
    except Exception as e:
        logger.error(f"Error getting CVE {cve_id}: {e}")
        return None

def get_cve_by_cve_id(db: Session, cve_id: str) -> Optional[CVE]:
    try:
        return db.query(CVE).filter(CVE.cve_id == cve_id).first()
    except Exception as e:
        logger.error(f"Error getting CVE by CVE ID {cve_id}: {e}")
        return None

def create_cve(db: Session, cve: CVECreate) -> CVE:
    try:
        db_cve = CVE(**cve.dict())
        db.add(db_cve)
        db.commit()
        db.refresh(db_cve)
        return db_cve
    except Exception as e:
        logger.error(f"Error creating CVE: {e}")
        db.rollback()
        raise

def get_cves_by_device_id(db: Session, device_id: int) -> List[CVE]:
    try:
        from app.models.relations import DeviceCVERelation
        return db.query(CVE).join(DeviceCVERelation).filter(DeviceCVERelation.device_id == device_id).all()
    except Exception as e:
        logger.error(f"Error getting CVEs for device {device_id}: {e}")
        return []

# ========================================
# app/crud/cwe.py
# ========================================

from sqlalchemy.orm import Session
from app.models.cwe import CWE
from app.schemas.cwe import CWECreate
from typing import Optional, List
from app.utils.logger import logger

def get_cwe(db: Session, cwe_id: int) -> Optional[CWE]:
    try:
        return db.query(CWE).filter(CWE.id == cwe_id).first()
    except Exception as e:
        logger.error(f"Error getting CWE {cwe_id}: {e}")
        return None

def get_cwe_by_cwe_id(db: Session, cwe_id: str) -> Optional[CWE]:
    try:
        return db.query(CWE).filter(CWE.cwe_id == cwe_id).first()
    except Exception as e:
        logger.error(f"Error getting CWE by CWE ID {cwe_id}: {e}")
        return None

def create_cwe(db: Session, cwe: CWECreate) -> CWE:
    try:
        db_cwe = CWE(**cwe.dict())
        db.add(db_cwe)
        db.commit()
        db.refresh(db_cwe)
        return db_cwe
    except Exception as e:
        logger.error(f"Error creating CWE: {e}")
        db.rollback()
        raise

def get_cwes_by_cve_id(db: Session, cve_id: int) -> List[CWE]:
    try:
        from app.models.relations import CVECWERelation
        return db.query(CWE).join(CVECWERelation).filter(CVECWERelation.cve_id == cve_id).all()
    except Exception as e:
        logger.error(f"Error getting CWEs for CVE {cve_id}: {e}")
        return []

# ========================================
# app/crud/capec.py
# ========================================

from sqlalchemy.orm import Session
from app.models.capec import CAPEC
from app.schemas.capec import CAPECCreate
from typing import Optional, List
from app.utils.logger import logger

def get_capec(db: Session, capec_id: int) -> Optional[CAPEC]:
    try:
        return db.query(CAPEC).filter(CAPEC.id == capec_id).first()
    except Exception as e:
        logger.error(f"Error getting CAPEC {capec_id}: {e}")
        return None

def get_capec_by_capec_id(db: Session, capec_id: str) -> Optional[CAPEC]:
    try:
        return db.query(CAPEC).filter(CAPEC.capec_id == capec_id).first()
    except Exception as e:
        logger.error(f"Error getting CAPEC by CAPEC ID {capec_id}: {e}")
        return None

def create_capec(db: Session, capec: CAPECCreate) -> CAPEC:
    try:
        db_capec = CAPEC(**capec.dict())
        db.add(db_capec)
        db.commit()
        db.refresh(db_capec)
        return db_capec
    except Exception as e:
        logger.error(f"Error creating CAPEC: {e}")
        db.rollback()
        raise

def get_capecs_by_cwe_id(db: Session, cwe_id: int) -> List[CAPEC]:
    try:
        from app.models.relations import CWECAPECRelation
        return db.query(CAPEC).join(CWECAPECRelation).filter(CWECAPECRelation.cwe_id == cwe_id).all()
    except Exception as e:
        logger.error(f"Error getting CAPECs for CWE {cwe_id}: {e}")
        return []

# ========================================
# app/crud/attack.py
# ========================================

from sqlalchemy.orm import Session
from app.models.attack import Attack
from app.schemas.attack import AttackCreate
from typing import Optional, List
from app.utils.logger import logger

def get_attack(db: Session, attack_id: int) -> Optional[Attack]:
    try:
        return db.query(Attack).filter(Attack.id == attack_id).first()
    except Exception as e:
        logger.error(f"Error getting Attack {attack_id}: {e}")
        return None

def get_attack_by_technique_id(db: Session, technique_id: str) -> Optional[Attack]:
    try:
        return db.query(Attack).filter(Attack.technique_id == technique_id).first()
    except Exception as e:
        logger.error(f"Error getting Attack by technique ID {technique_id}: {e}")
        return None

def create_attack(db: Session, attack: AttackCreate) -> Attack:
    try:
        db_attack = Attack(**attack.dict())
        db.add(db_attack)
        db.commit()
        db.refresh(db_attack)
        return db_attack
    except Exception as e:
        logger.error(f"Error creating Attack: {e}")
        db.rollback()
        raise

def get_attacks_by_capec_id(db: Session, capec_id: int) -> List[Attack]:
    try:
        from app.models.relations import CAPECAttackRelation
        return db.query(Attack).join(CAPECAttackRelation).filter(CAPECAttackRelation.capec_id == capec_id).all()
    except Exception as e:
        logger.error(f"Error getting Attacks for CAPEC {capec_id}: {e}")
        return []

# ========================================
# app/crud/relations.py
# ========================================

from sqlalchemy.orm import Session
from app.models.relations import DeviceCVERelation, CVECWERelation, CWECAPECRelation, CAPECAttackRelation
from app.utils.logger import logger

def create_device_cve_relation(db: Session, device_id: int, cve_id: int) -> DeviceCVERelation:
    try:
        # Check if relation already exists
        existing = db.query(DeviceCVERelation).filter(
            DeviceCVERelation.device_id == device_id,
            DeviceCVERelation.cve_id == cve_id
        ).first()
        
        if existing:
            return existing
        
        db_relation = DeviceCVERelation(device_id=device_id, cve_id=cve_id)
        db.add(db_relation)
        db.commit()
        db.refresh(db_relation)
        return db_relation
    except Exception as e:
        logger.error(f"Error creating device-CVE relation: {e}")
        db.rollback()
        raise

def create_cve_cwe_relation(db: Session, cve_id: int, cwe_id: int) -> CVECWERelation:
    try:
        # Check if relation already exists
        existing = db.query(CVECWERelation).filter(
            CVECWERelation.cve_id == cve_id,
            CVECWERelation.cwe_id == cwe_id
        ).first()
        
        if existing:
            return existing
        
        db_relation = CVECWERelation(cve_id=cve_id, cwe_id=cwe_id)
        db.add(db_relation)
        db.commit()
        db.refresh(db_relation)
        return db_relation
    except Exception as e:
        logger.error(f"Error creating CVE-CWE relation: {e}")
        db.rollback()
        raise

def create_cwe_capec_relation(db: Session, cwe_id: int, capec_id: int) -> CWECAPECRelation:
    try:
        # Check if relation already exists
        existing = db.query(CWECAPECRelation).filter(
            CWECAPECRelation.cwe_id == cwe_id,
            CWECAPECRelation.capec_id == capec_id
        ).first()
        
        if existing:
            return existing
        
        db_relation = CWECAPECRelation(cwe_id=cwe_id, capec_id=capec_id)
        db.add(db_relation)
        db.commit()
        db.refresh(db_relation)
        return db_relation
    except Exception as e:
        logger.error(f"Error creating CWE-CAPEC relation: {e}")
        db.rollback()
        raise

def create_capec_attack_relation(db: Session, capec_id: int, attack_id: int) -> CAPECAttackRelation:
    try:
        # Check if relation already exists
        existing = db.query(CAPECAttackRelation).filter(
            CAPECAttackRelation.capec_id == capec_id,
            CAPECAttackRelation.attack_id == attack_id
        ).first()
        
        if existing:
            return existing
        
        db_relation = CAPECAttackRelation(capec_id=capec_id, attack_id=attack_id)
        db.add(db_relation)
        db.commit()
        db.refresh(db_relation)
        return db_relation
    except Exception as e:
        logger.error(f"Error creating CAPEC-Attack relation: {e}")
        db.rollback()
        raise

def delete_device_relations(db: Session, device_id: int) -> bool:
    try:
        db.query(DeviceCVERelation).filter(DeviceCVERelation.device_id == device_id).delete()
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting device relations: {e}")
        db.rollback()
        raise

# ========================================
# app/routers/devices.py
# ========================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.schemas.asset import Device, DeviceCreate, DeviceUpdate
from app.schemas.response import DeviceFullResponse, APIResponse
from app.crud import asset as device_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.crud import relations as relations_crud
from app.services.data_processor import DataProcessorService
from app.utils.logger import logger

router = APIRouter(prefix="/devices", tags=["devices"])
data_processor = DataProcessorService()

@router.get("/", response_model=List[Device])
async def get_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all devices with pagination"""
    try:
        devices = device_crud.get_devices(db, skip=skip, limit=limit)
        return devices
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{device_id}", response_model=DeviceFullResponse)
async def get_device_full(device_id: int, db: Session = Depends(get_db)):
    """Get device with all related security information"""
    try:
        device = device_crud.get_device(db, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get all related data
        cves = cve_crud.get_cves_by_device_id(db, device_id)
        
        # Get CWEs for all CVEs
        cwes = []
        for cve in cves:
            cve_cwes = cwe_crud.get_cwes_by_cve_id(db, cve.id)
            cwes.extend(cve_cwes)
        
        # Get CAPECs for all CWEs
        capecs = []
        for cwe in cwes:
            cwe_capecs = capec_crud.get_capecs_by_cwe_id(db, cwe.id)
            capecs.extend(cwe_capecs)
        
        # Get Attacks for all CAPECs
        attacks = []
        for capec in capecs:
            capec_attacks = attack_crud.get_attacks_by_capec_id(db, capec.id)
            attacks.extend(capec_attacks)
        
        # Remove duplicates
        cwes = list({cwe.id: cwe for cwe in cwes}.values())
        capecs = list({capec.id: capec for capec in capecs}.values())
        attacks = list({attack.id: attack for attack in attacks}.values())
        
        return DeviceFullResponse(
            device=device,
            cves=cves,
            cwes=cwes,
            capecs=capecs,
            attacks=attacks
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device full data: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/", response_model=APIResponse)
async def create_device(device: DeviceCreate, db: Session = Depends(get_db)):
    """Create a new device and fetch related security data"""
    try:
        device_id = await data_processor.process_device_data(db, device.dict())
        
        return APIResponse(
            success=True,
            message="Device created successfully",
            data={"device_id": device_id}
        )
    except Exception as e:
        logger.error(f"Error creating device: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/{device_id}", response_model=APIResponse)
async def update_device(device_id: int, device: DeviceUpdate, db: Session = Depends(get_db)):
    """Update device information"""
    try:
        updated_device = device_crud.update_device(db, device_id, device)
        if not updated_device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return APIResponse(
            success=True,
            message="Device updated successfully",
            data={"device_id": device_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/{device_id}", response_model=APIResponse)
async def delete_device(device_id: int, db: Session = Depends(get_db)):
    """Delete device and all its relations"""
    try:
        # Delete relations first
        relations_crud.delete_device_relations(db, device_id)
        
        # Delete device
        deleted = device_crud.delete_device(db, device_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return APIResponse(
            success=True,
            message="Device deleted successfully",
            data={"device_id": device_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/{device_id}/refresh", response_model=APIResponse)
async def refresh_device_data(device_id: int, db: Session = Depends(get_db)):
    """Refresh device security data from external APIs"""
    try:
        device = device_crud.get_device(db, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Process updated data
        await data_processor.process_device_data(db, {
            "name": device.name,
            "vendor": device.vendor,
            "version": device.version,
            "description": device.description
        })
        
        return APIResponse(
            success=True,
            message="Device data refreshed successfully",
            data={"device_id": device_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing device data: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========================================
# app/routers/cves.py
# ========================================

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.schemas.cve import CVE
from app.crud import cve as cve_crud
from app.utils.logger import logger

router = APIRouter(prefix="/cves", tags=["cves"])

@router.get("/", response_model=List[CVE])
async def get_cves(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all CVEs with pagination"""
    try:
        # You can implement get_cves in cve_crud if needed
        return []
    except Exception as e:
        logger.error(f"Error getting CVEs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{cve_id}", response_model=CVE)
async def get_cve(cve_id: int, db: Session = Depends(get_db)):
    """Get specific CVE by ID"""
    try:
        cve = cve_crud.get_cve(db, cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        return cve
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CVE: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========================================
# app/main.py
# ========================================

from fastapi import FastAPI
from app.routers import assets, cves
from app.database import engine, Base
from app.utils.logger import logger

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Backend API",
    description="API for managing devices and their security information (CVEs, CWEs, CAPECs, ATT&CK)",
    version="1.0.0"
)

# Include routers
app.include_router(assets.router, prefix="/api/v1")
app.include_router(cves.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Security Backend API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# ========================================
# alembic.ini
# ========================================

"""
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql://username:password@localhost:5432/security_db

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""

# ========================================
# Setup Instructions
# ========================================

"""
1. Create project structure:
   mkdir my_app
   cd my_app
   mkdir -p app/{models,schemas,crud,routers,services,utils}
   touch app/__init__.py
   touch app/models/__init__.py
   touch app/schemas/__init__.py
   touch app/crud/__init__.py
   touch app/routers/__init__.py
   touch app/services/__init__.py
   touch app/utils/__init__.py

2. Set up virtual environment:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
   pip install -r requirements.txt

4. Set up PostgreSQL:
   # Option 1: Docker (recommended)
   docker run --name postgres_db -e POSTGRES_PASSWORD=password -e POSTGRES_DB=security_db -p 5432:5432 -d postgres:13
   
   # Option 2: Native installation
   # Install PostgreSQL and create database manually

5. Configure environment:
   cp .env.example .env
   # Edit .env with your database credentials

6. Initialize Alembic:
   alembic init alembic
   # Edit alembic.ini with your database URL
   # Edit alembic/env.py to import your models

7. Create and run migrations:
   alembic revision --autogenerate -m "Initial migration"
   alembic upgrade head

8. Run the application:
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

9. Access API documentation:
   http://localhost:8000/docs (Swagger UI)
   http://localhost:8000/redoc (ReDoc)

API Endpoints:
- GET /api/v1/devices/ - Get all devices
- GET /api/v1/devices/{device_id} - Get device with full security data
- POST /api/v1/devices/ - Create new device
- PUT /api/v1/devices/{device_id} - Update device
- DELETE /api/v1/devices/{device_id} - Delete device
- POST /api/v1/devices/{device_id}/refresh - Refresh device security data
- GET /api/v1/cves/ - Get all CVEs
- GET /api/v1/cves/{cve_id} - Get specific CVE
"""

# ========================================
# Docker Setup (Optional)
# ========================================

"""
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: security_db
      POSTGRES_USER: username
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgresql://username:password@postgres:5432/security_db
    volumes:
      - ./app:/app/app

volumes:
  postgres_data:

# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
"""