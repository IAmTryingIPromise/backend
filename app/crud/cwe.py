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
        db_cwe = CWE(**cwe.model_dump())
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