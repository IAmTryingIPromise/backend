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
        db_cve = CVE(**cve.model_dump())
        db.add(db_cve)
        db.commit()
        db.refresh(db_cve)
        return db_cve
    except Exception as e:
        logger.error(f"Error creating CVE: {e}")
        db.rollback()
        raise

def get_cves_by_asset_id(db: Session, asset_id: int) -> List[CVE]:
    try:
        from app.models.relations import AssetCVERelation
        return db.query(CVE).join(AssetCVERelation).filter(AssetCVERelation.asset_id == asset_id).all()
    except Exception as e:
        logger.error(f"Error getting CVEs for asset {asset_id}: {e}")
        return []