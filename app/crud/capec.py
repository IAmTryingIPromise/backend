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
        db_capec = CAPEC(**capec.model_dump())
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