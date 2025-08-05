from sqlalchemy.orm import Session
from app.models.relations import AssetCVERelation, CVECWERelation, CWECAPECRelation, CAPECAttackRelation
from app.utils.logger import logger

def create_asset_cve_relation(db: Session, asset_id: int, cve_id: int) -> AssetCVERelation:
    try:
        # Check if relation already exists
        existing = db.query(AssetCVERelation).filter(
            AssetCVERelation.asset_id == asset_id,
            AssetCVERelation.cve_id == cve_id
        ).first()
        
        if existing:
            return existing
        
        db_relation = AssetCVERelation(asset_id=asset_id, cve_id=cve_id)
        db.add(db_relation)
        db.commit()
        db.refresh(db_relation)
        return db_relation
    except Exception as e:
        logger.error(f"Error creating asset-CVE relation: {e}")
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

def delete_asset_relations(db: Session, asset_id: int) -> bool:
    try:
        db.query(AssetCVERelation).filter(AssetCVERelation.asset_id == asset_id).delete()
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting asset relations: {e}")
        db.rollback()
        raise