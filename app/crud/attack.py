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
        db_attack = Attack(**attack.model_dump())
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