from sqlalchemy.orm import Session
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetUpdate
from typing import Optional, List
from app.utils.logger import logger
from typing import Union

def get_asset(db: Session, asset_id: int) -> Optional[Asset]:
    try:
        return db.query(Asset).filter(Asset.id == asset_id).first()
    except Exception as e:
        logger.error(f"Error getting asset {asset_id}: {e}")
        return None

def get_assets(db: Session, skip: int = 0, limit: int = 100) -> List[Asset]:
    try:
        return db.query(Asset).offset(skip).limit(limit).all()
    except Exception as e:
        logger.error(f"Error getting assets: {e}")
        return []

def create_asset(db: Session, asset: AssetCreate) -> Asset:
    try:
        db_asset = Asset(**asset.model_dump())
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)
        return db_asset
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        db.rollback()
        raise

def update_asset(db: Session, asset_id: int, asset: Union[AssetUpdate, dict]) -> Optional[Asset]:
    try:
        db_asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if db_asset:
            if isinstance(asset, dict):
                update_data = asset
            else:
                update_data = asset.model_dump(exclude_unset=True)

            for key, value in update_data.items():
                setattr(db_asset, key, value)
            db.commit()
            db.refresh(db_asset)
        return db_asset
    except Exception as e:
        logger.error(f"Error updating asset {asset_id}: {e}")
        db.rollback()
        raise

def delete_asset(db: Session, asset_id: int) -> bool:
    try:
        db_asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if db_asset:
            db.delete(db_asset)
            db.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting asset {asset_id}: {e}")
        db.rollback()
        raise