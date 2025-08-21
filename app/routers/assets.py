# routers/assets.py
"""
Optional Assets CRUD Router for Advanced Asset Management
Only include this if you need direct asset manipulation capabilities
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.schemas.asset import Asset, AssetCreate, AssetUpdate
from app.crud import asset as asset_crud
from app.utils.logger import logger

router = APIRouter(prefix="/assets", tags=["assets-management"])


@router.get("/", response_model=List[Asset])
async def get_all_assets(
    skip: int = 0, 
    limit: int = 100, 
    department: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get all assets with pagination and optional filtering"""
    try:
        if department:
            assets = db.query(asset_crud.Asset).filter(
                asset_crud.Asset.department.ilike(f"%{department}%")
            ).offset(skip).limit(limit).all()
        else:
            assets = asset_crud.get_assets(db, skip=skip, limit=limit)
        return assets
    except Exception as e:
        logger.error(f"Error getting assets: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{asset_id}", response_model=Asset)
async def get_asset_by_id(asset_id: int, db: Session = Depends(get_db)):
    """Get specific asset by ID"""
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/", response_model=Asset)
async def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    """Create a new asset manually"""
    try:
        return asset_crud.create_asset(db, asset)
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{asset_id}", response_model=Asset)
async def update_asset(asset_id: int, asset: AssetUpdate, db: Session = Depends(get_db)):
    """Update asset information"""
    try:
        updated_asset = asset_crud.update_asset(db, asset_id, asset)
        if not updated_asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return updated_asset
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")