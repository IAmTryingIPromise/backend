from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.schemas.asset import Asset, AssetCreate, AssetUpdate
from app.schemas.response import AssetFullResponse, APIResponse
from app.crud import asset as asset_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.crud import relations as relations_crud
from app.services.data_processor import DataProcessorService
from app.utils.logger import logger

router = APIRouter(prefix="/assets", tags=["assets"])
data_processor = DataProcessorService()

@router.get("/", response_model=List[Asset])
async def get_assets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all assets with pagination"""
    try:
        assets = asset_crud.get_assets(db, skip=skip, limit=limit)
        return assets
    except Exception as e:
        logger.error(f"Error getting assets: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{asset_id}", response_model=AssetFullResponse)
async def get_asset_full(asset_id: int, db: Session = Depends(get_db)):
    """Get asset with all related security information"""
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Get all related data
        cves = cve_crud.get_cves_by_asset_id(db, asset_id)
        
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
        
        return AssetFullResponse(
            asset=asset,
            cves=cves,
            cwes=cwes,
            capecs=capecs,
            attacks=attacks
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting asset full data: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/", response_model=APIResponse)
async def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    """Create a new asset and fetch related security data"""
    try:
        asset_id = await data_processor.process_asset_data(db, asset.model_dump())
        
        return APIResponse(
            success=True,
            message="Asset created successfully",
            data={"asset_id": asset_id}
        )
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/{asset_id}", response_model=APIResponse)
async def update_asset(asset_id: int, asset: AssetUpdate, db: Session = Depends(get_db)):
    """Update asset information"""
    try:
        updated_asset = asset_crud.update_asset(db, asset_id, asset)
        if not updated_asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return APIResponse(
            success=True,
            message="Asset updated successfully",
            data={"asset_id": asset_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/{asset_id}", response_model=APIResponse)
async def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """Delete asset and all its relations"""
    try:
        # Delete relations first
        relations_crud.delete_asset_relations(db, asset_id)
        
        # Delete asset
        deleted = asset_crud.delete_asset(db, asset_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return APIResponse(
            success=True,
            message="Asset deleted successfully",
            data={"asset_id": asset_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/{asset_id}/refresh", response_model=APIResponse)
async def refresh_asset_data(asset_id: int, db: Session = Depends(get_db)):
    """Refresh asset security data from external APIs"""
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Process updated data
        await data_processor.process_asset_data(db, {
            "name": asset.name,
            "vendor": asset.vendor,
            "version": asset.version,
            "description": asset.description
        })
        
        return APIResponse(
            success=True,
            message="Asset data refreshed successfully",
            data={"asset_id": asset_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing asset data: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")