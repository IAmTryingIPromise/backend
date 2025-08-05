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