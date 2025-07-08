from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from ..models.models import ApiResponse
from ..schemas.schemas import ApiResponseCreate

class CRUDApiResponse:
    def create(self, db: Session, obj_in: ApiResponseCreate) -> ApiResponse:
        """Create a new API response record"""
        db_obj = ApiResponse(**obj_in.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def get(self, db: Session, id: int) -> Optional[ApiResponse]:
        """Get API response by ID"""
        return db.query(ApiResponse).filter(ApiResponse.id == id).first()
    
    def get_multi(self, db: Session, skip: int = 0, limit: int = 100) -> List[ApiResponse]:
        """Get multiple API responses"""
        return db.query(ApiResponse).offset(skip).limit(limit).all()
    
    def get_by_endpoint(self, db: Session, endpoint: str) -> List[ApiResponse]:
        """Get API responses by endpoint"""
        return db.query(ApiResponse).filter(ApiResponse.endpoint == endpoint).all()
    
    def update(self, db: Session, db_obj: ApiResponse, obj_in: Dict[str, Any]) -> ApiResponse:
        """Update API response"""
        for field, value in obj_in.items():
            setattr(db_obj, field, value)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def delete(self, db: Session, id: int) -> ApiResponse:
        """Delete API response"""
        obj = db.query(ApiResponse).get(id)
        db.delete(obj)
        db.commit()
        return obj

# Create instance
api_response = CRUDApiResponse()