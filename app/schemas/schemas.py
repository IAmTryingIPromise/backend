from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

# Base schemas
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True

# API Response schemas
class ApiResponseBase(BaseSchema):
    endpoint: str
    request_data: Optional[Dict[Any, Any]] = None
    response_data: Optional[Dict[Any, Any]] = None
    status_code: Optional[int] = None

class ApiResponseCreate(ApiResponseBase):
    pass

class ApiResponseResponse(ApiResponseBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

# Generic request/response schemas for frontend communication
class GenericRequest(BaseSchema):
    data: Dict[Any, Any]
    endpoint: Optional[str] = None
    method: Optional[str] = "GET"

class GenericResponse(BaseSchema):
    success: bool
    data: Optional[Dict[Any, Any]] = None
    message: Optional[str] = None
    status_code: Optional[int] = None

# External API schemas
class ExternalApiRequest(BaseSchema):
    endpoint: str
    method: str = "GET"
    data: Optional[Dict[Any, Any]] = None
    headers: Optional[Dict[str, str]] = None

class ExternalApiResponse(BaseSchema):
    success: bool
    data: Optional[Dict[Any, Any]] = None
    status_code: int
    message: Optional[str] = None