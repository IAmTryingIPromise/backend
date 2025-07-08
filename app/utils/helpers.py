from typing import Dict, Any, Optional
import json
from datetime import datetime

def format_response(
    success: bool,
    data: Optional[Dict[str, Any]] = None,
    message: Optional[str] = None,
    status_code: Optional[int] = None
) -> Dict[str, Any]:
    """Format standard API response"""
    response = {
        "success": success,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if data is not None:
        response["data"] = data
    if message is not None:
        response["message"] = message
    if status_code is not None:
        response["status_code"] = status_code
    
    return response

def sanitize_json(data: Any) -> str:
    """Safely convert data to JSON string"""
    try:
        return json.dumps(data, default=str, ensure_ascii=False)
    except Exception:
        return str(data)

def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> List[str]:
    """Validate that required fields are present in data"""
    missing_fields = []
    for field in required_fields:
        if field not in data or data[field] is None:
            missing_fields.append(field)
    return missing_fields