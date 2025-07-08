import httpx
from typing import Dict, Any, Optional
from ..config import settings
from ..schemas.schemas import ExternalApiRequest, ExternalApiResponse

class ExternalAPIClient:
    def __init__(self):
        self.base_url = settings.external_api_base_url
        self.api_key = settings.external_api_key
        self.default_headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    async def make_request(self, request: ExternalApiRequest) -> ExternalApiResponse:
        """
        Make a request to external API
        """
        url = f"{self.base_url}/{request.endpoint.lstrip('/')}"
        headers = {**self.default_headers, **(request.headers or {})}
        
        try:
            async with httpx.AsyncClient() as client:
                if request.method.upper() == "GET":
                    response = await client.get(url, headers=headers, params=request.data)
                elif request.method.upper() == "POST":
                    response = await client.post(url, headers=headers, json=request.data)
                elif request.method.upper() == "PUT":
                    response = await client.put(url, headers=headers, json=request.data)
                elif request.method.upper() == "DELETE":
                    response = await client.delete(url, headers=headers)
                else:
                    return ExternalApiResponse(
                        success=False,
                        status_code=400,
                        message=f"Unsupported HTTP method: {request.method}"
                    )
                
                return ExternalApiResponse(
                    success=response.status_code < 400,
                    data=response.json() if response.content else None,
                    status_code=response.status_code,
                    message=response.reason_phrase if hasattr(response, 'reason_phrase') else None
                )
        
        except httpx.RequestError as e:
            return ExternalApiResponse(
                success=False,
                status_code=500,
                message=f"Request error: {str(e)}"
            )
        except Exception as e:
            return ExternalApiResponse(
                success=False,
                status_code=500,
                message=f"Unexpected error: {str(e)}"
            )
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> ExternalApiResponse:
        """Convenience method for GET requests"""
        request = ExternalApiRequest(endpoint=endpoint, method="GET", data=params)
        return await self.make_request(request)
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> ExternalApiResponse:
        """Convenience method for POST requests"""
        request = ExternalApiRequest(endpoint=endpoint, method="POST", data=data)
        return await self.make_request(request)

# Create instance
external_api = ExternalAPIClient()