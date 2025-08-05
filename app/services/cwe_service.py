# app/services/cwe_service.py
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class CWEService:
    """Service for interacting with MITRE CWE API"""
    
    def __init__(self):
        self.max_concurrent = 25
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.cwe_cache: Dict[str, Any] = {}
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=50,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=20, connect=5)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'SecurityScanner/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def fetch_cwe_details_batch(self, cwe_ids: List[str]) -> Dict[str, Any]:
        """Fetch multiple CWE details concurrently with smart batching"""
        # Filter out already cached CWEs
        uncached_cwe_ids = [cwe_id for cwe_id in cwe_ids if cwe_id not in self.cwe_cache]
        
        if not uncached_cwe_ids:
            return {cwe_id: self.cwe_cache[cwe_id] for cwe_id in cwe_ids}
        
        logger.info(f"Fetching {len(uncached_cwe_ids)} unique CWE details...")
        
        # Ensure session is available
        if not self.session:
            await self.__aenter__()
        
        # Create tasks for uncached CWEs
        tasks = []
        for cwe_id in uncached_cwe_ids:
            task = self._fetch_single_cwe(cwe_id)
            tasks.append(task)
        
        # Execute all CWE requests concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Update cache with results
        for cwe_id, result in zip(uncached_cwe_ids, results):
            if isinstance(result, Exception):
                self.cwe_cache[cwe_id] = None
            else:
                self.cwe_cache[cwe_id] = result
        
        # Return all requested CWEs (cached + newly fetched)
        return {cwe_id: self.cwe_cache[cwe_id] for cwe_id in cwe_ids}
    
    async def _fetch_single_cwe(self, cwe_id: str) -> Optional[Dict]:
        """Fetch a single CWE with semaphore control"""
        url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
        
        async with self.semaphore:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.debug(f"Fetched CWE-{cwe_id} successfully")
                        return data
                    else:
                        logger.warning(f"Failed to fetch CWE-{cwe_id}: HTTP {response.status}")
                        return None
            except Exception as e:
                logger.error(f"Error fetching CWE-{cwe_id}: {e}")
                return None