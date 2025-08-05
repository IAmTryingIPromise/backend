# app/services/nvd_service.py
import asyncio
import aiohttp
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class NVDService:
    """Service for interacting with NIST NVD API"""
    
    def __init__(self):
        # PLACEHOLDER: Replace with your actual API key
        self.api_key = "YOUR_NVD_API_KEY_HERE"
        self.max_concurrent = 25
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
    
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
    
    async def fetch_nvd_data(self, cpe_name: str) -> Dict:
        """Fetch CVE data from NVD for a specific CPE"""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "cpeName": cpe_name,
            "startIndex": 0,
            "resultsPerPage": 2000,
        }
        headers = {"apiKey": self.api_key}
        
        logger.info(f"Fetching NVD data for CPE: {cpe_name}")
        
        # Ensure session is available
        if not self.session:
            await self.__aenter__()
        
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Found {len(data.get('vulnerabilities', []))} vulnerabilities")
                        return data
                    else:
                        logger.error(f"NVD API Error: {response.status}")
                        return {}
            except Exception as e:
                logger.error(f"Error fetching NVD data: {e}")
                return {}
    
    async def fetch_epss_scores_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for multiple CVEs in batches"""
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
        
        # EPSS API supports multiple CVEs in one request
        batch_size = 50
        all_results = {}
        
        # Ensure session is available
        if not self.session:
            await self.__aenter__()
        
        tasks = []
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            task = self._fetch_epss_batch(batch)
            tasks.append(task)
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if isinstance(result, dict):
                all_results.update(result)
        
        logger.info(f"Retrieved EPSS scores for {len(all_results)} CVEs")
        return all_results
    
    async def _fetch_epss_batch(self, cve_batch: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for a batch of CVEs"""
        url = "https://api.first.org/data/v1/epss"
        params = {"cve": ",".join(cve_batch)}
        
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = {}
                        for item in data.get("data", []):
                            results[item["cve"]] = float(item["epss"])
                        return results
            except Exception as e:
                logger.error(f"Error fetching EPSS batch: {e}")
            
            return {}