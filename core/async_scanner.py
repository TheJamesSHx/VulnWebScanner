"""Async HTTP request handler with rate limiting and retry logic."""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
from loguru import logger
import time
from collections import deque


class RateLimiter:
    """Token bucket rate limiter for request throttling."""

    def __init__(self, rate_limit: int = 100):
        """Initialize rate limiter.
        
        Args:
            rate_limit: Maximum requests per minute
        """
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.last_update = time.time()
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Acquire a token for making a request."""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill tokens based on elapsed time
            self.tokens = min(
                self.rate_limit,
                self.tokens + elapsed * (self.rate_limit / 60.0)
            )
            self.last_update = now
            
            # Wait if no tokens available
            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (60.0 / self.rate_limit)
                await asyncio.sleep(wait_time)
                self.tokens = 1
            
            self.tokens -= 1


class AsyncScanner:
    """Async HTTP scanner with connection pooling and error handling."""

    def __init__(self, config: Dict):
        """Initialize async scanner.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limiter = RateLimiter(config['performance']['rate_limit'])
        self.timeout = aiohttp.ClientTimeout(total=config['general']['timeout'])
        self.max_retries = config['general']['max_retries']
        self.user_agent = config['general']['user_agent']
        self.request_delay = config['performance']['request_delay']
        self.semaphore = asyncio.Semaphore(config['performance']['max_concurrent_requests'])
        
        logger.debug("AsyncScanner initialized")

    async def __aenter__(self):
        """Context manager entry."""
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close_session()

    async def start_session(self):
        """Create aiohttp session with connection pooling."""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                limit=self.config['performance']['max_concurrent_requests'],
                limit_per_host=10,
                ssl=False  # Set to True in production with proper cert validation
            )
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
            logger.debug("HTTP session started")

    async def close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None
            logger.debug("HTTP session closed")

    async def fetch(self, url: str, method: str = "GET", **kwargs) -> Optional[Dict[str, Any]]:
        """Fetch a URL with retry logic and rate limiting.
        
        Args:
            url: URL to fetch
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for aiohttp request
            
        Returns:
            Response dictionary or None on failure
        """
        if not self.session:
            await self.start_session()

        async with self.semaphore:
            await self.rate_limiter.acquire()
            
            for attempt in range(self.max_retries):
                try:
                    async with self.session.request(method, url, **kwargs) as response:
                        content = await response.text()
                        
                        result = {
                            'url': str(response.url),
                            'status': response.status,
                            'headers': dict(response.headers),
                            'content': content,
                            'length': len(content),
                            'elapsed': response.headers.get('X-Response-Time', 'N/A')
                        }
                        
                        logger.debug(f"{method} {url} -> {response.status}")
                        
                        # Respect request delay
                        if self.request_delay > 0:
                            await asyncio.sleep(self.request_delay)
                        
                        return result
                        
                except aiohttp.ClientError as e:
                    logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {url} - {str(e)}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        logger.error(f"Max retries reached for {url}")
                        return None
                        
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout (attempt {attempt + 1}/{self.max_retries}): {url}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        logger.error(f"Max retries reached for {url}")
                        return None

    async def fetch_many(self, urls: List[str], method: str = "GET", **kwargs) -> List[Optional[Dict]]:
        """Fetch multiple URLs concurrently.
        
        Args:
            urls: List of URLs to fetch
            method: HTTP method
            **kwargs: Additional arguments for requests
            
        Returns:
            List of response dictionaries
        """
        logger.info(f"Fetching {len(urls)} URLs concurrently...")
        tasks = [self.fetch(url, method, **kwargs) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = [r for r in results if isinstance(r, dict)]
        logger.info(f"Successfully fetched {len(valid_results)}/{len(urls)} URLs")
        
        return valid_results

    async def post(self, url: str, data: Optional[Dict] = None, 
                   json: Optional[Dict] = None, **kwargs) -> Optional[Dict]:
        """POST request wrapper.
        
        Args:
            url: URL to POST to
            data: Form data
            json: JSON data
            **kwargs: Additional arguments
            
        Returns:
            Response dictionary
        """
        return await self.fetch(url, method="POST", data=data, json=json, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[Dict]:
        """HEAD request wrapper.
        
        Args:
            url: URL to HEAD
            **kwargs: Additional arguments
            
        Returns:
            Response dictionary
        """
        return await self.fetch(url, method="HEAD", **kwargs)

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def normalize_url(self, base_url: str, path: str) -> str:
        """Normalize and join URL paths.
        
        Args:
            base_url: Base URL
            path: Path to join
            
        Returns:
            Normalized URL
        """
        return urljoin(base_url, path)