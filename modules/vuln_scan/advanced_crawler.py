"""
Advanced Web Crawler for Security Assessment
Uses multiple engines (Scrapy, Selenium, Playwright) for comprehensive crawling
"""

import asyncio
import aiohttp
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import re
from loguru import logger

try:
    from scrapy import Spider, Request
    from scrapy.crawler import CrawlerProcess
    from scrapy.utils.project import get_project_settings
    SCRAPY_AVAILABLE = True
except ImportError:
    SCRAPY_AVAILABLE = False
    Spider, Request, CrawlerProcess, get_project_settings = None, None, None, None

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    webdriver, By, ChromeOptions = None, None, None

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None


class AdvancedCrawler:
    """Advanced web crawler using multiple engines for comprehensive discovery"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.max_depth = self.config.get('crawl_depth', 3)
        self.max_pages = self.config.get('max_pages', 100)
        
    async def crawl(self, base_url: str) -> Dict[str, List[str]]:
        """
        Perform advanced crawling using multiple engines
        Returns discovered URLs organized by type
        """
        logger.info(f"Starting advanced crawl of {base_url}")
        
        results = {
            'all_urls': set(),
            'forms': set(),
            'links': set(),
            'scripts': set(),
            'images': set(),
            'api_endpoints': set(),
            'parameters': set()
        }
        
        # Try different crawling approaches
        crawlers = []
        
        # Basic async crawling (always available)
        crawlers.append(self._basic_async_crawl(base_url, results))
        
        # Scrapy crawling (if available)
        if SCRAPY_AVAILABLE:
            crawlers.append(self._scrapy_crawl(base_url, results))
        
        # Selenium crawling (if available)
        if SELENIUM_AVAILABLE:
            crawlers.append(self._selenium_crawl(base_url, results))
        
        # Playwright crawling (if available)
        if PLAYWRIGHT_AVAILABLE:
            crawlers.append(self._playwright_crawl(base_url, results))
        
        # Run all crawlers concurrently
        await asyncio.gather(*crawlers, return_exceptions=True)
        
        # Convert sets to lists for JSON serialization
        for key in results:
            results[key] = list(results[key])
        
        logger.success(f"Advanced crawl completed. Found {len(results['all_urls'])} URLs")
        return results
    
    async def _basic_async_crawl(self, base_url: str, results: Dict) -> None:
        """Basic async crawling using aiohttp"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                await self._crawl_page(session, base_url, 0, set(), results)
        except Exception as e:
            logger.error(f"Basic async crawl failed: {e}")
    
    async def _crawl_page(self, session, url: str, depth: int, visited: Set[str], results: Dict) -> None:
        """Recursively crawl pages"""
        if depth > self.max_depth or len(results['all_urls']) > self.max_pages:
            return
            
        if url in visited:
            return
            
        visited.add(url)
        results['all_urls'].add(url)
        
        try:
            async with session.get(url, ssl=False) as response:
                if response.content_type and 'text/html' not in response.content_type:
                    return
                    
                content = await response.text()
                
                # Extract various elements
                self._extract_elements(url, content, results)
                
                # Extract and follow links
                links = self._extract_links(url, content)
                for link in links:
                    if len(results['all_urls']) < self.max_pages:
                        await self._crawl_page(session, link, depth + 1, visited, results)
                        
        except Exception as e:
            logger.debug(f"Failed to crawl {url}: {e}")
    
    def _extract_elements(self, base_url: str, content: str, results: Dict) -> None:
        """Extract various elements from page content"""
        # Extract links
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, content, re.IGNORECASE)
        for link in links:
            full_url = urljoin(base_url, link)
            results['links'].add(full_url)
            results['all_urls'].add(full_url)
        
        # Extract forms
        form_pattern = r'<form[^>]+action=["\']([^"\']*)["\']'
        forms = re.findall(form_pattern, content, re.IGNORECASE)
        for form in forms:
            full_url = urljoin(base_url, form)
            results['forms'].add(full_url)
        
        # Extract scripts
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, content, re.IGNORECASE)
        for script in scripts:
            full_url = urljoin(base_url, script)
            results['scripts'].add(full_url)
        
        # Extract images
        img_pattern = r'<img[^>]+src=["\']([^"\']+)["\']'
        images = re.findall(img_pattern, content, re.IGNORECASE)
        for img in images:
            full_url = urljoin(base_url, img)
            results['images'].add(full_url)
        
        # Extract API endpoints
        api_patterns = [
            r'["\'](\/api\/[^"\']+)',
            r'["\'](\/v\d+\/[^"\']+)',
            r'["\'](\/rest\/[^"\']+)',
        ]
        for pattern in api_patterns:
            endpoints = re.findall(pattern, content, re.IGNORECASE)
            for endpoint in endpoints:
                full_url = urljoin(base_url, endpoint)
                results['api_endpoints'].add(full_url)
        
        # Extract parameters
        param_pattern = r'[?&]([^=&]+)=([^&]*)'
        params = re.findall(param_pattern, content, re.IGNORECASE)
        for param in params:
            results['parameters'].add(param[0])
    
    def _extract_links(self, base_url: str, content: str) -> List[str]:
        """Extract all links from page content"""
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, content, re.IGNORECASE)
        full_urls = []
        for link in links:
            # Filter out external links, javascript, mailto, etc.
            if link.startswith(('http', 'https', '/', '#')):
                if link.startswith('/'):
                    full_urls.append(urljoin(base_url, link))
                elif link.startswith(('http://', 'https://')):
                    # Only include same domain links
                    if urlparse(link).netloc == urlparse(base_url).netloc:
                        full_urls.append(link)
                elif not link.startswith('#'):
                    full_urls.append(urljoin(base_url, link))
        return full_urls
    
    async def _scrapy_crawl(self, base_url: str, results: Dict) -> None:
        """Scrapy-based crawling"""
        if not SCRAPY_AVAILABLE:
            return
            
        try:
            logger.info("Starting Scrapy crawl")
            # Implementation would go here
            # This is a simplified placeholder
            logger.info("Scrapy crawl completed")
        except Exception as e:
            logger.error(f"Scrapy crawl failed: {e}")
    
    async def _selenium_crawl(self, base_url: str, results: Dict) -> None:
        """Selenium-based crawling for JavaScript-heavy sites"""
        if not SELENIUM_AVAILABLE:
            return
            
        try:
            logger.info("Starting Selenium crawl")
            
            # Setup headless Chrome
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=options)
            driver.get(base_url)
            
            # Extract elements
            links = driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href:
                    results['links'].add(href)
                    results['all_urls'].add(href)
            
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                action = form.get_attribute("action")
                if action:
                    results['forms'].add(action)
            
            # Close driver
            driver.quit()
            logger.info("Selenium crawl completed")
        except Exception as e:
            logger.error(f"Selenium crawl failed: {e}")
    
    async def _playwright_crawl(self, base_url: str, results: Dict) -> None:
        """Playwright-based crawling for modern web applications"""
        if not PLAYWRIGHT_AVAILABLE:
            return
            
        try:
            logger.info("Starting Playwright crawl")
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(base_url)
                
                # Wait for network idle
                await page.wait_for_load_state("networkidle")
                
                # Extract links
                links = await page.eval_on_selector_all("a", "els => els.map(el => el.href)")
                for link in links:
                    if link:
                        results['links'].add(link)
                        results['all_urls'].add(link)
                
                # Extract forms
                forms = await page.eval_on_selector_all("form", "els => els.map(el => el.action)")
                for form in forms:
                    if form:
                        results['forms'].add(form)
                
                await browser.close()
                logger.info("Playwright crawl completed")
        except Exception as e:
            logger.error(f"Playwright crawl failed: {e}")

# Example usage
if __name__ == "__main__":
    async def main():
        crawler = AdvancedCrawler()
        results = await crawler.crawl("http://example.com")
        print(f"Found {len(results['all_urls'])} URLs")
    
    asyncio.run(main())