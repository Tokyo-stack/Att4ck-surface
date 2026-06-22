"""
Web Crawler Module - Enhanced for endpoint discovery
"""

import os
import re
import tempfile
import requests
from urllib.parse import urljoin, urlparse, quote
from typing import List, Dict, Set, Optional
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove invalid characters"""
    filename = filename.split('?')[0]
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'_+', '_', filename)
    if not filename.endswith('.js'):
        filename += '.js'
    return filename


class WebCrawler:
    def __init__(self, target_url: str, max_pages: int = 100):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.js_files: List[str] = []
        self.html_pages: List[str] = []
        self.endpoints: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def crawl(self) -> Dict[str, List[str]]:
        """Main crawling method"""
        console.print(f"[cyan]Crawling: {self.target_url}[/cyan]")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code != 200:
                console.print(f"[red]Failed to fetch: {response.status_code}[/red]")
                return {'js_files': [], 'html_pages': [], 'endpoints': []}
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(self.target_url, href)
                if self._is_same_domain(full_url):
                    self.discovered_urls.add(full_url)
                    self._extract_endpoints(full_url)
            
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    src = urljoin(self.target_url, src)
                elif not src.startswith('http'):
                    src = urljoin(self.target_url, src)
                
                clean_url = src.split('?')[0]
                if clean_url.endswith('.js') and clean_url not in self.js_files:
                    self.js_files.append(clean_url)
            
            for script in soup.find_all('script', src=False):
                if script.string:
                    self._extract_endpoints_from_js(script.string)
            
            for tag in soup.find_all(attrs={"data-url": True}):
                endpoint = tag.get('data-url')
                if endpoint:
                    self.endpoints.add(endpoint)
            
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    self.endpoints.add(action)
            
            console.print(f"[green]Found: {len(self.js_files)} JS files, {len(self.discovered_urls)} URLs, {len(self.endpoints)} endpoints[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return {
            'js_files': self.js_files,
            'html_pages': list(self.discovered_urls),
            'endpoints': list(self.endpoints)
        }
    
    def _is_same_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or not parsed.netloc
        except:
            return False
    
    def _extract_endpoints(self, url: str):
        parsed = urlparse(url)
        path = parsed.path
        if path and path != '/':
            self.endpoints.add(path)
        segments = path.split('/')
        for i in range(1, len(segments) + 1):
            partial = '/'.join(segments[:i])
            if partial:
                self.endpoints.add('/' + partial)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    self.endpoints.add(f'?{key}=')
    
    def _extract_endpoints_from_js(self, js_content: str):
        patterns = [
            r"['\"](/api/[^'\"]+)['\"]",
            r"['\"](/v\d+/[^'\"]+)['\"]",
            r"['\"](/admin/[^'\"]+)['\"]",
            r"['\"](/user/[^'\"]+)['\"]",
            r"['\"](/login)['\"]",
            r"['\"](/logout)['\"]",
            r"['\"](/register)['\"]",
            r"['\"](/dashboard)['\"]",
            r"['\"](/profile)['\"]",
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.(get|post|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"url\s*:\s*['\"]([^'\"]+)['\"]",
            r"endpoint\s*:\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[-1] if len(match) > 1 else match[0]
                else:
                    endpoint = match
                if endpoint and endpoint.startswith('/'):
                    self.endpoints.add(endpoint)
    
    def download_js_files(self, output_dir: str) -> List[str]:
        """Download JS files with sanitized filenames"""
        os.makedirs(output_dir, exist_ok=True)
        downloaded = []
        failed = 0
        
        for i, js_url in enumerate(self.js_files):
            try:
                filename = os.path.basename(js_url)
                sanitized = sanitize_filename(filename)
                filepath = os.path.join(output_dir, sanitized)
                
                if os.path.exists(filepath):
                    downloaded.append(filepath)
                    continue
                
                if js_url.startswith('//'):
                    js_url = 'https:' + js_url
                elif js_url.startswith('/'):
                    js_url = urljoin(self.target_url, js_url)
                
                response = self.session.get(js_url, timeout=10)
                if response.status_code == 200:
                    with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(response.text)
                    downloaded.append(filepath)
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                if failed <= 10:
                    console.print(f"[dim]Error downloading {js_url}: {e}[/dim]")
        
        if failed > 10:
            console.print(f"[dim]... and {failed - 10} more download errors[/dim]")
        elif failed > 0:
            console.print(f"[dim]{failed} files failed to download[/dim]")
        
        return downloaded
    
    def get_endpoints(self) -> List[str]:
        return sorted(list(self.endpoints))