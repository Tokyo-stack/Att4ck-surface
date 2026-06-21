"""
Web Crawler Module - Fetches and analyzes web content
"""

import os
import re
import time
import tempfile
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class WebCrawler:
    """Web crawler for fetching and analyzing web applications"""
    
    def __init__(self, target_url: str, max_depth: int = 2, max_pages: int = 50):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.js_files: List[str] = []
        self.html_pages: List[str] = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def crawl(self) -> Dict[str, List[str]]:
        """Main crawling method"""
        console.print(f"[cyan]Crawling: {self.target_url}[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Crawling pages...", total=None)
            self._crawl_page(self.target_url, 0)
            progress.update(task, completed=True)
        
        console.print(f"[green]Found: {len(self.js_files)} JS files, {len(self.html_pages)} HTML pages[/green]")
        
        return {
            'js_files': self.js_files,
            'html_pages': self.html_pages
        }
    
    def _crawl_page(self, url: str, depth: int):
        """Recursive page crawling"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        if url in self.visited_urls:
            return
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return
            
            self.visited_urls.add(url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Save HTML content
            self.html_pages.append(url)
            
            # Extract JS files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if js_url not in self.js_files:
                    self.js_files.append(js_url)
            
            # Extract inline JS
            for script in soup.find_all('script', src=False):
                if script.string:
                    # Save inline scripts as temp files
                    self._save_inline_js(script.string)
            
            # Find internal links for further crawling
            if depth < self.max_depth:
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Only crawl same domain
                    if self._is_same_domain(full_url) and full_url not in self.visited_urls:
                        if self._should_crawl(full_url):
                            time.sleep(0.5)  # Rate limiting
                            self._crawl_page(full_url, depth + 1)
        
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {e}[/red]")
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is from the same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or not parsed.netloc
        except:
            return False
    
    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled"""
        # Skip non-HTML content
        skip_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip mailto, tel, etc.
        if any(url.startswith(prefix) for prefix in ['mailto:', 'tel:', 'javascript:']):
            return False
        
        # Skip anchor links
        if '#' in url and not url.split('#')[0]:
            return False
        
        return True
    
    def _save_inline_js(self, js_content: str):
        """Save inline JavaScript to temp directory"""
        temp_dir = tempfile.gettempdir()
        js_file = os.path.join(temp_dir, f'inline_js_{len(self.js_files)}.js')
        
        with open(js_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(js_content)
        
        self.js_files.append(js_file)
    
    def fetch_js_content(self, js_url: str) -> Optional[str]:
        """Fetch JavaScript content from URL"""
        try:
            # If it's a file path, read directly
            if os.path.exists(js_url):
                with open(js_url, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            
            # Otherwise fetch from web
            response = self.session.get(js_url, timeout=10)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            console.print(f"[red]Error fetching JS: {e}[/red]")
            return None
    
    def scan_js_for_patterns(self, js_content: str, patterns: List[re.Pattern]) -> List[Dict]:
        """Scan JavaScript content for patterns"""
        findings = []
        
        if not js_content:
            return findings
        
        lines = js_content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern.search(line):
                    findings.append({
                        'line': i,
                        'snippet': line.strip()[:200],
                        'context': self._get_context(lines, i)
                    })
        
        return findings
    
    def _get_context(self, lines: List[str], line_num: int, context_size: int = 3) -> str:
        """Get context around a line"""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        return '\n'.join(lines[start:end])
    
    def download_js_files(self, output_dir: str) -> List[str]:
        """Download all JS files to output directory"""
        downloaded_files = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading JS files...", total=len(self.js_files))
            
            for js_url in self.js_files:
                try:
                    # Generate filename
                    if os.path.exists(js_url):
                        # Inline JS file
                        filename = os.path.basename(js_url)
                        filepath = os.path.join(output_dir, filename)
                        with open(js_url, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(content)
                        downloaded_files.append(filepath)
                    else:
                        # Web URL
                        filename = js_url.split('/')[-1] or f'script_{len(downloaded_files)}.js'
                        if not filename.endswith('.js'):
                            filename += '.js'
                        filepath = os.path.join(output_dir, filename)
                        
                        content = self.fetch_js_content(js_url)
                        if content:
                            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(content)
                            downloaded_files.append(filepath)
                    
                    progress.update(task, advance=1)
                
                except Exception as e:
                    console.print(f"[red]Error downloading {js_url}: {e}[/red]")
        
        return downloaded_files
    
    def get_web_links(self) -> List[str]:
        """Get all web links from crawled pages"""
        return list(self.visited_urls)