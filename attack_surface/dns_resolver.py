#!/usr/bin/env python3
"""
Production DNS Resolver for ATT4ck Surface
Enterprise-grade DNS resolution with multiple fallback strategies
"""

import socket
import dns.resolver
import dns.exception
import dns.name
from functools import lru_cache
from typing import Optional, List, Dict
from urllib.parse import urlparse
import threading
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class DNSConfig:
    """DNS resolver configuration"""
    primary_servers: List[str] = field(default_factory=lambda: ['8.8.8.8', '1.1.1.1'])
    secondary_servers: List[str] = field(default_factory=lambda: ['9.9.9.9', '208.67.222.222'])
    backup_servers: List[str] = field(default_factory=lambda: ['208.67.220.220', '8.26.56.26'])
    cache_ttl: int = 300  # 5 minutes
    timeout: int = 3
    lifetime: int = 5
    max_retries: int = 3
    retry_delay: float = 0.5

class DNSCache:
    """Thread-safe DNS cache with TTL"""
    
    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self._cache: Dict[str, tuple] = {}
        self._lock = threading.RLock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'expired': 0
        }
    
    def get(self, hostname: str) -> Optional[str]:
        """Get cached IP if not expired"""
        with self._lock:
            if hostname not in self._cache:
                self._stats['misses'] += 1
                return None
            
            ip, timestamp = self._cache[hostname]
            if datetime.now() - timestamp > timedelta(seconds=self.ttl):
                del self._cache[hostname]
                self._stats['expired'] += 1
                return None
            
            self._stats['hits'] += 1
            return ip
    
    def set(self, hostname: str, ip: str):
        """Cache DNS resolution result"""
        with self._lock:
            self._cache[hostname] = (ip, datetime.now())
    
    def clear(self):
        """Clear cache"""
        with self._lock:
            self._cache.clear()
            self._stats = {'hits': 0, 'misses': 0, 'expired': 0}
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            return {
                **self._stats,
                'size': len(self._cache),
                'ttl': self.ttl
            }

class ProductionDNSResolver:
    """
    Production DNS resolver with:
    - Multiple DNS server fallback
    - Thread-safe caching
    - Performance metrics
    - Comprehensive error handling
    - Support for Vercel and other modern platforms
    """
    
    # Known CDN/Platform domains that may need special handling
    PLATFORM_IPS = {
        'vercel.app': '76.76.21.21',  # Vercel CDN
        'netlify.app': '75.2.60.5',    # Netlify CDN
        'github.io': '185.199.108.153', # GitHub Pages
        'herokuapp.com': '34.120.151.151', # Heroku
        'cloudfront.net': '54.192.0.0',  # AWS CloudFront
    }
    
    def __init__(self, config: Optional[DNSConfig] = None):
        self.config = config or DNSConfig()
        self.cache = DNSCache(self.config.cache_ttl)
        self._resolver = None
        self._stats = {
            'total_resolutions': 0,
            'successful_resolutions': 0,
            'failed_resolutions': 0,
            'fallback_used': 0,
            'platform_override': 0,
            'resolution_time': 0
        }
        self._lock = threading.RLock()
        
        # Initialize resolver
        self._init_resolver()
    
    def _init_resolver(self):
        """Initialize DNS resolver with all servers"""
        all_servers = (
            self.config.primary_servers + 
            self.config.secondary_servers + 
            self.config.backup_servers
        )
        
        try:
            self._resolver = dns.resolver.Resolver()
            self._resolver.nameservers = all_servers
            self._resolver.timeout = self.config.timeout
            self._resolver.lifetime = self.config.lifetime
            logger.debug(f"DNS resolver initialized with {len(all_servers)} servers")
        except Exception as e:
            logger.error(f"Failed to initialize DNS resolver: {e}")
            # Fallback to system resolver
            self._resolver = None
    
    def _get_platform_ip(self, hostname: str) -> Optional[str]:
        """Get known IP for platform domains"""
        for platform, ip in self.PLATFORM_IPS.items():
            if hostname.endswith(platform):
                self._stats['platform_override'] += 1
                logger.debug(f"Platform override: {hostname} -> {ip}")
                return ip
        return None
    
    @lru_cache(maxsize=1000)
    def resolve(self, hostname: str, force_refresh: bool = False) -> str:
        """
        Resolve hostname to IP with multi-strategy fallback
        
        Args:
            hostname: Domain to resolve
            force_refresh: Bypass cache
        
        Returns:
            IP address as string
            
        Raises:
            Exception: If resolution fails with all strategies
        """
        # Check platform override first
        platform_ip = self._get_platform_ip(hostname)
        if platform_ip:
            return platform_ip
        
        # Check cache
        if not force_refresh:
            cached_ip = self.cache.get(hostname)
            if cached_ip:
                return cached_ip
        
        start_time = time.time()
        self._stats['total_resolutions'] += 1
        
        # Try all DNS servers in order
        for servers in [
            self.config.primary_servers,
            self.config.secondary_servers,
            self.config.backup_servers
        ]:
            try:
                ip = self._resolve_with_servers(hostname, servers)
                if ip:
                    self.cache.set(hostname, ip)
                    self._stats['successful_resolutions'] += 1
                    self._stats['resolution_time'] += (time.time() - start_time)
                    return ip
            except Exception as e:
                logger.debug(f"DNS resolution failed with {servers[0]}: {e}")
                self._stats['fallback_used'] += 1
                continue
        
        # Ultimate fallback: system DNS
        try:
            ip = socket.gethostbyname(hostname)
            self.cache.set(hostname, ip)
            self._stats['successful_resolutions'] += 1
            logger.warning(f"Used system DNS fallback for {hostname} -> {ip}")
            return ip
        except socket.gaierror as e:
            self._stats['failed_resolutions'] += 1
            raise Exception(f"Could not resolve {hostname} with any DNS server: {e}")
    
    def _resolve_with_servers(self, hostname: str, servers: List[str]) -> Optional[str]:
        """Attempt resolution with specific DNS servers"""
        for attempt in range(self.config.max_retries):
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = servers
                resolver.timeout = self.config.timeout
                resolver.lifetime = self.config.lifetime
                
                answers = resolver.resolve(hostname, 'A')
                if answers:
                    ip = str(answers[0])
                    logger.debug(f"Resolved {hostname} -> {ip} (attempt {attempt + 1})")
                    return ip
                
            except dns.exception.Timeout:
                logger.debug(f"Timeout with {servers[0]}, attempt {attempt + 1}")
                time.sleep(self.config.retry_delay * (attempt + 1))
                
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {hostname} does not exist")
                break  # Domain doesn't exist, no point retrying
                
            except (dns.exception.DNSException, Exception) as e:
                logger.debug(f"DNS error with {servers[0]}: {e}")
                time.sleep(self.config.retry_delay * (attempt + 1))
        
        return None
    
    def resolve_url(self, url: str) -> str:
        """Extract hostname from URL and resolve"""
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: {url}")
        return self.resolve(parsed.hostname)
    
    def batch_resolve(self, hostnames: List[str]) -> Dict[str, str]:
        """Resolve multiple hostnames efficiently"""
        results = {}
        for hostname in hostnames:
            try:
                results[hostname] = self.resolve(hostname)
            except Exception as e:
                logger.error(f"Failed to resolve {hostname}: {e}")
                results[hostname] = None
        return results
    
    def get_stats(self) -> Dict:
        """Get resolver statistics"""
        with self._lock:
            return {
                **self._stats,
                'cache': self.cache.get_stats(),
                'config': {
                    'primary_servers': self.config.primary_servers,
                    'cache_ttl': self.config.cache_ttl,
                    'timeout': self.config.timeout,
                    'max_retries': self.config.max_retries
                }
            }
    
    def clear_cache(self):
        """Clear DNS cache"""
        self.cache.clear()
        self.resolve.cache_clear()
        logger.info("DNS cache cleared")
    
    @staticmethod
    def test_resolution(hostname: str = 'vercel.app') -> bool:
        """Test if DNS resolution is working"""
        try:
            resolver = ProductionDNSResolver()
            ip = resolver.resolve(hostname)
            logger.info(f"Test resolution successful: {hostname} -> {ip}")
            return True
        except Exception as e:
            logger.error(f"Test resolution failed: {e}")
            return False

# Singleton for production use
_default_resolver = None

def get_resolver() -> ProductionDNSResolver:
    """Get or create default resolver singleton"""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = ProductionDNSResolver()
    return _default_resolver