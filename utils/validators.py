"""Input validation utilities"""

import re
from urllib.parse import urlparse
from typing import Optional
import socket

def validate_target(target: str) -> bool:
    """Validate target URL or IP address"""
    if not target:
        return False
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        return validate_url(target)
    
    # Check if it's an IP address
    if validate_ip(target):
        return True
    
    # Check if it's a domain
    if validate_domain(target):
        return True
    
    return False

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def validate_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address"""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return None

def extract_base_url(url: str) -> str:
    """Extract base URL (scheme + netloc)"""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return url
