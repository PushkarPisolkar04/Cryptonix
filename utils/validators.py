"""Input validation utilities"""

import re
import ipaddress
from pathlib import Path
from typing import Union


def validate_target(target: str) -> bool:
    """Validate target IP, domain, or CIDR"""
    # Check if it's a valid IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid domain
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True
    
    return False


def validate_scope(scope_file: str) -> bool:
    """Validate scope configuration file"""
    path = Path(scope_file)
    
    if not path.exists():
        return False
    
    if path.suffix not in ['.yaml', '.yml', '.json']:
        return False
    
    return True


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
