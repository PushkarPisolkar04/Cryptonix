"""
Configuration management
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ToolConfig:
    """Configuration for external tools"""
    nmap_path: str = "nmap"
    metasploit_host: str = "127.0.0.1"
    metasploit_port: int = 55553
    metasploit_password: Optional[str] = None
    zap_api_key: Optional[str] = None
    zap_host: str = "127.0.0.1"
    zap_port: int = 8080
    nessus_url: Optional[str] = None
    nessus_access_key: Optional[str] = None
    nessus_secret_key: Optional[str] = None


@dataclass
class APIConfig:
    """Configuration for external APIs"""
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    haveibeenpwned_api_key: Optional[str] = None


@dataclass
class Config:
    """Main configuration"""
    tools: ToolConfig
    apis: APIConfig
    database_url: str = "sqlite:///autopent.db"
    redis_url: str = "redis://localhost:6379/0"
    max_concurrent_scans: int = 5
    default_timeout: int = 300
    enable_ml: bool = False
    
    @classmethod
    def load(cls, config_path: str) -> 'Config':
        """Load configuration from YAML file"""
        path = Path(config_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Parse tool config
        tools = ToolConfig(**data.get('tools', {}))
        
        # Parse API config
        apis = APIConfig(**data.get('apis', {}))
        
        # Create main config
        return cls(
            tools=tools,
            apis=apis,
            database_url=data.get('database_url', 'sqlite:///autopent.db'),
            redis_url=data.get('redis_url', 'redis://localhost:6379/0'),
            max_concurrent_scans=data.get('max_concurrent_scans', 5),
            default_timeout=data.get('default_timeout', 300),
            enable_ml=data.get('enable_ml', False)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'tools': self.tools.__dict__,
            'apis': self.apis.__dict__,
            'database_url': self.database_url,
            'redis_url': self.redis_url,
            'max_concurrent_scans': self.max_concurrent_scans,
            'default_timeout': self.default_timeout,
            'enable_ml': self.enable_ml
        }
