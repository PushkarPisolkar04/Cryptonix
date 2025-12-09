"""
Automatic tool detection for Windows and Linux
Finds installed security tools regardless of OS
"""

import os
import platform
import shutil
from pathlib import Path
from typing import Optional, Dict
from loguru import logger


class ToolDetector:
    """Detect and locate security tools on any OS"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == 'windows'
        self.is_linux = self.os_type == 'linux'
        self.is_kali = self._is_kali_linux()
        
        logger.info(f"OS detected: {self.os_type}")
        if self.is_kali:
            logger.info("Kali Linux detected - enhanced tools available")
    
    def _is_kali_linux(self) -> bool:
        """Check if running on Kali Linux"""
        if not self.is_linux:
            return False
        
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
        except:
            return False
    
    def find_tool(self, tool_name: str) -> Optional[str]:
        """Find a tool's path on any OS"""
        
        # Common tool locations by OS
        search_paths = {
            'nmap': {
                'windows': [
                    'nmap',
                    r'C:\Program Files (x86)\Nmap\nmap.exe',
                    r'C:\Program Files\Nmap\nmap.exe',
                ],
                'linux': [
                    '/usr/bin/nmap',
                    '/usr/local/bin/nmap',
                    'nmap'
                ]
            },
            'sqlmap': {
                'windows': [
                    'sqlmap',
                    'sqlmap.py',
                    r'C:\sqlmap\sqlmap.py',
                ],
                'linux': [
                    '/usr/bin/sqlmap',
                    '/usr/local/bin/sqlmap',
                    '/usr/share/sqlmap/sqlmap.py',
                    'sqlmap'
                ]
            },
            'nikto': {
                'windows': [
                    'nikto',
                    'nikto.pl',
                ],
                'linux': [
                    '/usr/bin/nikto',
                    '/usr/local/bin/nikto',
                    '/usr/share/nikto/nikto.pl',
                    'nikto'
                ]
            },
            'msfconsole': {
                'windows': [
                    'msfconsole',
                    r'C:\metasploit-framework\bin\msfconsole.bat',
                ],
                'linux': [
                    '/usr/bin/msfconsole',
                    '/opt/metasploit-framework/bin/msfconsole',
                    'msfconsole'
                ]
            },
            'zap': {
                'windows': [
                    r'C:\Program Files\OWASP\Zed Attack Proxy\zap.bat',
                    r'C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat',
                ],
                'linux': [
                    '/usr/bin/zaproxy',
                    '/usr/share/zaproxy/zap.sh',
                    'zaproxy'
                ]
            }
        }
        
        # Get paths for this tool and OS
        os_key = 'windows' if self.is_windows else 'linux'
        paths = search_paths.get(tool_name, {}).get(os_key, [tool_name])
        
        # Try each path
        for path in paths:
            # Check if it's an absolute path that exists
            if os.path.isabs(path) and os.path.exists(path):
                logger.debug(f"Found {tool_name} at: {path}")
                return path
            
            # Try using shutil.which (checks PATH)
            found = shutil.which(path)
            if found:
                logger.debug(f"Found {tool_name} in PATH: {found}")
                return found
        
        logger.warning(f"{tool_name} not found on system")
        return None
    
    def detect_all_tools(self) -> Dict[str, Optional[str]]:
        """Detect all security tools"""
        tools = ['nmap', 'sqlmap', 'nikto', 'msfconsole', 'zap']
        
        results = {}
        for tool in tools:
            results[tool] = self.find_tool(tool)
        
        # Log summary
        found = sum(1 for v in results.values() if v)
        logger.info(f"Tools detected: {found}/{len(tools)}")
        
        for tool, path in results.items():
            if path:
                logger.success(f"✅ {tool}: {path}")
            else:
                logger.warning(f"❌ {tool}: not found")
        
        return results
    
    def get_install_instructions(self, tool_name: str) -> str:
        """Get installation instructions for a tool"""
        
        instructions = {
            'nmap': {
                'windows': 'Download from https://nmap.org/download.html or run: choco install nmap',
                'linux': 'sudo apt install nmap  # Debian/Ubuntu\nsudo yum install nmap  # RedHat/CentOS',
                'kali': 'Already installed on Kali Linux'
            },
            'sqlmap': {
                'windows': 'Download from https://sqlmap.org/ or run: pip install sqlmap-python',
                'linux': 'sudo apt install sqlmap  # Debian/Ubuntu',
                'kali': 'Already installed on Kali Linux'
            },
            'nikto': {
                'windows': 'Download from https://github.com/sullo/nikto',
                'linux': 'sudo apt install nikto  # Debian/Ubuntu',
                'kali': 'Already installed on Kali Linux'
            },
            'msfconsole': {
                'windows': 'Download from https://www.metasploit.com/',
                'linux': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall',
                'kali': 'Already installed on Kali Linux'
            },
            'zap': {
                'windows': 'Download from https://www.zaproxy.org/download/',
                'linux': 'sudo apt install zaproxy  # Debian/Ubuntu',
                'kali': 'Already installed on Kali Linux'
            }
        }
        
        if self.is_kali:
            return instructions.get(tool_name, {}).get('kali', 'Tool not found')
        elif self.is_windows:
            return instructions.get(tool_name, {}).get('windows', 'Tool not found')
        else:
            return instructions.get(tool_name, {}).get('linux', 'Tool not found')
    
    def check_python_version(self) -> bool:
        """Check if Python version is compatible"""
        import sys
        version = sys.version_info
        
        if version.major >= 3 and version.minor >= 8:
            logger.success(f"✅ Python {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            logger.error(f"❌ Python {version.major}.{version.minor} - Need Python 3.8+")
            return False
    
    def check_dependencies(self) -> Dict[str, bool]:
        """Check all dependencies"""
        results = {
            'python_version': self.check_python_version(),
            'tools': {}
        }
        
        # Check tools
        tool_paths = self.detect_all_tools()
        for tool, path in tool_paths.items():
            results['tools'][tool] = path is not None
        
        return results
