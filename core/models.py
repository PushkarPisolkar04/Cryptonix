"""
Data models for the assessment pipeline
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AssessmentScope:
    """Defines the scope of the assessment"""
    target: str
    scope_file: Optional[str] = None
    dry_run: bool = False
    stealth_mode: bool = False
    aggressive_mode: bool = False
    excluded_hosts: List[str] = field(default_factory=list)
    excluded_ports: List[int] = field(default_factory=list)
    max_threads: int = 10
    timeout: int = 300


@dataclass
class Host:
    """Represents a discovered host"""
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    status: str = "unknown"
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List['Vulnerability'] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    id: str
    name: str
    severity: Severity
    cvss_score: float
    cve_id: Optional[str] = None
    description: str = ""
    affected_service: Optional[str] = None
    affected_port: Optional[int] = None
    exploit_available: bool = False
    exploit_id: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    verified: bool = False


@dataclass
class ExploitResult:
    """Result of an exploitation attempt"""
    vulnerability_id: str
    success: bool
    exploit_used: str
    timestamp: datetime
    evidence: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    error: Optional[str] = None


@dataclass
class Credential:
    """Harvested credential"""
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    hash_type: Optional[str] = None
    source: str = ""
    privilege_level: str = "user"


@dataclass
class StageResult:
    """Result from a single stage"""
    stage_name: str
    success: bool
    start_time: datetime
    end_time: datetime
    duration: float
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    """Complete assessment result"""
    target: str
    start_time: datetime
    scope: AssessmentScope
    end_time: Optional[datetime] = None
    duration: float = 0.0
    
    # Discovered assets
    hosts: List[Host] = field(default_factory=list)
    hosts_discovered: int = 0
    
    # Vulnerabilities
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    
    # Exploitation
    exploit_results: List[ExploitResult] = field(default_factory=list)
    exploits_verified: int = 0
    
    # Post-exploitation
    credentials: List[Credential] = field(default_factory=list)
    compromised_hosts: List[str] = field(default_factory=list)
    
    # Stage results
    stage_results: Dict[str, StageResult] = field(default_factory=dict)
    
    # Reporting
    report_path: Optional[str] = None
    errors: Dict[str, str] = field(default_factory=dict)
    
    def add_stage_result(self, stage_name: str, result: StageResult):
        """Add a stage result and update summary statistics"""
        self.stage_results[stage_name] = result
        
        # Update statistics based on stage data
        if 'hosts' in result.data:
            self.hosts.extend(result.data['hosts'])
            self.hosts_discovered = len(self.hosts)
        
        if 'vulnerabilities' in result.data:
            self.vulnerabilities.extend(result.data['vulnerabilities'])
            self._update_vuln_counts()
        
        if 'exploit_results' in result.data:
            self.exploit_results.extend(result.data['exploit_results'])
            self.exploits_verified = sum(1 for e in self.exploit_results if e.success)
        
        if 'credentials' in result.data:
            self.credentials.extend(result.data['credentials'])
        
        if 'compromised_hosts' in result.data:
            self.compromised_hosts.extend(result.data['compromised_hosts'])
    
    def _update_vuln_counts(self):
        """Update vulnerability counts by severity"""
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.critical_vulns = sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
        self.high_vulns = sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
        self.medium_vulns = sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
        self.low_vulns = sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)
    
    def add_error(self, stage: str, error: str):
        """Add an error for a specific stage"""
        self.errors[stage] = error
