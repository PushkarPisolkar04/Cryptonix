"""
Enhanced Discovery & Enumeration Module
Stage 2: Active scanning with cloud, CDN, WAF, and SSL analysis
"""

import asyncio
import json
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess
import re

from loguru import logger


@dataclass
class ServiceInfo:
    """Service discovery information"""
    host: str
    port: int
    protocol: str
    version: Optional[str]
    fingerprint: Optional[str]


@dataclass
class DiscoveryResult:
    """Container for discovery findings"""
    timestamp: str
    target: str
    live_hosts: List[str]
    open_ports: List[Dict]
    services: List[ServiceInfo]
    cloud_assets: List[Dict]
    cdn_detected: List[Dict]
    waf_detected: List[Dict]
    ssl_issues: List[Dict]
    api_endpoints: List[Dict]

    def to_dict(self):
        """Convert to dictionary"""
        result = asdict(self)
        result['services'] = [asdict(s) if isinstance(s, ServiceInfo) else s for s in result['services']]
        return result


class EnhancedDiscoveryRunner:
    """Enhanced discovery orchestrator"""

    def __init__(self, config: Dict):
        self.config = config
        self.target = None

    async def discover(self, target: str, aggressive: bool = False) -> DiscoveryResult:
        """Orchestrate all discovery tasks"""
        logger.info(f"Starting enhanced discovery for {target}")
        self.target = target

        result = DiscoveryResult(
            timestamp=datetime.now().isoformat(),
            target=target,
            live_hosts=[],
            open_ports=[],
            services=[],
            cloud_assets=[],
            cdn_detected=[],
            waf_detected=[],
            ssl_issues=[],
            api_endpoints=[]
        )

        # Run discovery tasks in parallel
        tasks = [
            self._network_scanning(target, aggressive),
            self._cloud_asset_discovery(target),
            self._cdn_detection(target),
            self._waf_detection(target),
            self._ssl_analysis(target),
            self._api_endpoint_discovery(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Discovery task {idx} failed: {res}")
                continue

            if idx == 0:  # Network scanning
                result.live_hosts, result.open_ports, result.services = res
            elif idx == 1:  # Cloud assets
                result.cloud_assets = res
            elif idx == 2:  # CDN
                result.cdn_detected = res
            elif idx == 3:  # WAF
                result.waf_detected = res
            elif idx == 4:  # SSL
                result.ssl_issues = res
            elif idx == 5:  # API endpoints
                result.api_endpoints = res

        logger.success(f"Discovery complete. Found {len(result.live_hosts)} hosts, {len(result.open_ports)} open ports")
        return result

    async def _network_scanning(self, target: str, aggressive: bool) -> tuple:
        """Perform network scanning with Nmap"""
        logger.info(f"Scanning network: {target}")
        try:
            import nmap
            nm = nmap.PortScanner()
            
            # Choose scanning profile
            if aggressive:
                args = "-sV -sC -O -A -T4"  # Aggressive
            else:
                args = "-sV -sC -T3"  # Standard

            nm.scan(target, arguments=args)

            live_hosts = []
            open_ports = []
            services = []

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    live_hosts.append(host)
                    
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if state == 'open':
                                service_info = {
                                    'host': host,
                                    'port': port,
                                    'protocol': nm[host][proto][port].get('name', 'unknown'),
                                    'version': nm[host][proto][port].get('version', 'unknown'),
                                    'product': nm[host][proto][port].get('product', 'unknown')
                                }
                                open_ports.append(service_info)
                                
                                services.append(ServiceInfo(
                                    host=host,
                                    port=port,
                                    protocol=nm[host][proto][port].get('name', 'unknown'),
                                    version=nm[host][proto][port].get('version'),
                                    fingerprint=nm[host][proto][port].get('extrainfo')
                                ))

            logger.success(f"Found {len(live_hosts)} live hosts and {len(open_ports)} open ports")
            return live_hosts, open_ports, services

        except Exception as e:
            logger.error(f"Network scanning failed: {e}")
            return [], [], []

    async def _cloud_asset_discovery(self, target: str) -> List[Dict]:
        """Discover cloud assets (S3, Azure Blobs, GCS)"""
        logger.info(f"Discovering cloud assets for {target}")
        assets = []

        # AWS S3 bucket discovery
        assets.extend(await self._discover_s3_buckets(target))
        
        # Azure blob discovery
        assets.extend(await self._discover_azure_blobs(target))
        
        # Google Cloud Storage discovery
        assets.extend(await self._discover_gcs_buckets(target))

        logger.success(f"Found {len(assets)} cloud assets")
        return assets

    async def _discover_s3_buckets(self, target: str) -> List[Dict]:
        """Discover AWS S3 buckets"""
        buckets = []
        try:
            domain_parts = target.split('.')
            base_name = domain_parts[0]

            bucket_names = [
                base_name,
                f"{base_name}-backup",
                f"{base_name}-prod",
                f"{base_name}-dev",
                f"{base_name}-staging",
                f"{base_name}-data",
                f"{base_name}-assets",
                f"{base_name}-logs",
            ]

            import boto3
            s3 = boto3.client('s3', region_name='us-east-1')

            for bucket_name in bucket_names:
                try:
                    s3.head_bucket(Bucket=bucket_name)
                    # Check if publicly accessible
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket_name)
                        public = any(g.get('Grantee', {}).get('Type') == 'Group' 
                                   for g in acl.get('Grants', []))
                    except:
                        public = False

                    buckets.append({
                        'type': 'AWS S3',
                        'bucket': bucket_name,
                        'public': public,
                        'url': f"https://{bucket_name}.s3.amazonaws.com"
                    })
                    logger.warning(f"Found S3 bucket: {bucket_name} (public: {public})")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"S3 bucket discovery failed: {e}")

        return buckets

    async def _discover_azure_blobs(self, target: str) -> List[Dict]:
        """Discover Azure Blob Storage"""
        blobs = []
        try:
            domain_parts = target.split('.')
            base_name = domain_parts[0]

            blob_names = [
                base_name,
                f"{base_name}backup",
                f"{base_name}prod",
                f"{base_name}dev",
                f"{base_name}staging",
            ]

            for blob_name in blob_names:
                url = f"https://{blob_name}.blob.core.windows.net"
                try:
                    import requests
                    response = requests.head(url, timeout=5)
                    if response.status_code != 404:
                        blobs.append({
                            'type': 'Azure Blob',
                            'account': blob_name,
                            'url': url
                        })
                        logger.warning(f"Found Azure Blob: {blob_name}")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Azure blob discovery failed: {e}")

        return blobs

    async def _discover_gcs_buckets(self, target: str) -> List[Dict]:
        """Discover Google Cloud Storage buckets"""
        buckets = []
        try:
            domain_parts = target.split('.')
            base_name = domain_parts[0]

            bucket_names = [
                base_name,
                f"{base_name}-backup",
                f"{base_name}-prod",
                f"{base_name}-dev",
            ]

            for bucket_name in bucket_names:
                url = f"https://storage.googleapis.com/{bucket_name}"
                try:
                    import requests
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200 and 'NotFound' not in response.text:
                        buckets.append({
                            'type': 'Google Cloud Storage',
                            'bucket': bucket_name,
                            'url': url
                        })
                        logger.warning(f"Found GCS bucket: {bucket_name}")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"GCS bucket discovery failed: {e}")

        return buckets

    async def _cdn_detection(self, target: str) -> List[Dict]:
        """Detect CDN providers"""
        logger.info(f"Detecting CDN for {target}")
        cdn_info = []

        try:
            # DNS lookup
            ips = await self._resolve_dns(target)
            
            cdn_signatures = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'Akamai': ['akamai', 'akam'],
                'Fastly': ['fastly'],
                'CloudFront': ['cloudfront', 'amazonaws'],
                'KeyCDN': ['keycdn'],
                'Imperva': ['imperva', 'incapsula'],
            }

            import requests
            try:
                response = requests.head(f"http://{target}", timeout=5, allow_redirects=True)
                headers = response.headers
                
                for cdn_name, signatures in cdn_signatures.items():
                    for sig in signatures:
                        if any(sig.lower() in str(v).lower() for v in headers.values()):
                            cdn_info.append({
                                'cdn': cdn_name,
                                'detected': True,
                                'evidence': str(headers)[:200]
                            })
                            logger.warning(f"Detected CDN: {cdn_name}")
                            break

            except Exception as e:
                logger.debug(f"CDN detection failed: {e}")

        except Exception as e:
            logger.error(f"CDN detection error: {e}")

        return cdn_info

    async def _waf_detection(self, target: str) -> List[Dict]:
        """Detect Web Application Firewall (WAF)"""
        logger.info(f"Detecting WAF for {target}")
        waf_info = []

        try:
            # Use wafw00f if available
            try:
                result = subprocess.run(
                    ['wafw00f', target, '-o', 'json'],
                    capture_output=True,
                    timeout=30,
                    text=True
                )
                if result.returncode == 0:
                    output = json.loads(result.stdout)
                    if output.get('WAF'):
                        waf_info.append({
                            'waf': output['WAF'],
                            'detected': True,
                            'confidence': 'high'
                        })
                        logger.warning(f"Detected WAF: {output['WAF']}")
            except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
                pass

            # Manual HTTP response analysis
            import requests
            try:
                response = requests.get(f"http://{target}", timeout=5)
                headers = response.headers
                
                waf_signatures = {
                    'Cloudflare': ['cf-ray', 'cf-request-id'],
                    'AWS WAF': ['x-amzn-waf-action'],
                    'Akamai': ['x-akamai-transformed'],
                    'ModSecurity': ['server', 'modsecurity'],
                }

                for waf_name, signatures in waf_signatures.items():
                    for sig in signatures:
                        if any(sig.lower() in k.lower() or sig.lower() in str(v).lower() 
                              for k, v in headers.items()):
                            waf_info.append({
                                'waf': waf_name,
                                'detected': True,
                                'confidence': 'medium'
                            })
                            logger.warning(f"Detected WAF: {waf_name}")
                            break

            except Exception as e:
                logger.debug(f"WAF HTTP analysis failed: {e}")

        except Exception as e:
            logger.error(f"WAF detection error: {e}")

        return waf_info

    async def _ssl_analysis(self, target: str) -> List[Dict]:
        """Analyze SSL/TLS configuration"""
        logger.info(f"Analyzing SSL/TLS for {target}")
        ssl_issues = []

        try:
            import socket
            import ssl
            
            try:
                hostname = target
                port = 443

                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        version = ssock.version()
                        cipher = ssock.cipher()

                        # Check for weak SSL/TLS versions
                        if version in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                            ssl_issues.append({
                                'issue': 'Weak TLS version',
                                'version': version,
                                'severity': 'high'
                            })
                            logger.warning(f"Weak TLS version detected: {version}")

                        # Check certificate expiration
                        import datetime
                        not_after = datetime.datetime.strptime(
                            cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                        if (not_after - datetime.datetime.now()).days < 30:
                            ssl_issues.append({
                                'issue': 'Certificate expiring soon',
                                'days_left': (not_after - datetime.datetime.now()).days,
                                'severity': 'medium'
                            })
                            logger.warning(f"Certificate expires in {(not_after - datetime.datetime.now()).days} days")

                        # Check cipher strength
                        if cipher[1] < 128:
                            ssl_issues.append({
                                'issue': 'Weak cipher',
                                'cipher': cipher[0],
                                'bits': cipher[1],
                                'severity': 'high'
                            })
                            logger.warning(f"Weak cipher detected: {cipher[0]} ({cipher[1]} bits)")

            except Exception as e:
                logger.debug(f"SSL analysis failed: {e}")

        except Exception as e:
            logger.error(f"SSL analysis error: {e}")

        return ssl_issues

    async def _api_endpoint_discovery(self, target: str) -> List[Dict]:
        """Discover hidden API endpoints"""
        logger.info(f"Discovering API endpoints for {target}")
        endpoints = []

        try:
            import requests
            
            # Common API paths
            api_paths = [
                '/api/',
                '/api/v1/',
                '/api/v2/',
                '/graphql',
                '/graphql/api',
                '/rest/api/',
                '/swagger/',
                '/swagger-ui/',
                '/api-docs/',
                '/.well-known/openapi.json',
                '/.well-known/swagger.json',
                '/openapi.json',
                '/openapi.yaml',
                '/api/openapi.json',
            ]

            base_url = f"http://{target}" if not target.startswith('http') else target

            for path in api_paths:
                try:
                    response = requests.get(f"{base_url}{path}", timeout=5)
                    if response.status_code == 200:
                        endpoints.append({
                            'path': path,
                            'status': 200,
                            'content_type': response.headers.get('content-type'),
                            'found': True
                        })
                        logger.success(f"Found API endpoint: {path}")
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"API endpoint discovery error: {e}")

        return endpoints

    async def _resolve_dns(self, target: str) -> List[str]:
        """Resolve DNS name to IPs"""
        try:
            ips = socket.gethostbyname_ex(target)
            return ips[2]
        except Exception:
            return []

    def save_results(self, result: DiscoveryResult, output_path: str):
        """Save discovery results"""
        output_file = Path(output_path) / f"discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

        logger.success(f"Discovery results saved to {output_file}")
        return output_file
