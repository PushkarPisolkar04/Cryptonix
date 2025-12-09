"""Display banner"""

import sys
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    """Print banner with proper encoding handling"""
    
    # Simple ASCII banner for Windows compatibility
    banner = f"""
{Fore.CYAN}================================================================
                                                               
     {Fore.RED}CRYPTONIX - Automated Penetration Testing{Fore.CYAN}
                                                               
     {Fore.YELLOW}Automated Penetration Testing Orchestrator{Fore.CYAN}
     {Fore.GREEN}v1.0.0 - Full Pipeline{Fore.CYAN}
                                                               
================================================================{Style.RESET_ALL}

{Fore.YELLOW}WARNING: For authorized security testing only!{Style.RESET_ALL}
"""
    
    try:
        print(banner)
    except UnicodeEncodeError:
        # Fallback to plain ASCII if Unicode fails
        print("\n" + "="*60)
        print("CRYPTONIX - Automated Penetration Testing")
        print("v1.0.0 - Full Pipeline")
        print("="*60)
        print("\nWARNING: For authorized security testing only!\n")
