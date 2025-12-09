"""Display banner"""

from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     {Fore.RED}█████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗███╗   ██╗{Fore.CYAN}║
║    {Fore.RED}██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║{Fore.CYAN}║
║    {Fore.RED}███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██╔██╗ ██║{Fore.CYAN}║
║    {Fore.RED}██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║{Fore.CYAN}║
║    {Fore.RED}██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ███████╗██║ ╚████║{Fore.CYAN}║
║    {Fore.RED}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝{Fore.CYAN}║
║                                                               ║
║          {Fore.YELLOW}Automated Penetration Testing Orchestrator{Fore.CYAN}           ║
║                      {Fore.GREEN}v1.0.0 - Full Pipeline{Fore.CYAN}                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  WARNING: For authorized security testing only!{Style.RESET_ALL}
"""
    print(banner)
