import os
import platform
from datetime import datetime

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    banner = f"""{RED}
 █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗    ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
███████║   ██║      ██║   ███████║██║     █████╔╝     ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗     ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗    ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝

{WHITE}
╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                   ATT&CK SURFACE v1.0.0                                            ║
║                      Attack Surface Mapping & Security Review Framework                            ║
║                                                                                                    ║
║  Features:                                                                                         ║
║   • Endpoint Discovery      • Secret Detection      • File Upload Analysis                         ║
║   • API Enumeration         • Security Misconfig    • Parameter Mapping                            ║
║   • Source Code Review      • Risk Classification   • Attack Surface Coverage                      ║
║                                                                                                    ║
║  Developer : Tokyo                                                                                 ║
║  GitHub    : github.com/Tokyo-stack/Att4ck-surface                                                ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
{RESET}
"""
    print(banner)


def print_startup():
    print(f"{BLUE}[INFO]{RESET} Initializing modules...")
    print(f"{BLUE}[INFO]{RESET} Loading attack surface inventory...")
    print(f"{BLUE}[INFO]{RESET} Loading detection engine...")
    print(f"{BLUE}[INFO]{RESET} Loading security rulesets...")
    print(f"{BLUE}[INFO]{RESET} Initializing reporting engine...")
    print(f"{GREEN}[SUCCESS]{RESET} ATT&CK Surface initialized.\n")


def print_environment():
    print(f"{CYAN}{'─' * 90}{RESET}")
    print(f"{WHITE}Framework :{RESET} ATT&CK Surface")
    print(f"{WHITE}Version   :{RESET} 1.0.0")
    print(f"{WHITE}Python    :{RESET} {platform.python_version()}")
    print(f"{WHITE}Platform  :{RESET} {platform.system()} {platform.release()}")
    print(f"{WHITE}Timestamp :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{CYAN}{'─' * 90}{RESET}\n")


if __name__ == "__main__":
    # Enable ANSI support on Windows
    if os.name == "nt":
        os.system("")

    print_banner()
    print_startup()
    print_environment()