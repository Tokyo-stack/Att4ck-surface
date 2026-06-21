import platform
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner():
    # Use a simpler ASCII-safe banner to avoid cp1252 encoding issues on Windows
    banner_lines = [
        "    _  _____ _____   _    ____ _  __   ____  _   _ ____  _____ _    ____ _____",
        "   / \\|_   _|_   _| / \\  / ___| |/ /  / ___|| | | |  _ \\|  ___/ \\  / ___| ____|",
        "  / _ \\ | |   | |  / _ \\| |   | ' /   \\___ \\| | | | |_) | |_ / _ \\| |   |  _|",
        " / ___ \\| |   | | / ___ \\ |___| . \\    ___) | |_| |  _ <|  _/ ___ \\ |___| |___",
        "/_/   \\_\\_|   |_|/_/   \\_\\____|_|\\_\\  |____/ \\___/|_| \\_\\_|/_/   \\_\\____|_____|",
    ]

    banner_art = Text()
    for line in banner_lines:
        banner_art.append(line + "\n", style="bold red")

    console.print(banner_art)

    info_text = (
        "[bold white]ATT&CK SURFACE v1.0.0[/bold white]\n"
        "[white]Attack Surface Mapping & Security Review Framework[/white]\n"
        "\n"
        "[bold white]Features:[/bold white]\n"
        " [cyan]*[/cyan] Endpoint Discovery      [cyan]*[/cyan] Secret Detection      [cyan]*[/cyan] File Upload Analysis\n"
        " [cyan]*[/cyan] API Enumeration         [cyan]*[/cyan] Security Misconfig    [cyan]*[/cyan] Parameter Mapping\n"
        " [cyan]*[/cyan] Source Code Review      [cyan]*[/cyan] Risk Classification   [cyan]*[/cyan] Attack Surface Coverage\n"
        "\n"
        " [bold white]Developer :[/bold white] Tokyo\n"
        " [bold white]GitHub    :[/bold white] github.com/Tokyo-stack/Att4ck-surface"
    )

    console.print(Panel(info_text, border_style="white"))
    console.print()


def print_startup():
    console.print("[blue][INFO][/blue] Initializing modules...")
    console.print("[blue][INFO][/blue] Loading attack surface inventory...")
    console.print("[blue][INFO][/blue] Loading detection engine...")
    console.print("[blue][INFO][/blue] Loading security rulesets...")
    console.print("[blue][INFO][/blue] Initializing reporting engine...")
    console.print("[green][SUCCESS][/green] ATT&CK Surface initialized.\n")


def print_environment():
    console.print(f"[cyan]{'-' * 90}[/cyan]")
    console.print(f"[white]Framework :[/white] ATT&CK Surface")
    console.print(f"[white]Version   :[/white] 1.0.0")
    console.print(f"[white]Python    :[/white] {platform.python_version()}")
    console.print(f"[white]Platform  :[/white] {platform.system()} {platform.release()}")
    console.print(f"[white]Timestamp :[/white] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"[cyan]{'-' * 90}[/cyan]\n")


if __name__ == "__main__":
    print_banner()
    print_startup()
    print_environment()