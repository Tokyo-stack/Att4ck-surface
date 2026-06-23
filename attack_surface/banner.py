import platform
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()


def print_banner():
    """
    Print the ATT4ck Surface banner with enhanced styling
    """
    # Clean ASCII banner - properly formatted
    banner_lines = [
        "",
        "    █████╗ ████████╗████████╗██╗  ██╗ ██████╗██╗  ██╗     ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗",
        "   ██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║ ██╔╝     ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝",
        "   ███████║   ██║      ██║   ███████║██║     █████╔╝      ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗  ",
        "   ██╔══██║   ██║      ██║   ╚════██║██║     ██╔═██╗      ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝  ",
        "   ██║  ██║   ██║      ██║        ██║╚██████╗██║  ██╗     ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗",
        "   ╚═╝  ╚═╝   ╚═╝      ╚═╝        ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝",
        "",
    ]

    # Print banner with gradient effect
    colors = ['bold red', 'bright_red', 'red', 'bold red', 'bright_red', 'red']
    
    for i, line in enumerate(banner_lines):
        if line.strip():
            color = colors[i % len(colors)]
            console.print(Align.center(Text(line, style=color)))
    
    # Title Box - Bold and Enhanced
    title_box = Panel(
        Text(" ATT4ck Surface v1.0.0 ", style="bold white on red") + 
        Text("\n") +
        Text(" Attack Surface Mapping & Security Review Framework ", style="bold white") +
        Text("\n\n") +
        Text(" Features:", style="bold cyan") +
        Text("\n") +
        Text("  • ", style="bold green") + Text("Endpoint Discovery", style="white") + 
        Text("      ", style="dim") +
        Text("• ", style="bold green") + Text("Secret Detection", style="white") + 
        Text("      ", style="dim") +
        Text("• ", style="bold green") + Text("File Upload Analysis", style="white") +
        Text("\n  • ", style="bold green") + Text("API Enumeration", style="white") + 
        Text("         ", style="dim") +
        Text("• ", style="bold green") + Text("Security Misconfig", style="white") + 
        Text("    ", style="dim") +
        Text("• ", style="bold green") + Text("Parameter Mapping", style="white") +
        Text("\n  • ", style="bold green") + Text("Source Code Review", style="white") + 
        Text("      ", style="dim") +
        Text("• ", style="bold green") + Text("Risk Classification", style="white") + 
        Text("   ", style="dim") +
        Text("• ", style="bold green") + Text("Attack Surface Coverage", style="white") +
        Text("\n\n") +
        Text(" Developer : ", style="bold yellow") + Text("Tokyo", style="bright_white") +
        Text("\n") +
        Text(" GitHub    : ", style="bold yellow") + Text("github.com/Tokyo-stack/Att4ck-surface", style="bright_white"),
        border_style="bright_red",
        width=80,
        title="🔥 ATT4CK SURFACE 🔥",
        title_align="center",
        padding=(1, 2)
    )
    
    console.print(Align.center(title_box))
    console.print()


def print_startup():
    """Print startup messages with enhanced styling"""
    console.print()
    
    # Create a status panel
    status_lines = [
        Text("🔧 Initializing modules...", style="bold cyan"),
        Text("📦 Loading attack surface inventory...", style="bold cyan"),
        Text("⚡ Loading detection engine...", style="bold cyan"),
        Text("🛡️  Loading security rulesets...", style="bold cyan"),
        Text("📊 Initializing reporting engine...", style="bold cyan"),
        Text("✅ ATT&CK Surface initialized.", style="bold green"),
    ]
    
    for line in status_lines:
        console.print(f"  {line}")
    
    console.print()


def print_environment():
    """Print environment information with enhanced styling"""
    console.print()
    
    # Create a styled environment box
    env_lines = [
        ("Framework", "ATT&CK Surface v1.0.0", "bold cyan"),
        ("Version", "1.0.0", "bold white"),
        ("Python", platform.python_version(), "bold yellow"),
        ("Platform", f"{platform.system()} {platform.release()}", "bold green"),
        ("Timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "bold blue"),
    ]
    
    # Print separator
    console.print(Text("═" * 90, style="bright_black"))
    
    # Print each line with proper alignment
    for label, value, style in env_lines:
        console.print(
            Text(f"{label:>12} ", style="bold white") + 
            Text(":", style="bright_black") + 
            Text(f" {value}", style=style)
        )
    
    console.print(Text("═" * 90, style="bright_black"))
    console.print()


def print_footer():
    """Print a footer for the scanner"""
    console.print()
    console.print(Align.center(Text("⚡ Made with ❤️ by Tokyo ⚡", style="bold red")))
    console.print(Align.center(Text("Stay Secure, Stay Vigilant!", style="bold white")))


if __name__ == "__main__":
    print_banner()
    print_startup()
    print_environment()
    print_footer()