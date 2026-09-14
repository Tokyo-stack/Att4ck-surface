"""Terminal banner, project info box and environment summary.

The ASCII logo is the canonical project artwork and must not be altered.
"""

from __future__ import annotations

import platform
from datetime import datetime

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from attack_surface.version import __version__

console = Console()

LOGO_LINES: tuple[str, ...] = (
    " █████╗ ████████╗████████╗██╗  ██╗ ██████╗██╗  ██╗     ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗",
    "██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║ ██╔╝     ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝",
    "███████║   ██║      ██║   ███████║██║     █████╔╝      ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗  ",
    "██╔══██║   ██║      ██║   ╚════██║██║     ██╔═██╗      ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝  ",
    "██║  ██║   ██║      ██║        ██║╚██████╗██║  ██╗     ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗",
    "╚═╝  ╚═╝   ╚═╝      ╚═╝        ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝",
)

_LOGO_COLOURS = ("bold red", "bright_red", "red", "bold red", "bright_red", "red")

PROJECT_NAME = "ATT4ck Surface"
PROJECT_TAGLINE = "Attack Surface Mapping & Security Review Framework"
DEVELOPER = "Tokyo"
GITHUB_URL = "github.com/Tokyo-stack/Att4ck-surface"

FEATURE_ROWS: tuple[tuple[str, str, str], ...] = (
    ("Endpoint Discovery", "Secret Detection", "File Upload Analysis"),
    ("API Enumeration", "Security Misconfig", "Parameter Mapping"),
    ("Source Code Review", "Risk Classification", "Attack Surface Coverage"),
)


def _feature_lines() -> Text:
    """Render the three feature rows with aligned bullet columns."""
    text = Text()
    for row in FEATURE_ROWS:
        text.append("\n  ")
        for idx, feature in enumerate(row):
            text.append("• ", style="bold green")
            text.append(f"{feature:<24}", style="white")
            if idx < len(row) - 1:
                text.append(" ")
    return text


def print_banner(target_console: Console | None = None) -> None:
    """Print the ATT4ck Surface logo and the project information box."""
    out = target_console or console
    out.print()
    for idx, line in enumerate(LOGO_LINES):
        out.print(Align.center(Text(line, style=_LOGO_COLOURS[idx % len(_LOGO_COLOURS)])))
    out.print()

    body = Text()
    body.append(f" {PROJECT_NAME} v{__version__} ", style="bold white on red")
    body.append("\n")
    body.append(f" {PROJECT_TAGLINE} ", style="bold white")
    body.append("\n\n")
    body.append(" Features:", style="bold cyan")
    body.append_text(_feature_lines())
    body.append("\n\n")
    body.append(" Developer : ", style="bold yellow")
    body.append(DEVELOPER, style="bright_white")
    body.append("\n")
    body.append(" GitHub    : ", style="bold yellow")
    body.append(GITHUB_URL, style="bright_white")

    panel = Panel(
        body,
        border_style="bright_red",
        width=100,
        title="🔥 ATT4CK SURFACE 🔥",
        title_align="center",
        padding=(1, 2),
    )
    out.print(Align.center(panel))
    out.print()


def print_startup(target_console: Console | None = None) -> None:
    """Print the module initialisation sequence."""
    out = target_console or console
    steps = (
        ("🔧", "Initializing modules..."),
        ("📦", "Loading attack surface inventory..."),
        ("⚡", "Loading detection engine..."),
        ("🛡️ ", "Loading security rulesets..."),
        ("📊", "Initializing reporting engine..."),
    )
    out.print()
    for icon, message in steps:
        out.print(Text(f"  {icon} {message}", style="bold cyan"))
    out.print(Text("  ✅ ATT&CK Surface initialized.", style="bold green"))
    out.print()


def print_environment(target_console: Console | None = None) -> None:
    """Print framework / interpreter / platform information."""
    out = target_console or console
    rows = (
        ("Framework", f"{PROJECT_NAME} v{__version__}", "bold cyan"),
        ("Version", __version__, "bold white"),
        ("Python", platform.python_version(), "bold yellow"),
        ("Platform", f"{platform.system()} {platform.release()}", "bold green"),
        ("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "bold blue"),
    )
    out.print()
    out.print(Text("═" * 90, style="bright_black"))
    for label, value, style in rows:
        line = Text(f"{label:>12} ", style="bold white")
        line.append(":", style="bright_black")
        line.append(f" {value}", style=style)
        out.print(line)
    out.print(Text("═" * 90, style="bright_black"))
    out.print()


def print_footer(target_console: Console | None = None) -> None:
    """Print the closing footer."""
    out = target_console or console
    out.print()
    out.print(Align.center(Text("⚡ Made with ❤️  by Tokyo ⚡", style="bold red")))
    out.print(Align.center(Text("Stay Secure, Stay Vigilant!", style="bold white")))


def plain_banner() -> str:
    """Return the logo and info box as plain text (README / --no-color output)."""
    width = 100
    inner = width - 2
    lines = list(LOGO_LINES)
    lines.append("")
    lines.append("╔" + "═" * inner + "╗")
    lines.append("║" + f"{PROJECT_NAME} v{__version__}".center(inner) + "║")
    lines.append("║" + PROJECT_TAGLINE.center(inner) + "║")
    lines.append("║" + " " * inner + "║")
    lines.append("║" + "  Features:".ljust(inner) + "║")
    for row in FEATURE_ROWS:
        content = "   " + "".join(f"• {feature:<24} " for feature in row)
        lines.append("║" + content.ljust(inner) + "║")
    lines.append("║" + " " * inner + "║")
    lines.append("║" + f"  Developer : {DEVELOPER}".ljust(inner) + "║")
    lines.append("║" + f"  GitHub    : {GITHUB_URL}".ljust(inner) + "║")
    lines.append("╚" + "═" * inner + "╝")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - manual preview
    print_banner()
    print_startup()
    print_environment()
    print_footer()
