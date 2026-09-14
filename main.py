#!/usr/bin/env python3
"""ATT4ck Surface - command line entry point.

Also importable as ``python -m attack_surface`` (see ``attack_surface/__main__``).
"""

from __future__ import annotations

import sys

from attack_surface.cli import main

if __name__ == "__main__":
    sys.exit(main())
