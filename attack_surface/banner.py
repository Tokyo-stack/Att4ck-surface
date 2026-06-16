def print_banner():
        lines = [
        r"  ___  _____ _____ _   _ _____ _   _   _____ _   _ ______  ___  _____ _____ ",
        r" / _ \/__   _/__   | | / /  ___| | | | /  ___| | | | ___ \/ _ \/  __ \  ___|",
        r"/ /_\ \  | |   | | | |/ /| |__ | |_| | \`--. | | | | |_/ / /_\ \ /  \/| |__  ",
        r"|  _  |  | |   | | |    \|  __||  _  |  \`--. \ | | |    /|  _  | \__/\|  __| ",
        r"| | | |  | |   | | | |\  \ |___| | | | /\__/ / |_| | |\ \| | | | \____/\____|",
        r"\_| |_/  \_/   \_/ \_| \_/\____/\_| |_/ \____/ \___/\_| \_\_| |_/\____/\____|",
        r"                                                                            ",
        r"                  Attack Surface Mapping & Security Review                  ",
        r"                                  by Tokyo                                  "
    ]


   colors = [
    "\033[1;38;5;197m", # Bold Pink/Red
    "\033[1;38;5;201m", # Bold Magenta
    "\033[1;38;5;129m", # Bold Purple
    "\033[1;38;5;93m",  # Bold Indigo
    "\033[1;38;5;39m",  # Bold Blue
    "\033[1;38;5;51m",  # Bold Cyan
    "\033[1;38;5;51m",  # Spacer line
    "\033[1;38;5;39m",  # Bold Subtitle
    "\033[1;38;5;244m"  # Bold Author
]


    print()

    for line, color in zip(lines, colors):
        print(f"{color}{line}\033[0m")

    # MAIN HEADLINE (inside banner area)
    print(f"\033[96m\033[1mATT&ck SURFACE\033[0m")

    print(f"\033[93mBy TOKYO\033[0m")

    print(f"\033[94m------------------------------------------------------------------------------------------\033[0m")