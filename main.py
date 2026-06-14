import os
import sys

# Ensure the script directory is in sys.path for minimal/embedded Python interpreters
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attack_surface import scan_directory

def main():
    # Enable virtual terminal processing for ANSI colors on Windows
    if os.name == 'nt':
        os.system('')
        try:
            # Reconfigure stdout to use UTF-8
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "."
        
    if not os.path.exists(target):
        print(f"\033[91mError: Path '{target}' does not exist.\033[0m")
        sys.exit(1)
        
    scan_directory(target)

if __name__ == "__main__":
    main()
