# main.py
import sys
import os
import shutil
import tempfile
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from attack_surface.banner import print_banner
from attack_surface.rules import RULES
from attack_surface.scanner import SurfaceScanner

def is_remote_git_link(token):
    """Detects if the target link points to a structured repository platform."""
    url = token.strip()
    if not url.startswith(("http://", "https://", "git@")):
        return False
    # Identifies typical source repository path structures
    git_pattern = r'^(https?://|git@)[a-zA-Z0-9.-]+[:/][a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(\.git)?/?$'
    return bool(re.match(git_pattern, url))

def is_standard_web_url(token):
    """Detects if the token is a standard live web application link."""
    url = token.strip()
    return url.startswith(("http://", "https://")) and not is_remote_git_link(url)

def scan_git_link(git_url):
    """Clones a repository into a temporary directory and runs the scanner."""
    print(f"\033[1;36m[*] Target Remote Repository Link Detected: {git_url}\033[0m")
    try:
        from git import Repo
    except ImportError:
        print("\033[1;31m[-] Dependency Error: 'GitPython' package is missing.\033[0m")
        sys.exit(1)

    temp_workspace = tempfile.mkdtemp(prefix="att4ck_git_")
    print(f"\033[1;34m[*] Mirroring latest codebase profile into temporary sandbox...\033[0m")
    try:
        Repo.clone_from(git_url, temp_workspace, depth=1)
        print(f"\033[1;32m[+] Codebase acquired. Processing 40 surface layers...\033[0m\n")
        scanner = SurfaceScanner(temp_workspace, RULES)
        _print_terminal_summary(scanner.scan())
    except Exception as e:
        print(f"\033[1;31m[-] Git Clone Operation Aborted: {e}\033[0m")
    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)
        print(f"\033[1;32m[+] Temporary environment storage cleared cleanly.\033[0m")

def scan_web_url(web_url):
    """Scrapes a live website, captures front-end source maps, and analyzes them."""
    print(f"\033[1;36m[*] Live Web URL Scan Target Initiated: {web_url}\033[0m")
    
    # Generate temporary workplace folder to hold scraped assets
    temp_workspace = tempfile.mkdtemp(prefix="att4ck_web_")
    print(f"\033[1;34m[*] Spidery ingest engine downloading target runtime front-end code map...\033[0m")
    
    headers = {"User-Agent": "ATT4ck-Surface-Scanner/1.0 (Security-Researcher-Audit)"}
    try:
        # 1. Download primary index HTML page asset
        response = requests.get(web_url, headers=headers, timeout=10)
        html_content = response.text
        
        # Save page context locally
        with open(os.path.join(temp_workspace, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
            
        # 2. Extract and download associated external embedded JavaScript scripts
        soup = BeautifulSoup(html_content, 'html.parser')
        js_count = 0
        
        for script_tag in soup.find_all("script"):
            src = script_tag.get("src")
            if src:
                # Build absolute download URLs for relative scripts
                absolute_js_url = urljoin(web_url, src)
                try:
                    js_res = requests.get(absolute_js_url, headers=headers, timeout=5)
                    js_count += 1
                    js_filename = f"script_{js_count}_{os.path.basename(urlparse(absolute_js_url).path)}"
                    if not js_filename.endswith(".js"):
                        js_filename += ".js"
                        
                    with open(os.path.join(temp_workspace, js_filename), "w", encoding="utf-8") as js_f:
                        js_f.write(js_res.text)
                except Exception:
                    pass # Continue scanning if an individual script blocks requests

        print(f"\033[1;32m[+] Ingest mirrored: 1 HTML index file and {js_count} javascript source modules captured.\033[0m")
        print(f"\033[1;34m[*] Launching multi-core rules analyzer pipeline...\033[0m\n")
        
        # 3. Fire the core scanner against the downloaded asset maps
        scanner = SurfaceScanner(temp_workspace, RULES)
        _print_terminal_summary(scanner.scan())

    except Exception as e:
        print(f"\033[1;31m[-] Web Scraping Failed: Connection refused or host unreachable: {e}\033[0m")
    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)
        print(f"\033[1;32m[+] Ephemeral memory space sanitized cleanly.\033[0m")

def _print_terminal_summary(results):
    """Outputs matching logs onto terminal interface dashboards."""
    vulnerable_findings = [r for r in results if r.get("status") == "VULNERABLE"]
    sanitized_findings = [r for r in results if r.get("status") == "SANITIZED"]

    if vulnerable_findings:
        print(f"\033[1;31m[!] ALERT: Identified {len(vulnerable_findings)} Open Attack Surfaces:\033[0m\n")
        for f in vulnerable_findings:
            print(f"🚨 \033[1;31m[VULNERABLE]\033[0m {f['category']} -> {f['file']}:{f['line']}")
            print(f"   Snippet: {f['snippet']}\n   Desc:    {f['description']}\n")
    
    if sanitized_findings:
        print(f"\033[1;32m[+] SECURE: Found {len(sanitized_findings)} Actively Defended Surfaces:\033[0m\n")
        for f in sanitized_findings:
            print(f"✅ \033[1;32m[SAFE]\033[0m {f['category']} -> {f['file']}:{f['line']}")
            print(f"   Snippet: {f['snippet']}\n")

    if not results:
        print("\033[1;32m[+] Scan Complete: No vulnerabilities found matching current rulesets.\033[0m")

def main():
    print_banner()

    if len(sys.argv) < 2:
        print("\033[1;31m[-] Error: Please pass a target directory path, repository link, or standard website URL.\033[0m")
        sys.exit(1)

    input_target = sys.argv[1].strip()

    # Route request dynamically based on token structural matches
    if is_remote_git_link(input_target):
        scan_git_link(input_target)
    elif is_standard_web_url(input_target):
        scan_web_url(input_target)
    else:
        if not os.path.exists(input_target):
            print(f"\033[1;31m[-] Error: Local path folder path location does not exist: {input_target}\033[0m")
            sys.exit(1)
            
        print(f"\033[1;34m[*] Running multi-core scan against local asset folder: {input_target}...\033[0m\n")
        scanner = SurfaceScanner(input_target, RULES)
        _print_terminal_summary(scanner.scan())

if __name__ == "__main__":
    main()
