#!/usr/bin/python3

import datetime
import argparse
import ftplib
import socket
import sys
import re
import signal
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore, Event
from functools import lru_cache
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# Global shutdown flag
shutdown_event = Event()
connection_semaphore = None
print_lock = Lock()
DB_CACHE = None
SCAN_RESULTS = []  # Store successful results
RESULTS_LOCK = Lock()

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    safe_print("\n[!] Received interrupt signal, saving results and shutting down...")
    shutdown_event.set()

signal.signal(signal.SIGINT, signal_handler)

def safe_print(*args, **kwargs):
    """Thread-safe printing"""
    with print_lock:
        print(*args, **kwargs)

def save_results(results, output_format='json', output_file=None):
    """Save scan results to file"""
    if not results:
        safe_print("[!] No results to save")
        return
    
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"ftp_scan_results_{timestamp}"
    
    # Save as JSON
    if output_format == 'json':
        filename = f"{output_file}.json"
        with open(filename, 'w') as f:
            json.dump({
                'scan_date': datetime.datetime.now().isoformat(),
                'total_found': len(results),
                'results': results
            }, f, indent=2)
        safe_print(f"[*] Results saved to {filename}")
    
    # Save as CSV
    elif output_format == 'csv':
        filename = f"{output_file}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ip', 'port', 'banner', 'software', 'version', 'exploits_found', 'anonymous_enabled'])
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        safe_print(f"[*] Results saved to {filename}")
    
    # Save as simple text
    elif output_format == 'txt':
        filename = f"{output_file}.txt"
        with open(filename, 'w') as f:
            f.write(f"FTP Scan Results - {datetime.datetime.now()}\n")
            f.write("="*60 + "\n\n")
            for result in results:
                f.write(f"IP: {result['ip']}:{result['port']}\n")
                f.write(f"Banner: {result['banner']}\n")
                if result.get('software'):
                    f.write(f"Software: {result['software']} {result.get('version', '')}\n")
                if result.get('exploits_found'):
                    f.write(f"Exploits found: {result['exploits_found']}\n")
                    for exploit in result.get('exploits_list', [])[:5]:
                        f.write(f"  - {exploit}\n")
                if result.get('anonymous_enabled'):
                    f.write(f"⚠️  ANONYMOUS LOGIN ENABLED!\n")
                f.write("-"*40 + "\n\n")
        safe_print(f"[*] Results saved to {filename}")

class scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        timeout_value = 4
        self.ftp = ftplib.FTP(timeout=timeout_value)

    def connect(self):
        try:
            self.ftp.connect(self.ip, self.port)
            return True
        except Exception:
            return False

    def check_anon_login(self):
        if self.connect():
            try:
                self.ftp.login()  # anonymous
                safe_print(Fore.YELLOW + f"[!] {self.ip}:{self.port} - ANONYMOUS LOGIN ENABLED!" + Fore.RESET)
                try:
                    safe_print(f"[*] {self.ip}:{self.port} - Listing files...")
                    files = []
                    self.ftp.dir(files.append)
                    for f in files[:10]:  # Show first 10 files
                        safe_print(f"    {f}")
                    return True
                except Exception as e:
                    safe_print(f"[-] {self.ip}:{self.port} - Could not list files: {e}")
                    return True
                finally:
                    self.ftp.quit()
            except Exception:
                if '-d' in sys.argv or '--debug' in sys.argv:
                    safe_print(f"[-] {self.ip}:{self.port} - Anonymous login disabled")
                return False
        return False


class VulnScan():
    def __init__(self, ip, port, timeout=3, debug=False):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.debug = debug

    def grabBanner(self):
        """Grab FTP banner with proper socket cleanup"""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, self.port))
            
            banner = s.recv(1024)
            final = banner.decode('utf-8', errors='ignore').strip()
            final = re.sub(r'^\s*220[ -]?', '', final).strip()
            
            if self.debug:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                safe_print(f"[{timestamp}] {self.ip}:{self.port} - Banner: {final[:100]}")
            
            return final
            
        except socket.timeout:
            if self.debug:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                safe_print(f"[{timestamp}] {self.ip}:{self.port} - Connection timeout")
            return None
        except ConnectionRefusedError:
            if self.debug:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                safe_print(f"[{timestamp}] {self.ip}:{self.port} - Connection refused")
            return None
        except OSError as e:
            if self.debug:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                safe_print(f"[{timestamp}] {self.ip}:{self.port} - Connection error: {e}")
            return None
        except Exception as e:
            if self.debug:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                safe_print(f"[{timestamp}] {self.ip}:{self.port} - Error: {e}")
            return None
        finally:
            if s:
                s.close()

    @staticmethod
    @lru_cache(maxsize=256)
    def extract_software_version(banner_text):
        """Cached version extraction"""
        if not banner_text:
            return ('', '')

        text = ' '.join(banner_text.split())
        # Try to extract from parentheses first
        paren_contents = re.findall(r'\(([^)]+)\)', text)
        candidates = paren_contents + [text]

        name_char_class = r"[A-Za-z0-9\-\._\+'\& ]+?"
        patterns = [
            rf'({name_char_class})\s+v?([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})/([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})\s+release\s+([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})\s+(?:version|ver)\s*([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})\s+([0-9]+\.[0-9A-Za-z\.\-rc+]*)\b',
        ]

        def clean_name(n):
            n = re.sub(r'\s+', ' ', n).strip()
            n = re.sub(r'\b(server|ftp|service|daemon|ready)\b\.?$', '', n, flags=re.IGNORECASE).strip()
            return n

        for cand in candidates:
            s = cand.strip()
            for pat in patterns:
                m = re.search(pat, s, flags=re.IGNORECASE)
                if m:
                    name = clean_name(m.group(1))
                    ver = m.group(2).strip()
                    return (name, ver)

        # Fallback: take first word as software name
        first_word = text.split()[0] if text else ''
        return (clean_name(first_word), '')

    @staticmethod
    def normalize_for_match(s: str) -> str:
        if not s:
            return ''
        s2 = re.sub(r"[^\w\s]", ' ', s, flags=re.UNICODE)
        s2 = re.sub(r'\s+', ' ', s2).strip().lower()
        return s2

    @staticmethod
    def vuln_check(banner, db_cached, ip, debug=False):
        """Check vulnerabilities against database"""
        if not db_cached or not banner:
            return []
            
        fsoftware, fsversion = VulnScan.extract_software_version(banner)
        if not fsoftware:
            return []
        
        if debug:
            safe_print(f"[*] {ip} - Detected: {fsoftware} {fsversion}".strip())
        
        fsoftware_norm = VulnScan.normalize_for_match(fsoftware)
        fsversion_norm = fsversion.strip().lower()

        found_exploits = []
        for exploit_desc in db_cached:
            exploit_norm = VulnScan.normalize_for_match(exploit_desc)
            software_in_exploit = fsoftware_norm and (fsoftware_norm in exploit_norm)
            
            # Version matching: either no version detected or version in exploit
            version_in_exploit = (not fsversion_norm) or (fsversion_norm in exploit_desc.lower())

            if software_in_exploit and version_in_exploit:
                found_exploits.append(exploit_desc)

        if found_exploits:
            safe_print(Fore.GREEN + f"[!] {ip} - VULNERABLE! {len(found_exploits)} exploit(s) found" + Fore.RESET)
            for exploit in found_exploits[:3]:  # Show first 3
                safe_print(f"    → {exploit[:90]}")
        
        return found_exploits

    def scan_host(self, ip, port, db_cached, check_anon, debug=False):
        """Complete scan for a single host"""
        global connection_semaphore
        
        # Check for shutdown
        if shutdown_event.is_set():
            return None
        
        # Limit concurrent connections
        with connection_semaphore:
            result = {
                'ip': ip,
                'port': port,
                'banner': None,
                'software': '',
                'version': '',
                'exploits_found': 0,
                'exploits_list': [],
                'anonymous_enabled': False,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            # Grab banner
            banner = self.grabBanner()
            if banner:
                result['banner'] = banner
                
                # Check for vulnerabilities
                exploits = self.vuln_check(banner, db_cached, ip, debug)
                if exploits:
                    result['exploits_found'] = len(exploits)
                    result['exploits_list'] = exploits[:10]  # Store first 10
                    
                    # Extract software info
                    software, version = self.extract_software_version(banner)
                    result['software'] = software
                    result['version'] = version
                
                # Check anonymous login (only if we have a banner)
                if check_anon:
                    ftp_scanner = scanner(ip, port)
                    anon_result = ftp_scanner.check_anon_login()
                    result['anonymous_enabled'] = anon_result
                
                return result
            
            return None


def load_database(db_path):
    """Load and cache database once"""
    db_exploits = []
    try:
        with open(db_path, 'r', errors='ignore') as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                # Parse exploit-db format
                m = re.match(r'\s*(\d+)\s*,\s*"(.*)"\s*$', line)
                if m:
                    db_exploits.append(m.group(2).strip())
                else:
                    parts = line.split(',', 1)
                    if len(parts) == 2 and parts[0].strip().isdigit():
                        db_exploits.append(parts[1].strip().strip('"'))
        safe_print(f"[*] Loaded {len(db_exploits)} exploits from database")
    except FileNotFoundError:
        safe_print(f"[-] Database file not found: {db_path}")
    except Exception as e:
        safe_print(f"[-] Error loading database: {e}")
    
    return db_exploits


def load_ips_from_file(filename):
    """Load IP addresses from file, one per line"""
    ips = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.append(line)
    except FileNotFoundError:
        safe_print(f"[-] File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        safe_print(f"[-] Error reading file: {e}")
        sys.exit(1)
    
    if not ips:
        safe_print(f"[-] No IP addresses found in {filename}")
        sys.exit(1)
    
    return ips


def main():
    global connection_semaphore
    
    parser = argparse.ArgumentParser(description="High-performance FTP scanner + vuln lookup")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help="Target IP or hostname")
    target_group.add_argument('-l', '--list', help="File containing list of IP addresses (one per line)")
    
    parser.add_argument('-p', '--port', default=21, type=int, help="Target port (default: 21)")
    parser.add_argument('--db', default='ftp-vuln.db', help="Path to ftp vuln DB")
    parser.add_argument('--threads', default=20, type=int, help="Number of concurrent threads (default: 20)")
    parser.add_argument('--conn-limit', type=int, default=100, help="Max concurrent connections (default: 100)")
    parser.add_argument('--timeout', type=float, default=3, help="Connection timeout in seconds (default: 3)")
    parser.add_argument('--no-anon', action='store_true', help="Skip anonymous login check")
    parser.add_argument('-d', '--debug', action='store_true', help="Show detailed output for all hosts (timeouts, errors, etc)")
    parser.add_argument('-o', '--output', help="Output file prefix (without extension)")
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json', help="Output format (default: json)")
    
    args = parser.parse_args()
    
    connection_semaphore = Semaphore(args.conn_limit)
    
    DB_PATH = args.db
    port = args.port
    max_threads = args.threads
    check_anon = not args.no_anon
    debug = args.debug
    
    # Pre-load database
    db_cached = load_database(DB_PATH)
    
    # Get list of targets
    if args.target:
        targets = [args.target]
    else:
        targets = load_ips_from_file(args.list)
    
    safe_print(f"[*] Starting scan on {len(targets)} target(s)")
    safe_print(f"[*] Using {max_threads} threads, max {args.conn_limit} connections, {args.timeout}s timeout")
    safe_print(f"[*] Database: {DB_PATH} ({len(db_cached)} exploits)")
    safe_print(f"[*] Anonymous login check: {'Enabled' if check_anon else 'Disabled'}")
    safe_print(f"[*] Output mode: {'Debug (full output)' if debug else 'Quiet (success only)'}")
    safe_print("-" * 50)
    
    start_time = datetime.datetime.now()
    results = []
    completed = 0
    
    # Perform scans with thread pool
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {}
        for ip in targets:
            if shutdown_event.is_set():
                break
            vuln_scanner = VulnScan(ip, port, timeout=args.timeout, debug=debug)
            future = executor.submit(vuln_scanner.scan_host, ip, port, db_cached, check_anon, debug)
            future_to_ip[future] = ip
        
        # Process results with progress indicator
        for future in as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]
            
            # Show progress every 100 hosts (only in debug mode or periodically)
            if debug and completed % 100 == 0:
                elapsed = (datetime.datetime.now() - start_time).total_seconds()
                rate = completed / elapsed if elapsed > 0 else 0
                safe_print(f"[*] Progress: {completed}/{len(targets)} ({completed*100/len(targets):.1f}%) Rate: {rate:.1f} hosts/sec")
            
            try:
                result = future.result()
                if result:
                    results.append(result)
                    if not debug:  # In quiet mode, show when we find something
                        safe_print(f"[+] Found FTP server: {result['ip']}:{result['port']} - {result['banner'][:60]}")
                        if result['exploits_found'] > 0:
                            safe_print(Fore.GREEN + f"    [!] VULNERABLE! {result['exploits_found']} exploits" + Fore.RESET)
                        if result['anonymous_enabled']:
                            safe_print(Fore.YELLOW + f"    [!] ANONYMOUS LOGIN ENABLED!" + Fore.RESET)
            except Exception as e:
                if debug:
                    safe_print(f"[-] {ip} - Scan failed: {e}")
            
            if shutdown_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break
    
    # Calculate statistics
    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    vulnerable_hosts = [r for r in results if r['exploits_found'] > 0]
    anonymous_hosts = [r for r in results if r['anonymous_enabled']]
    
    # Summary
    safe_print("\n" + "=" * 50)
    safe_print("[*] SCAN SUMMARY")
    safe_print("=" * 50)
    safe_print(f"[*] Total hosts scanned: {len(targets)}")
    safe_print(f"[*] Hosts with FTP service: {len(results)}")
    safe_print(f"[*] Vulnerable hosts: {len(vulnerable_hosts)}")
    safe_print(f"[*] Anonymous login enabled: {len(anonymous_hosts)}")
    safe_print(f"[*] Success rate: {len(results)/len(targets)*100:.2f}%")
    safe_print(f"[*] Time elapsed: {elapsed:.1f} seconds")
    safe_print(f"[*] Average scan rate: {len(targets)/elapsed:.1f} hosts/second")
    
    # Save results if output specified or if we found something
    if results and args.output:
        save_results(results, args.format, args.output)
    elif results and not args.output:
        # Auto-save if we found hosts
        save_results(results, args.format)
    
    # Show top findings
    if vulnerable_hosts:
        safe_print(f"\n[!] VULNERABLE HOSTS FOUND ({len(vulnerable_hosts)}):")
        for r in vulnerable_hosts[:10]:
            safe_print(f"    {r['ip']}:{r['port']} - {r['software']} {r['version']} - {r['exploits_found']} exploits")
    
    if anonymous_hosts:
        safe_print(f"\n[!] ANONYMOUS LOGIN ENABLED ({len(anonymous_hosts)}):")
        for r in anonymous_hosts[:10]:
            safe_print(f"    {r['ip']}:{r['port']}")


if __name__ == "__main__":
    main()
