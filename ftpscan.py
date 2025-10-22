#!/usr/bin/python3
"""
ftp-scan (updated)
Improved banner parsing and vuln-db matching (handles apostrophes, noise words,
multiple banner formats, and normalizes punctuation for matching).
"""
import argparse
import ftplib
import socket
import sys
import re
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

parser = argparse.ArgumentParser(description="Simple FTP scanner + vuln lookup")
parser.add_argument('-t', '--target', required=True, help="Target IP or hostname")
parser.add_argument('-p', '--port', required=False, default=21, type=int, help="Target port (default: 21)")
parser.add_argument('--db', required=False, default='/opt/ftp-vuln.db', help="Path to ftp vuln DB (CSV style)")
args = parser.parse_args()
target = args.target
port = args.port
DB_PATH = args.db


class scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        timeout_value = 4
        self.ftp = ftplib.FTP(timeout=timeout_value)

    def connect(self):
        try:
            self.ftp.connect(self.ip, self.port)
        except Exception as e:
            print(f"[-] Connection failed , error :-")
            print(e)
            return False
        return True

    def check_anon_login(self):
        if self.connect():
            try:
                self.ftp.login()  # anonymous
                print(f"[+] Anonymous login is enabled!")
                try:
                    print(f"[+] Trying to list all the files..")
                    # ftp.dir prints to stdout and returns None; keep that behavior
                    self.ftp.dir("-a")
                except Exception as e:
                    print("Error listing files, please check manually... error :- ")
                    print(e)
            except Exception:
                print(f"[-] Anonymous Login is Disabled.")


class VulnScan():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(5)

    def grabBanner(self):
        try:
            self.s.connect((self.ip, self.port))
        except Exception:
            # silent exit for unreachable host to match original behavior
            sys.exit(0)

        try:
            banner = self.s.recv(1024)
        except Exception:
            banner = b''
        try:
            final = banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            final = str(banner)
        self.s.close()
        # Remove common FTP greeting code prefix (220)
        final = re.sub(r'^\s*220[ -]?', '', final).strip()
        return final

    @staticmethod
    def extract_software_version(banner_text):
        """
        Try multiple strategies to pull software name and version from a banner.
        Returns (software_name, version) where version may be '' if not found.
        """
        if not banner_text:
            return ('', '')

        # collapse whitespace
        text = ' '.join(banner_text.split())

        # try parenthetical contents first (many banners use parentheses)
        paren_contents = re.findall(r'\(([^)]+)\)', text)
        candidates = paren_contents + [text]

        # allow apostrophes & ampersand and common punctuation in names
        name_char_class = r"[A-Za-z0-9\-\._\+'\& ]+?"

        patterns = [
            rf'({name_char_class})\s+v?([0-9][0-9A-Za-z\.\-rc+]*)\b',   # Name v1.2 or Name 1.2
            rf'({name_char_class})/([0-9][0-9A-Za-z\.\-rc+]*)\b',       # Name/1.2
            rf'({name_char_class})\s+release\s+([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})\s+(?:version|ver)\s*([0-9][0-9A-Za-z\.\-rc+]*)\b',
            rf'({name_char_class})\s+([0-9]+\.[0-9A-Za-z\.\-rc+]*)\b',   # fallback name + dotted version
        ]

        def clean_name(n):
            # normalize whitespace
            n = re.sub(r'\s+', ' ', n).strip()
            # remove trailing noise words
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

        # last resort: take left-most chunk until common separator, try to extract version
        sep = re.split(r'[-|/,:()]', text)[0].strip()
        m = re.match(rf'({name_char_class})\s+([0-9][0-9A-Za-z\.\-rc+]*)\b', sep)
        if m:
            return (clean_name(m.group(1)), m.group(2).strip())

        return (clean_name(sep), '')

    @staticmethod
    def normalize_for_match(s: str) -> str:
        """
        Normalize string for comparison:
        - lower-case
        - remove punctuation except whitespace and alphanumerics
        - collapse multiple spaces
        """
        if not s:
            return ''
        # remove characters that are not word chars or whitespace
        s2 = re.sub(r"[^\w\s]", ' ', s, flags=re.UNICODE)
        s2 = re.sub(r'\s+', ' ', s2).strip().lower()
        return s2

    @staticmethod
    def vuln_check(banner):
        try:
            with open(DB_PATH, 'r', errors='ignore') as fp:
                print(f"[*] Searching Exploits in the database for banner: {banner}")
                db_lines = fp.readlines()
        except FileNotFoundError:
            print(f"[-] Failed to open the ftp-vuln.db file at {DB_PATH}.")
            return
        except Exception as e:
            print(f"[-] Error opening DB file: {e}")
            return

        fsoftware, fsversion = VulnScan.extract_software_version(banner)
        if fsoftware:
            print(f"[*] Detected software: '{fsoftware}'  version: '{fsversion}'")
        else:
            print("[*] Could not detect software/version from banner, falling back to raw banner search.")
            fsoftware = banner
            fsversion = ''

        fsoftware_norm = VulnScan.normalize_for_match(fsoftware)
        fsversion_norm = fsversion.strip().lower()

        found = []
        exploit_counter = 0

        # parse DB: support lines like 39,"Atftpd 0.6 - Remote Root Exploit (atftpdx.c)"
        for raw in db_lines:
            line = raw.strip()
            if not line:
                continue

            # try to parse id and quoted description (handles commas inside quotes)
            m = re.match(r'\s*(\d+)\s*,\s*"(.*)"\s*$', line)
            if m:
                id = int(m.group(1))
                exploit_desc = m.group(2).strip()
            else:
                # fallback: split on first comma
                parts = line.split(',', 1)
                if len(parts) == 2 and parts[0].strip().isdigit():
                    id = int(parts[0].strip())
                    exploit_desc = parts[1].strip().strip('"')
                else:
                    # unknown format; skip
                    continue

            exploit_norm = VulnScan.normalize_for_match(exploit_desc)

            # check for software match (normalized)
            software_in_exploit = fsoftware_norm and (fsoftware_norm in exploit_norm)
            version_in_exploit = (not fsversion_norm) or (fsversion_norm in exploit_desc.lower())

            # If software name appears in exploit text and version matches (or not present), count it
            if software_in_exploit and version_in_exploit:
                exploit_counter += 1
                found.append((id, exploit_desc))

        if exploit_counter == 0:
            print("[+] No exploits found in DB file..")
        else:
            print(Fore.GREEN + f"[+] FTP Version is vulnerable!! Found {exploit_counter} matching exploit(s)." + Fore.RESET)
            for id, exploit in found:
                print(Style.BRIGHT + f"[+] Exploit: {exploit}" + Style.RESET_ALL)
                print(Style.BRIGHT + f"[*] Exploit DB : http://exploit-db.com/download/{id}" + Style.RESET_ALL)


def menu():
    banner = r'''
╭━━━┳╮
┃╭━┳╯╰╮
┃╰━┻╮╭╋━━╮╱╱╭━━┳━━┳━━┳━╮
┃╭━━┫┃┃╭╮┣━━┫━━┫╭━┫╭╮┃╭╮╮
┃┃╱╱┃╰┫╰╯┣━━╋━━┃╰━┫╭╮┃┃┃┃
╰╯╱╱╰━┫╭━╯╱╱╰━━┻━━┻╯╰┻╯╰╯
╱╱╱╱╱╱┃┃
╱╱╱╱╱╱╰╯
'''
    print(Fore.RED + banner + Fore.RESET)
    print(Fore.RED + "Author - Sc17" + Fore.RESET)
    print(Fore.RED + "Github - https://github.com/MIISTERC" + Fore.RESET)


if __name__ == "__main__":
    menu()
    scan = scanner(target, port)
    scan.check_anon_login()
    vuln = VulnScan(target, port)
    banner = vuln.grabBanner()
    print("Banner Grabbed! : ", banner)
    vuln.vuln_check(banner)

