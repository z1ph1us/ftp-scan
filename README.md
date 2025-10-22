# FTP Scanner for Pentesting & CTFs

![Screenshot](https://github.com/user-attachments/assets/eb855e92-71a9-49fe-a3f2-009d52610df8)
<br>
![Python](https://img.shields.io/badge/python-v3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux--64%20%7C%20windows--64-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A lightweight FTP reconnaissance tool made for pentesters and CTF players. It detects anonymous logins, lists files, grabs FTP banners, and checks those banners against a local vulnerability database (CSV-style) to point you to potential exploit entries.

---

## Key features
- ✅ Anonymous login detection  
- ✅ Directory listing (when allowed)  
- ✅ Banner grabbing and safe decoding  
- ✅ Heuristic software & version extraction (handles apostrophes, parentheses, common banner noise)  
- ✅ Local exploit DB lookup (CSV-like: `id,"description"`)  
- ✅ Portable — single Python script, minimal dependencies

---

## Requirements
- Python 3.8+  
- `pip3` for installing dependencies  
- Linux/macOS/Windows (tested on Linux)  
- A vulnerability DB file (default: `/opt/ftp-vuln.db`) — CSV lines like:
  ```
  39,"Atftpd 0.6 - Remote Root Exploit (atftpdx.c)"
  43,"ProFTPD 1.2.9RC1 (mod_sql) Remote SQL Injection Exploit"
  ```

---

## Installation

Clone the repo and use the provided installer or install manually.

Automated:
```bash
git clone https://github.com/MIISTERC/ftp-scan.git
cd ftp-scan
sudo bash setup.sh
```

Manual:
```bash
git clone https://github.com/MIISTERC/ftp-scan.git
cd ftp-scan
pip3 install -r requirements.txt
# Optional: create a convenient symlink (adjust path accordingly)
sudo ln -s /full/path/to/ftp-scan/ftpscan.py /usr/local/bin/ftpscan
```

Run help:
```bash
ftpscan -h
# or
python3 ftpscan.py -h
```

---

## Usage examples

Basic scan (default port 21):
```bash
ftpscan -t 192.168.1.10
```

Custom port:
```bash
ftpscan -t 192.168.1.10 -p 2121
```

Custom DB path:
```bash
ftpscan -t 10.0.0.5 --db /path/to/ftp-vuln.db
```

Typical output:
- Anonymous login status  
- Directory listing (if allowed)  
- Extracted banner and parsed `software + version`  
- Matching exploit(s) from DB with Exploit-DB download links

---

## How it works (simple)
1. Connects to the FTP port and reads the greeting banner.  
2. Cleans the banner and tries several patterns to extract the software name and version (handles formats like `Name 1.2`, `Name/1.2`, `Name v1.2`, and things inside `(...)`).  
3. Normalizes the extracted name (lowercase, strip punctuation) and searches the local DB for matches.  
4. Prints matched exploits and provides exploit-db links.

---

## Troubleshooting & notes
- **DB file location**: Default is `/opt/ftp-vuln.db`. Use `--db` to point to a different file.  
- **Symlink caveat**: If you create a symlink, don’t move the cloned directory afterwards — the script may rely on relative paths for the DB. Prefer an absolute DB path or `--db` to avoid issues.  
- **Shebang**: Ensure `#!/usr/bin/python3` in the script matches your system’s Python 3 path, or run with `python3 ftpscan.py`.  
- **Permissions**: `setup.sh` may create symlinks and require `sudo`. 
- **False negatives**: Banner parsing is heuristic. If a match is missed, inspect printed `Detected software:` output to tune your DB or enable verbose logging.

---

## Contributing
Contributions welcome — fork, create a feature branch, and open a PR. Useful contributions:
- DB improvements / curated entries
- Fuzzy matching to catch slightly different vendor spellings
- Better multi-line banner handling or extended fingerprinting
- New Features ! 

Please keep changes small and well-documented.

---

## License
This project is released under the **MIT License**. See `LICENSE` for details.

---

## Author & Contact
**Sc17** — `https://github.com/MIISTERC`  
If you find bugs or have feature requests, open an issue or a PR on the GitHub repo.

---

**Disclaimer:** Use this tool only on systems you own or have explicit permission to test. Unauthorized scanning or exploitation is illegal.
