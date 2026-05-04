# FTP Scanner for Pentesting & CTFs

![Screenshot](https://github.com/user-attachments/assets/eb855e92-71a9-49fe-a3f2-009d52610df8)
<br>
![Python](https://img.shields.io/badge/python-v3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux--64%20%7C%20windows--64-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A lightweight FTP reconnaissance tool made for pentesters and CTF players. It detects anonymous logins, lists files, grabs FTP banners, and checks those banners against a local vulnerability database (CSV-style) to point you to potential exploit entries.

EDIT: Added batch processing and output saving into a file. Run with -l flag to specify input list of IPs: python3 ftpscan.py -l ips_list.txt --db ./ftp-vuln.db 
