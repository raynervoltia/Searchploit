#!/usr/bin/env python3
"""
core/extractor.py — Exploit-DB Extractor, Feed Parser, and Downloader Engine.
"""

import os
import sys
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import csv
import io
import re

from core.display import Colors

GITLAB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
GITLAB_RAW_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
EDB_RSS_URL = "https://www.exploit-db.com/rss.xml"
EDB_RAW_DOWNLOAD_BASE = "https://www.exploit-db.com/download/"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Searchploit/1.0"


def _build_request(url):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "*/*")
    return req


def fetch_rss_feed():
    """
    Fetch the latest exploits from Exploit-DB official RSS feed.
    Returns list of dicts: [{'id': ..., 'title': ..., 'link': ..., 'date': ..., 'type': ...}]
    """
    print(f"{Colors.CYAN}[*] Menghubungi Exploit-DB RSS Feed ({EDB_RSS_URL})...{Colors.RESET}")
    try:
        req = _build_request(EDB_RSS_URL)
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read()

        root = ET.fromstring(content)
        items = []
        for item in root.findall(".//item"):
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            desc = item.findtext("description", "").strip()
            pub_date = item.findtext("pubDate", "").strip()

            # Extract EDB-ID from link (e.g. https://www.exploit-db.com/exploits/52692)
            eid_match = re.search(r"/exploits/(\d+)", link)
            eid = eid_match.group(1) if eid_match else ""

            # Extract category from title like "[remote] Title..." or "[webapps] Title..."
            cat_match = re.match(r"^\[([a-zA-Z0-9_\-]+)\]\s*(.*)", title)
            if cat_match:
                vuln_type = cat_match.group(1).lower()
                clean_title = cat_match.group(2).strip()
            else:
                vuln_type = "unknown"
                clean_title = title

            items.append({
                "id": eid,
                "title": clean_title,
                "raw_title": title,
                "link": link,
                "type": vuln_type,
                "date": pub_date,
                "description": desc
            })
        print(f"{Colors.GREEN}[+] Berhasil mengekstrak {len(items)} exploit terbaru dari RSS Feed!{Colors.RESET}")
        return items
    except Exception as e:
        print(f"{Colors.RED}[!] Gagal mengambil RSS feed: {e}{Colors.RESET}")
        return []


def download_database_csv(target_path, show_progress=True):
    """
    Download complete files_exploits.csv from Exploit-DB GitLab repository.
    """
    print(f"{Colors.CYAN}[*] Mendownload database Exploit-DB terbaru dari GitLab...{Colors.RESET}")
    print(f"{Colors.DIM}    URL: {GITLAB_CSV_URL}{Colors.RESET}")

    try:
        req = _build_request(GITLAB_CSV_URL)
        with urllib.request.urlopen(req, timeout=30) as resp:
            total_size = resp.getheader("Content-Length")
            total_size = int(total_size) if total_size else None
            
            chunk_size = 1024 * 64
            downloaded = 0
            start_time = time.time()

            os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
            temp_path = target_path + ".tmp"

            with open(temp_path, "wb") as f:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if show_progress and total_size:
                        pct = (downloaded / total_size) * 100
                        mb = downloaded / (1024 * 1024)
                        total_mb = total_size / (1024 * 1024)
                        sys.stdout.write(f"\r{Colors.YELLOW}[>] Download progress: {mb:.1f} MB / {total_mb:.1f} MB ({pct:.1f}%)...{Colors.RESET}")
                        sys.stdout.flush()

            if show_progress:
                sys.stdout.write("\n")

            os.replace(temp_path, target_path)
            elapsed = time.time() - start_time
            size_mb = downloaded / (1024 * 1024)
            print(f"{Colors.GREEN}[+] Sukses mengunduh {size_mb:.2f} MB dalam {elapsed:.2f}s! Disimpan ke: {target_path}{Colors.RESET}")
            return True

    except Exception as e:
        print(f"{Colors.RED}[!] Gagal mengunduh database CSV: {e}{Colors.RESET}")
        return False


def fetch_raw_exploit_code(file_rel_path, eid=None):
    """
    Fetch the raw exploit code directly from GitLab (or fallback to EDB download).
    Returns raw string content or None.
    """
    urls_to_try = []
    if file_rel_path:
        clean_rel = file_rel_path.lstrip("/")
        urls_to_try.append(GITLAB_RAW_BASE + clean_rel)
    if eid:
        urls_to_try.append(f"{EDB_RAW_DOWNLOAD_BASE}{eid}")

    for url in urls_to_try:
        try:
            req = _build_request(url)
            with urllib.request.urlopen(req, timeout=12) as resp:
                content = resp.read()
                # Decode to string
                try:
                    return content.decode("utf-8")
                except UnicodeDecodeError:
                    return content.decode("latin-1", errors="replace")
        except Exception:
            continue

    return None


def save_exploit_file(file_rel_path, eid, dest_dir="downloads"):
    """
    Download and save an exploit code file to local directory.
    """
    content = fetch_raw_exploit_code(file_rel_path, eid)
    if not content:
        print(f"{Colors.RED}[!] Gagal mengambil kode exploit untuk ID #{eid}{Colors.RESET}")
        return None

    os.makedirs(dest_dir, exist_ok=True)
    filename = os.path.basename(file_rel_path) if file_rel_path else f"{eid}.txt"
    dest_path = os.path.join(dest_dir, filename)

    with open(dest_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)

    print(f"{Colors.GREEN}[+] Exploit #{eid} berhasil disimpan ke: {dest_path}{Colors.RESET}")
    return dest_path
