#!/usr/bin/env python3
"""
searchploit.py — Exploit-DB Live Extractor & Vulnerability Intelligence Engine.
Usage:
    python3 searchploit.py                      (Interactive Menu)
    python3 searchploit.py -u                   (Update / sync local database)
    python3 searchploit.py -l 20                (Show 20 latest exploits)
    python3 searchploit.py -s "wordpress"       (Search by keyword)
    python3 searchploit.py -t webapps           (Filter by category: webapps, remote, local, dos)
    python3 searchploit.py -p php               (Filter by platform: php, linux, windows, etc.)
    python3 searchploit.py --cve CVE-2024       (Search by CVE)
    python3 searchploit.py -i 52692             (Show detailed metadata)
    python3 searchploit.py -x 52692             (View exploit code in terminal)
    python3 searchploit.py -d 52692             (Download exploit file locally)
    python3 searchploit.py --live               (Extract live latest from Exploit-DB RSS)
"""

import os
import sys
import argparse
import json
import csv

from core.display import (
    Colors, print_banner, format_table, print_exploit_card,
    type_badge, platform_badge
)
from core.extractor import (
    fetch_rss_feed, download_database_csv, fetch_raw_exploit_code,
    save_exploit_file
)
from core.db import ExploitDB, DEFAULT_DB_PATH

CSV_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "files_exploits.csv")


def ensure_database(db):
    """Ensure database has data; if not, auto-sync."""
    if not db.is_populated():
        print(f"{Colors.YELLOW}[!] Database lokal kosong. Melakukan sinkronisasi awal dari GitLab...{Colors.RESET}")
        if not os.path.exists(CSV_CACHE_PATH):
            success = download_database_csv(CSV_CACHE_PATH)
            if not success:
                print(f"{Colors.RED}[!] Gagal inisialisasi database. Periksa koneksi internet.{Colors.RESET}")
                return False
        db.import_from_csv(CSV_CACHE_PATH)
    return True


def cmd_update(db):
    """Update database from upstream."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== SINKRONISASI DATABASE EXPLOIT-DB ==={Colors.RESET}")
    success = download_database_csv(CSV_CACHE_PATH)
    if success:
        db.import_from_csv(CSV_CACHE_PATH)
        stats = db.get_stats()
        print(f"{Colors.GREEN}[✓] Sinkronisasi selesai! Total {stats['total']} exploit siap dicari.{Colors.RESET}\n")
    else:
        print(f"{Colors.RED}[✗] Gagal memperbarui database.{Colors.RESET}\n")


def cmd_live_rss():
    """Fetch live feed directly from Exploit-DB RSS."""
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== LIVE FEED: EXPLOIT-DB REAL-TIME UPDATES ==={Colors.RESET}")
    items = fetch_rss_feed()
    if not items:
        return

    table_rows = []
    headers = ["EDB-ID", "Category", "Title", "Date"]
    for it in items:
        table_rows.append([
            it["id"] or "-",
            it["type"].upper(),
            it["title"],
            it["date"][:16] if it.get("date") else "-"
        ])

    print("")
    format_table(table_rows, headers, col_widths=[8, 12, 55, 18])
    print(f"\n{Colors.DIM}Tips: Gunakan 'python3 searchploit.py -i <ID>' untuk melihat detail atau -x <ID> untuk melihat kode.{Colors.RESET}\n")


def cmd_latest(db, limit=20, vuln_type=None, platform=None):
    """Show latest exploits from local database."""
    ensure_database(db)
    results = db.get_latest(limit=limit, vuln_type=vuln_type, platform=platform)
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== {limit} EXPLOIT TERBARU ==={Colors.RESET}")
    if vuln_type:
        print(f"{Colors.CYAN}[Filter Category]: {vuln_type.upper()}{Colors.RESET}")
    if platform:
        print(f"{Colors.CYAN}[Filter Platform]: {platform}{Colors.RESET}")

    display_results_table(results)


def cmd_search(db, query, vuln_type=None, platform=None, cve=None, author=None, limit=50):
    """Search exploits by query and filters."""
    ensure_database(db)
    results = db.search(query=query, vuln_type=vuln_type, platform=platform, cve=cve, author=author, limit=limit)
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== HASIL PENCARIAN: '{query or cve or author}' (Ditemukan: {len(results)}) ==={Colors.RESET}")
    display_results_table(results)


def display_results_table(results):
    """Render list of exploit dicts as table."""
    if not results:
        print(f"{Colors.YELLOW}[!] Tidak ada exploit yang cocok dengan kriteria.{Colors.RESET}\n")
        return

    table_rows = []
    headers = ["EDB-ID", "Category", "Platform", "Date", "Title"]
    for r in results:
        table_rows.append([
            str(r["id"]),
            (r["type"] or "-").upper(),
            r["platform"] or "-",
            r["date_published"] or "-",
            r["description"] or "-"
        ])

    print("")
    format_table(table_rows, headers, col_widths=[8, 10, 12, 12, 60])
    print(f"\n{Colors.DIM}Total: {len(results)} entri. Gunakan -i <ID> untuk info detail atau -x <ID> untuk melihat kode.{Colors.RESET}\n")


def cmd_info(db, eid):
    """Display exploit details."""
    ensure_database(db)
    exp = db.get_by_id(eid)
    if not exp:
        print(f"{Colors.RED}[!] Exploit EDB-ID #{eid} tidak ditemukan di database.{Colors.RESET}")
        return
    print_exploit_card(exp)


def cmd_cat(db, eid):
    """Print exploit code in terminal."""
    ensure_database(db)
    exp = db.get_by_id(eid)
    rel_path = exp.get("file") if exp else None
    
    print(f"{Colors.CYAN}[*] Mengambil kode exploit untuk EDB-ID #{eid}...{Colors.RESET}")
    code = fetch_raw_exploit_code(rel_path, eid)
    if not code:
        print(f"{Colors.RED}[!] Gagal mengambil kode exploit untuk #{eid}.{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}{Colors.WHITE}══════════════════════ [ EDB-ID #{eid} SOURCE CODE ] ══════════════════════{Colors.RESET}\n")
    print(code)
    print(f"\n{Colors.BOLD}{Colors.WHITE}══════════════════════════════════════════════════════════════════════════{Colors.RESET}\n")


def cmd_download(db, eid, dest_dir="downloads"):
    """Download exploit file locally."""
    ensure_database(db)
    exp = db.get_by_id(eid)
    rel_path = exp.get("file") if exp else None
    save_exploit_file(rel_path, eid, dest_dir=dest_dir)


def cmd_stats(db):
    """Display database statistics."""
    ensure_database(db)
    stats = db.get_stats()
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== STATISTIK DATABASE SEARCHPLOIT ==={Colors.RESET}")
    print(f" {Colors.WHITE}Total Exploit Terindeks :{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{stats['total']:,}{Colors.RESET}")
    print(f" {Colors.WHITE}Tanggal Rilis Terakhir  :{Colors.RESET} {Colors.YELLOW}{stats['latest_date']}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Distribusi Kategori:{Colors.RESET}")
    for t, cnt in stats["types"]:
        print(f"   {type_badge(t).ljust(20)}: {cnt:,}")

    print(f"\n{Colors.BOLD}Top 10 Platform:{Colors.RESET}")
    for p, cnt in stats["top_platforms"]:
        print(f"   • {Colors.CYAN}{p.ljust(15)}{Colors.RESET}: {cnt:,}")
    print("")


def interactive_menu(db):
    """Run interactive CLI menu."""
    while True:
        print_banner()
        print(f"{Colors.BOLD}PILIH MENU:{Colors.RESET}")
        print(f" {Colors.GREEN}[1]{Colors.RESET} 🔥 Lihat Exploit Terbaru (Live RSS Feed)")
        print(f" {Colors.GREEN}[2]{Colors.RESET} 📋 Lihat Exploit Terbaru (Database Lokal)")
        print(f" {Colors.GREEN}[3]{Colors.RESET} 🔍 Cari Exploit Berdasarkan Keyword")
        print(f" {Colors.GREEN}[4]{Colors.RESET} 🏷️  Filter Berdasarkan Kategori (webapps, remote, local, dos)")
        print(f" {Colors.GREEN}[5]{Colors.RESET} 💻 Filter Berdasarkan Platform (php, linux, windows, python)")
        print(f" {Colors.GREEN}[6]{Colors.RESET} 📄 Lihat Detail Exploit (Input ID)")
        print(f" {Colors.GREEN}[7]{Colors.RESET} 👁️  Lihat Kode Exploit Langsung di Terminal")
        print(f" {Colors.GREEN}[8]{Colors.RESET} ⬇️  Download File Exploit ke Lokal")
        print(f" {Colors.GREEN}[9]{Colors.RESET} 🔄 Sinkronisasi / Update Database Exploit-DB")
        print(f" {Colors.GREEN}[10]{Colors.RESET} 📊 Statistik Database")
        print(f" {Colors.RED}[0]{Colors.RESET} Keluar")

        try:
            choice = input(f"\n{Colors.CYAN}Searchploit > {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSampai jumpa!")
            break

        if choice == "1":
            cmd_live_rss()
        elif choice == "2":
            num = input("Jumlah exploit yang ditampilkan [default 20]: ").strip()
            limit = int(num) if num.isdigit() else 20
            cmd_latest(db, limit=limit)
        elif choice == "3":
            kw = input("Masukkan keyword pencarian (misal: wordpress, spring, apache, cve): ").strip()
            if kw:
                cmd_search(db, query=kw)
        elif choice == "4":
            print("\nKategori yang tersedia: webapps, remote, local, dos, papers")
            cat = input("Pilih kategori: ").strip().lower()
            if cat:
                cmd_latest(db, limit=30, vuln_type=cat)
        elif choice == "5":
            plat = input("Masukkan nama platform (misal: php, linux, windows, hardware, python): ").strip().lower()
            if plat:
                cmd_latest(db, limit=30, platform=plat)
        elif choice == "6":
            eid = input("Masukkan EDB-ID (misal: 52692): ").strip()
            if eid:
                cmd_info(db, eid)
        elif choice == "7":
            eid = input("Masukkan EDB-ID yang ingin dibaca kodenya: ").strip()
            if eid:
                cmd_cat(db, eid)
        elif choice == "8":
            eid = input("Masukkan EDB-ID yang ingin diunduh: ").strip()
            if eid:
                cmd_download(db, eid)
        elif choice == "9":
            cmd_update(db)
        elif choice == "10":
            cmd_stats(db)
        elif choice == "0":
            print("Keluar dari Searchploit. Sampai jumpa!")
            break
        else:
            print(f"{Colors.RED}[!] Pilihan tidak valid.{Colors.RESET}")

        input(f"\n{Colors.DIM}[Tekan Enter untuk melanjutkan]{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Searchploit — Exploit-DB Live Extractor & Vulnerability Intelligence Engine."
    )
    parser.add_argument("-u", "--update", action="store_true", help="Download / update local database from GitLab")
    parser.add_argument("--live", action="store_true", help="Fetch live newest exploits from Exploit-DB RSS feed")
    parser.add_argument("-l", "--latest", nargs="?", const=20, type=int, help="Show N latest exploits (default: 20)")
    parser.add_argument("-s", "--search", type=str, help="Search exploits by keyword (title, author, CVE, file)")
    parser.add_argument("-t", "--type", type=str, help="Filter by category (webapps, remote, local, dos, papers)")
    parser.add_argument("-p", "--platform", type=str, help="Filter by platform (php, linux, windows, hardware, etc.)")
    parser.add_argument("--cve", type=str, help="Filter by CVE identifier")
    parser.add_argument("--author", type=str, help="Filter by author name")
    parser.add_argument("-i", "--info", type=str, help="Show detailed exploit metadata by EDB-ID")
    parser.add_argument("-x", "--cat", type=str, help="Display raw exploit source code in terminal")
    parser.add_argument("-d", "--download", type=str, help="Download exploit code file to local directory")
    parser.add_argument("--dest", type=str, default="downloads", help="Destination folder for downloads")
    parser.add_argument("--stats", action="store_true", help="Show database overview statistics")

    args = parser.parse_args()
    db = ExploitDB()

    # If no flags passed, launch interactive menu
    if len(sys.argv) == 1:
        interactive_menu(db)
        return

    print_banner()

    if args.update:
        cmd_update(db)
    elif args.live:
        cmd_live_rss()
    elif args.search or args.cve or args.author:
        limit = args.latest if args.latest is not None else 50
        cmd_search(
            db, query=args.search, vuln_type=args.type,
            platform=args.platform, cve=args.cve, author=args.author,
            limit=limit
        )
    elif args.latest is not None:
        cmd_latest(db, limit=args.latest, vuln_type=args.type, platform=args.platform)
    elif args.type and not args.search:
        cmd_latest(db, limit=30, vuln_type=args.type, platform=args.platform)
    elif args.platform and not args.search:
        cmd_latest(db, limit=30, platform=args.platform)
    elif args.info:
        cmd_info(db, args.info)
    elif args.cat:
        cmd_cat(db, args.cat)
    elif args.download:
        cmd_download(db, args.download, dest_dir=args.dest)
    elif args.stats:
        cmd_stats(db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
