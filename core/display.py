#!/usr/bin/env python3
"""
core/display.py — ANSI Terminal Formatter and UI Components for Searchploit.
"""

import sys
import shutil

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDER   = "\033[4m"

    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # Background
    BG_BLUE = "\033[44m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[48;5;236m"


def type_badge(vuln_type):
    """Return colored badge for exploit category."""
    t = (vuln_type or "").lower().strip()
    if t == "webapps":
        return f"{Colors.MAGENTA}[WEBAPPS]{Colors.RESET}"
    elif t == "remote":
        return f"{Colors.RED}[REMOTE]{Colors.RESET}"
    elif t == "local":
        return f"{Colors.YELLOW}[LOCAL]{Colors.RESET}"
    elif t == "dos":
        return f"{Colors.GRAY}[DOS]{Colors.RESET}"
    elif t == "papers":
        return f"{Colors.BLUE}[PAPERS]{Colors.RESET}"
    else:
        return f"{Colors.CYAN}[{t.upper() if t else 'N/A'}]{Colors.RESET}"


def platform_badge(platform):
    """Return colored platform badge."""
    p = (platform or "").lower().strip()
    return f"{Colors.DIM}{p}{Colors.RESET}"


def print_banner():
    """Print ASCII art banner."""
    term_width = shutil.get_terminal_size((80, 20)).columns
    banner = fr"""
{Colors.CYAN}{Colors.BOLD}   _____                      __           __       _ __ 
  / ___/___  ____ ___________/ /_  ____  / /___   (_) /_
  \__ \/ _ \/ __ `/ ___/ ___/ __ \/ __ \/ / __ \ / / __/
 ___/ /  __/ /_/ / /  / /__/ / / / /_/ / / /_/ // / /_  
/____/\___/\__,_/_/   \___/_/ /_/ .___/_/\____//_/\__/  
                               /_/                      {Colors.RESET}
{Colors.DIM}» Exploit-DB Live Extractor & Vulnerability Intelligence Engine (v1.0){Colors.RESET}
{Colors.GRAY}───────────────────────────────────────────────────────────────────────{Colors.RESET}"""
    print(banner)


def format_table(rows, headers, col_widths=None):
    """Print formatted terminal table."""
    if not rows:
        print(f"{Colors.YELLOW}[!] Tidak ada hasil yang ditemukan.{Colors.RESET}")
        return

    term_width = shutil.get_terminal_size((100, 20)).columns
    
    # Calculate widths if not provided
    if not col_widths:
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                if i < len(col_widths):
                    clean_len = len(str(val))
                    if clean_len > col_widths[i]:
                        col_widths[i] = clean_len

    # Cap description column to fit terminal
    total_w = sum(col_widths) + (len(headers) * 3)
    if total_w > term_width and len(col_widths) >= 3:
        excess = total_w - term_width
        col_widths[2] = max(25, col_widths[2] - excess)

    # Print Header
    header_str = " | ".join(f"{Colors.BOLD}{Colors.CYAN}{h.ljust(col_widths[i])}{Colors.RESET}" for i, h in enumerate(headers))
    sep_str = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    
    print(header_str)
    print(f"{Colors.GRAY}{sep_str}{Colors.RESET}")

    # Print Rows
    for row in rows:
        row_cols = []
        for i, val in enumerate(row):
            w = col_widths[i] if i < len(col_widths) else 10
            s_val = str(val)
            if len(s_val) > w:
                s_val = s_val[:w - 3] + "..."
            row_cols.append(s_val.ljust(w))
        print(" | ".join(row_cols))


def print_exploit_card(exp):
    """Print detailed card for a single exploit record."""
    eid = exp.get("id", "N/A")
    title = exp.get("description", "N/A")
    author = exp.get("author", "N/A")
    date_pub = exp.get("date_published", "N/A")
    v_type = exp.get("type", "N/A")
    platform = exp.get("platform", "N/A")
    port = exp.get("port", "")
    codes = exp.get("codes", "")
    file_path = exp.get("file", "")
    verified = "Yes" if str(exp.get("verified", "0")) == "1" else "No"
    source_url = exp.get("source_url", "")
    edb_url = f"https://www.exploit-db.com/exploits/{eid}"

    print(f"\n{Colors.BOLD}{Colors.WHITE}════════════════════════════════════════════════════════════════════════════════{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}[*] EXPLOIT DETAILS: EDB-ID #{eid}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}════════════════════════════════════════════════════════════════════════════════{Colors.RESET}")
    print(f" {Colors.CYAN}Title       :{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")
    print(f" {Colors.CYAN}Category    :{Colors.RESET} {type_badge(v_type)}  {Colors.CYAN}Platform:{Colors.RESET} {platform_badge(platform)}  {Colors.CYAN}Port:{Colors.RESET} {port or '-'}")
    print(f" {Colors.CYAN}Published   :{Colors.RESET} {date_pub}    {Colors.CYAN}Verified:{Colors.RESET} {Colors.GREEN if verified=='Yes' else Colors.GRAY}{verified}{Colors.RESET}")
    print(f" {Colors.CYAN}Author      :{Colors.RESET} {author}")
    if codes:
        print(f" {Colors.CYAN}CVE / Codes :{Colors.RESET} {Colors.YELLOW}{codes}{Colors.RESET}")
    print(f" {Colors.CYAN}Relative File:{Colors.RESET} {file_path}")
    print(f" {Colors.CYAN}EDB URL     :{Colors.RESET} {Colors.BLUE}{edb_url}{Colors.RESET}")
    if source_url:
        print(f" {Colors.CYAN}Source Ref  :{Colors.RESET} {source_url}")
    print(f"{Colors.BOLD}{Colors.WHITE}════════════════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
