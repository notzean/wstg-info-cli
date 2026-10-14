#!/usr/bin/env python3
"""
WSTG-INFO-01: Conduct Search Engine Discovery Reconnaissance for Information Leakage
Menggunakan python-whois untuk WHOIS lookup dan ddgs (DuckDuckGo) untuk search engine scraping.
"""

import re
from urllib.parse import urlparse
from colorama import Fore, Style

# ─── Helpers ───────────────────────────────────────────────────────────────────

from utils.helper import USER_AGENT, log, extract_domain


# ─── WHOIS Lookup ──────────────────────────────────────────────────────────────

def perform_whois(domain, verbose):
    """Lakukan WHOIS lookup menggunakan python-whois dengan fallback API bgp.he.net."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Melakukan WHOIS lookup untuk: {Fore.YELLOW}{domain}{Style.RESET_ALL}", verbose)
    
    # 1. Coba menggunakan python-whois
    try:
        import whois
        w = whois.whois(domain)
        if w.domain_name:
            import datetime
            
            def clean_whois_val(val):
                if not val:
                    return "N/A"
                if isinstance(val, list):
                    return ", ".join([clean_whois_val(v) for v in val])
                elif isinstance(val, datetime.datetime):
                    return val.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    return str(val)

            whois_data = {}
            whois_data["domain_name"] = clean_whois_val(w.domain_name)
            whois_data["registrar"] = clean_whois_val(w.registrar)
            whois_data["creation_date"] = clean_whois_val(w.creation_date)
            whois_data["expiration_date"] = clean_whois_val(w.expiration_date)
            whois_data["updated_date"] = clean_whois_val(w.updated_date)
            whois_data["name_servers"] = clean_whois_val(w.name_servers)
            whois_data["registrant_country"] = clean_whois_val(w.country)
            whois_data["emails"] = clean_whois_val(w.emails)
            whois_data["org"] = clean_whois_val(w.org)
            whois_data["dnssec"] = clean_whois_val(w.dnssec)

            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} WHOIS data berhasil diambil (via python-whois).", verbose)
            return whois_data
    except Exception as e:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} python-whois gagal atau tidak menemukan data ({e}), mencoba fallback API...", verbose)

    # 2. Fallback menggunakan API bgp.he.net
    try:
        import requests
        url = f"https://bgp.he.net/whois/dns/{domain}"
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            raw_text = data.get("data", "")
            
            if not raw_text or "not found" in raw_text.lower() or "no entries found" in raw_text.lower():
                log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Domain tidak ditemukan di API bgp.he.net", verbose)
                return {"error": "Domain not found in whois records"}

            parsed_data = {}
            for line in raw_text.split('\n'):
                if ':' in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if key in parsed_data:
                        parsed_data[key] = f"{parsed_data[key]}, {val}"
                    else:
                        parsed_data[key] = val

            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} WHOIS data berhasil diambil (via API bgp.he.net).", verbose)
            return parsed_data if parsed_data else {"raw_whois": raw_text}
        else:
            log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} WHOIS API return status: {response.status_code}", verbose)
            return {"error": f"API returned status {response.status_code}"}

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} WHOIS lookup API gagal: {e}", verbose)
        return {"error": str(e)}



# ─── Search Engine Discovery (DuckDuckGo via ddgs) ────────────────────────────

def search_engine_recon(domain, verbose):
    """Scraping pencarian menggunakan DuckDuckGo (ddgs library)."""
    results_all = []

    dork_queries = [
        f"site:{domain}",
        f'intitle:"{domain}"',
        f'inurl:"{domain}"',
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:doc",
        f"site:{domain} filetype:docx",
        f"site:{domain} filetype:xls",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:dashboard",
        f"site:{domain} ext:sql",
        f"site:{domain} ext:bak",
        f"site:{domain} ext:log",
        f"site:{domain} ext:env",
    ]

    try:
        from ddgs import DDGS
        import time
        import random
    except ImportError:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Library 'ddgs' belum terpasang. Jalankan: pip install ddgs", verbose)
        return [{"error": "ddgs library not installed"}]

    for query in dork_queries:
        log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Searching: {Fore.YELLOW}{query}{Style.RESET_ALL}", verbose)
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with DDGS() as ddgs:
                    raw = list(ddgs.text(query, max_results=10))

                filtered_count = 0
                for r in raw:
                    title = r.get("title", "")
                    href = r.get("href", r.get("link", ""))
                    body = r.get("body", "")

                    # Strict filtering: if using 'site:', the domain must be in the URL
                    if "site:" in query and domain not in href.lower():
                        continue
                        
                    # Loose filtering: domain must at least be mentioned in url, title, or body
                    if domain not in href.lower() and domain not in title.lower() and domain not in body.lower():
                        continue

                    results_all.append({
                        "query": query,
                        "title": title,
                        "url": href,
                        "snippet": body[:200]
                    })
                    filtered_count += 1

                log(f"    {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan {filtered_count} hasil relevan (dari total {len(raw)} raw).", verbose)
                time.sleep(random.uniform(3, 6))  # Delay between successful queries to avoid rate limit
                break  # Success, exit retry loop

            except Exception as e:
                error_str = str(e).lower()
                if "no results" in error_str:
                    log(f"    {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan 0 hasil.", verbose)
                    time.sleep(random.uniform(2, 4))
                    break # it's not an error, just no results
                elif attempt < max_retries - 1:
                    log(f"    {Fore.YELLOW}[RETRY]{Style.RESET_ALL} Gagal untuk query '{query}', mencoba lagi... ({type(e).__name__})", verbose)
                    time.sleep(random.uniform(5, 10))  # Delay before retry
                else:
                    if "connecterror" in error_str or "timeout" in error_str or "getaddrinfo" in error_str:
                        log(f"    {Fore.RED}[ERROR]{Style.RESET_ALL} DuckDuckGo memblokir IP Anda (Anti-Bot/Rate Limit). Gagal query '{query}'.", verbose)
                    else:
                        log(f"    {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal untuk query '{query}' setelah {max_retries} percobaan: {e}", verbose)
                    
                    results_all.append({"query": query, "error": str(e)})
                    break # Skip query ini, lanjut ke dorking query berikutnya

    return results_all


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-01.
    Returns dict: wstg_id, title, status, findings, error
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-01: Search Engine Discovery Reconnaissance", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    domain = extract_domain(target_url)
    findings = []
    errors = []

    # 1. WHOIS Lookup
    log(f"\n{Fore.CYAN}[PHASE 1] WHOIS Lookup{Style.RESET_ALL}", verbose)
    whois_data = perform_whois(domain, verbose)
    findings.append({
        "category": "WHOIS Information",
        "data": whois_data
    })

    # 2. Search Engine Scraping
    log(f"\n{Fore.CYAN}[PHASE 2] Search Engine Discovery (DuckDuckGo){Style.RESET_ALL}", verbose)
    search_results = search_engine_recon(domain, verbose)
    findings.append({
        "category": "Search Engine Results",
        "data": search_results
    })

    # Tentukan status
    has_error = any("error" in str(f.get("data", "")).lower() for f in findings)
    status = "partial" if has_error else "completed"
    if all("error" in str(f.get("data", "")) for f in findings):
        status = "error"

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-01 selesai. Status: {status}{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-01",
        "title": "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
        "status": status,
        "findings": findings,
        "error": None if status != "error" else "Semua fase mengalami error"
    }
