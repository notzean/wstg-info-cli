#!/usr/bin/env python3
"""
WSTG-INFO-02: Fingerprint Web Server
Mengidentifikasi tipe dan versi web server melalui HTTP headers, response behavior, dan error pages.
"""

import re
import socket
from urllib.parse import urlparse
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url, get_hostname


# ─── HTTP Header Analysis ─────────────────────────────────────────────────────

def analyze_headers(target_url, verbose):
    """Analisa HTTP response headers untuk fingerprinting."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa HTTP headers...", verbose)
    headers_info = {}

    try:
        url = ensure_url(target_url)
        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})

        headers_info["status_code"] = response.status_code
        headers_info["server"] = response.headers.get("Server", "Not Disclosed")
        headers_info["x_powered_by"] = response.headers.get("X-Powered-By", "Not Disclosed")
        headers_info["x_aspnet_version"] = response.headers.get("X-AspNet-Version", "Not Disclosed")
        headers_info["x_generator"] = response.headers.get("X-Generator", "Not Disclosed")
        headers_info["via"] = response.headers.get("Via", "Not Disclosed")
        headers_info["x_cache"] = response.headers.get("X-Cache", "Not Disclosed")

        # Header response lengkap
        headers_info["all_headers"] = dict(response.headers)

        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Server: {Fore.YELLOW}{headers_info['server']}{Style.RESET_ALL}", verbose)
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} X-Powered-By: {Fore.YELLOW}{headers_info['x_powered_by']}{Style.RESET_ALL}", verbose)

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal mengambil headers: {e}", verbose)
        headers_info["error"] = str(e)

    return headers_info


# ─── HTTP Methods Check ───────────────────────────────────────────────────────

def check_http_methods(target_url, verbose):
    """Cek method HTTP yang didukung via OPTIONS dan percobaan langsung."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memeriksa HTTP methods yang didukung...", verbose)
    methods_info = {}

    url = ensure_url(target_url)

    # OPTIONS request
    try:
        response = requests.options(url, timeout=10, headers={"User-Agent": USER_AGENT})
        allow_header = response.headers.get("Allow", "")
        methods_info["options_allow"] = allow_header if allow_header else "Not Disclosed"
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} OPTIONS Allow: {Fore.YELLOW}{allow_header}{Style.RESET_ALL}", verbose)
    except Exception as e:
        methods_info["options_allow"] = f"Error: {e}"

    # HEAD request
    try:
        response = requests.head(url, timeout=10, headers={"User-Agent": USER_AGENT})
        methods_info["head_status"] = response.status_code
        methods_info["head_server"] = response.headers.get("Server", "Not Disclosed")
    except Exception as e:
        methods_info["head_status"] = f"Error: {e}"

    return methods_info


# ─── Error Page Analysis ──────────────────────────────────────────────────────

def analyze_error_pages(target_url, verbose):
    """Analisa halaman error (404, 500) untuk informasi server."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa error pages...", verbose)
    error_info = {}

    url = ensure_url(target_url)

    # Request 404 page
    try:
        not_found_url = url.rstrip("/") + "/thispagedoesnotexist_wstg_test_404"
        response = requests.get(not_found_url, timeout=10, headers={"User-Agent": USER_AGENT})
        error_info["404_status"] = response.status_code
        body_lower = response.text.lower()

        # Deteksi signature server dari error page
        signatures = {
            "Apache": ["apache", "mod_ssl", "openssl"],
            "Nginx": ["nginx"],
            "Microsoft-IIS": ["microsoft", "iis", "asp.net"],
            "LiteSpeed": ["litespeed"],
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Tomcat": ["apache tomcat", "catalina"],
        }

        detected = []
        for server_name, keywords in signatures.items():
            for kw in keywords:
                if kw in body_lower:
                    detected.append(server_name)
                    break

        error_info["error_page_signatures"] = list(set(detected)) if detected else ["No signature detected"]
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Error page signatures: {detected}", verbose)

    except Exception as e:
        error_info["error"] = str(e)

    return error_info


# ─── Banner Grab (Socket) ────────────────────────────────────────────────────

def banner_grab(target_url, verbose):
    """Ambil banner langsung via socket connection."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Melakukan banner grab via socket...", verbose)
    hostname = get_hostname(target_url)
    banner_info = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, 80))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
        banner = sock.recv(2048).decode("utf-8", errors="ignore")
        sock.close()

        banner_info["raw_banner"] = banner[:500]

        # Extract server dari banner
        server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
        if server_match:
            banner_info["banner_server"] = server_match.group(1).strip()
        else:
            banner_info["banner_server"] = "Not found in banner"

        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Banner server: {banner_info.get('banner_server', 'N/A')}", verbose)

    except Exception as e:
        banner_info["error"] = str(e)
        log(f"  {Fore.YELLOW}[WARN]{Style.RESET_ALL} Banner grab gagal: {e}", verbose)

    return banner_info


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-02.
    Returns dict: wstg_id, title, status, findings, error
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-02: Fingerprint Web Server", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    findings = []
    errors = []

    # 1. HTTP Headers
    log(f"\n{Fore.CYAN}[PHASE 1] HTTP Header Analysis{Style.RESET_ALL}", verbose)
    header_data = analyze_headers(target_url, verbose)
    findings.append({"category": "HTTP Headers", "data": header_data})

    # 2. HTTP Methods
    log(f"\n{Fore.CYAN}[PHASE 2] HTTP Methods Check{Style.RESET_ALL}", verbose)
    methods_data = check_http_methods(target_url, verbose)
    findings.append({"category": "HTTP Methods", "data": methods_data})

    # 3. Error Page Analysis
    log(f"\n{Fore.CYAN}[PHASE 3] Error Page Analysis{Style.RESET_ALL}", verbose)
    error_data = analyze_error_pages(target_url, verbose)
    findings.append({"category": "Error Page Analysis", "data": error_data})

    # 4. Banner Grab
    log(f"\n{Fore.CYAN}[PHASE 4] Banner Grab{Style.RESET_ALL}", verbose)
    banner_data = banner_grab(target_url, verbose)
    findings.append({"category": "Banner Grab", "data": banner_data})

    # Server summary
    server_detected = header_data.get("server", "Unknown")
    log(f"\n{Fore.GREEN}[*] WSTG-INFO-02 selesai. Server terdeteksi: {server_detected}{Style.RESET_ALL}", verbose)

    status = "completed"
    if all("error" in f.get("data", {}) for f in findings):
        status = "error"
    elif any("error" in f.get("data", {}) for f in findings):
        status = "partial"

    return {
        "wstg_id": "WSTG-INFO-02",
        "title": "Fingerprint Web Server",
        "status": status,
        "findings": findings,
        "error": None if status != "error" else "Semua fase mengalami error"
    }
