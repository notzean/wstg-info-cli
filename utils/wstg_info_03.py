#!/usr/bin/env python3
"""
WSTG-INFO-03: Review Webserver Metafiles for Information Leakage
Mengambil dan menganalisa robots.txt, sitemap.xml, security.txt, humans.txt, dan .well-known.
"""

import re
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url


# ─── Robots.txt ────────────────────────────────────────────────────────────────

def check_robots_txt(base_url, verbose):
    """Fetch dan parse robots.txt."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching robots.txt...", verbose)
    result = {"exists": False, "disallow_paths": [], "allow_paths": [], "sitemaps": [], "raw": ""}

    try:
        url = base_url.rstrip("/") + "/robots.txt"
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})

        if response.status_code == 200 and "user-agent" in response.text.lower():
            result["exists"] = True
            result["raw"] = response.text[:3000]

            for line in response.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallow_paths"].append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["allow_paths"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    # Fix: sitemap URL bisa punya "http:" di depan
                    if "://" not in sitemap_url:
                        sitemap_url = "Sitemap:" + sitemap_url
                    else:
                        sitemap_url = line.split(" ", 1)[1].strip() if " " in line else sitemap_url
                    result["sitemaps"].append(sitemap_url)

            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} robots.txt ditemukan. "
                 f"Disallow: {len(result['disallow_paths'])}, "
                 f"Allow: {len(result['allow_paths'])}, "
                 f"Sitemaps: {len(result['sitemaps'])}", verbose)
        else:
            log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} robots.txt tidak ditemukan (status: {response.status_code})", verbose)

    except Exception as e:
        result["error"] = str(e)
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal fetch robots.txt: {e}", verbose)

    return result


# ─── Sitemap.xml ───────────────────────────────────────────────────────────────

def check_sitemap(base_url, verbose):
    """Fetch dan parse sitemap.xml."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching sitemap.xml...", verbose)
    result = {"exists": False, "urls": [], "url_count": 0}

    sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"]

    for path in sitemap_paths:
        try:
            url = base_url.rstrip("/") + path
            response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})

            if response.status_code == 200 and ("<urlset" in response.text or "<sitemapindex" in response.text):
                result["exists"] = True
                result["sitemap_path"] = path

                # Extract URLs (limit 50 untuk ringkas)
                urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text)
                result["url_count"] = len(urls)
                result["urls"] = urls[:50]

                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Sitemap ditemukan di {path}. Total URL: {len(urls)}", verbose)
                break

        except Exception as e:
            continue

    if not result["exists"]:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Sitemap tidak ditemukan.", verbose)

    return result


# ─── Security.txt ──────────────────────────────────────────────────────────────

def check_security_txt(base_url, verbose):
    """Cek /.well-known/security.txt dan /security.txt."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching security.txt...", verbose)
    result = {"exists": False, "content": ""}

    paths = ["/.well-known/security.txt", "/security.txt"]

    for path in paths:
        try:
            url = base_url.rstrip("/") + path
            response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})

            if response.status_code == 200 and ("contact:" in response.text.lower() or "policy:" in response.text.lower()):
                result["exists"] = True
                result["path"] = path
                result["content"] = response.text[:2000]

                # Parse fields
                fields = {}
                for line in response.text.splitlines():
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        key, val = line.split(":", 1)
                        fields[key.strip()] = val.strip()
                result["fields"] = fields

                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} security.txt ditemukan di {path}", verbose)
                break

        except Exception as e:
            continue

    if not result["exists"]:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} security.txt tidak ditemukan.", verbose)

    return result


# ─── Humans.txt ────────────────────────────────────────────────────────────────

def check_humans_txt(base_url, verbose):
    """Cek /humans.txt."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching humans.txt...", verbose)
    result = {"exists": False, "content": ""}

    try:
        url = base_url.rstrip("/") + "/humans.txt"
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})

        if response.status_code == 200 and len(response.text.strip()) > 10:
            result["exists"] = True
            result["content"] = response.text[:2000]
            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} humans.txt ditemukan.", verbose)
        else:
            log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} humans.txt tidak ditemukan.", verbose)

    except Exception as e:
        result["error"] = str(e)

    return result


# ─── .well-known Discovery ────────────────────────────────────────────────────

def check_well_known(base_url, verbose):
    """Cek resource .well-known yang umum."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memeriksa .well-known resources...", verbose)

    well_known_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/change-password",
        "/.well-known/dnt-policy.txt",
        "/.well-known/nodeinfo",
    ]

    found = []
    for path in well_known_paths:
        try:
            url = base_url.rstrip("/") + path
            response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
            if response.status_code == 200:
                found.append({
                    "path": path,
                    "status": response.status_code,
                    "content_type": response.headers.get("Content-Type", "unknown"),
                    "size": len(response.text)
                })
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan: {path}", verbose)
        except Exception:
            continue

    if not found:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Tidak ada .well-known resource ditemukan.", verbose)

    return found


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-03.
    Returns dict: wstg_id, title, status, findings, error
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-03: Review Webserver Metafiles", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    base_url = target_url if target_url.startswith(("http://", "https://")) else "http://" + target_url
    findings = []

    # 1. Robots.txt
    log(f"\n{Fore.CYAN}[PHASE 1] robots.txt{Style.RESET_ALL}", verbose)
    robots = check_robots_txt(base_url, verbose)
    findings.append({"category": "robots.txt", "data": robots})

    # 2. Sitemap
    log(f"\n{Fore.CYAN}[PHASE 2] sitemap.xml{Style.RESET_ALL}", verbose)
    sitemap = check_sitemap(base_url, verbose)
    findings.append({"category": "Sitemap", "data": sitemap})

    # 3. Security.txt
    log(f"\n{Fore.CYAN}[PHASE 3] security.txt{Style.RESET_ALL}", verbose)
    security = check_security_txt(base_url, verbose)
    findings.append({"category": "security.txt", "data": security})

    # 4. Humans.txt
    log(f"\n{Fore.CYAN}[PHASE 4] humans.txt{Style.RESET_ALL}", verbose)
    humans = check_humans_txt(base_url, verbose)
    findings.append({"category": "humans.txt", "data": humans})

    # 5. .well-known
    log(f"\n{Fore.CYAN}[PHASE 5] .well-known Resources{Style.RESET_ALL}", verbose)
    well_known = check_well_known(base_url, verbose)
    findings.append({"category": ".well-known Resources", "data": well_known})

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-03 selesai.{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-03",
        "title": "Review Webserver Metafiles for Information Leakage",
        "status": "completed",
        "findings": findings,
        "error": None
    }
