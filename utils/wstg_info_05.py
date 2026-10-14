#!/usr/bin/env python3
"""
WSTG-INFO-05: Review Webpage Content for Information Leakage
Menganalisa source code HTML untuk menemukan informasi sensitif: comments, meta tags, emails, API keys, dll.
"""

import re
from urllib.parse import urlparse
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url


# ─── HTML Comments Extraction ─────────────────────────────────────────────────

def extract_html_comments(html_content, verbose):
    """Ekstrak semua HTML comments dari source code."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mengekstrak HTML comments...", verbose)

    comments = re.findall(r"<!--(.*?)-->", html_content, re.DOTALL)

    # Filter komentar kosong atau pendek yang tidak berarti
    meaningful_comments = []
    for comment in comments:
        cleaned = comment.strip()
        if len(cleaned) > 3 and not cleaned.startswith("[if ") and not cleaned.startswith("[endif"):
            meaningful_comments.append(cleaned[:500])

    log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan {len(meaningful_comments)} komentar bermakna.", verbose)
    return meaningful_comments


# ─── Meta Tags Extraction ─────────────────────────────────────────────────────

def extract_meta_tags(html_content, verbose):
    """Ekstrak meta tags informatif."""
    from bs4 import BeautifulSoup

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mengekstrak meta tags...", verbose)

    soup = BeautifulSoup(html_content, "html.parser")
    meta_info = []

    interesting_names = [
        "generator", "author", "description", "keywords", "robots",
        "viewport", "csrf-token", "msapplication-config",
        "theme-color", "application-name"
    ]

    for meta in soup.find_all("meta"):
        name = meta.get("name", meta.get("property", meta.get("http-equiv", ""))).lower()
        content = meta.get("content", "")

        if name and content:
            meta_info.append({"name": name, "content": content[:300]})
            if name in interesting_names:
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Meta [{name}]: {content[:100]}", verbose)

    # Title tag
    title_tag = soup.find("title")
    if title_tag and title_tag.string:
        meta_info.append({"name": "title", "content": title_tag.string.strip()})

    return meta_info


# ─── Sensitive Pattern Detection ──────────────────────────────────────────────

def detect_sensitive_patterns(html_content, verbose):
    """Cari pola sensitif di source code: emails, IPs, API keys, paths, dll."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mencari pola sensitif...", verbose)

    patterns = {
        "email_addresses": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "ip_addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "api_keys": r"""(?:api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?""",
        "internal_paths": r"""(?:\/(?:var|etc|usr|home|tmp|opt|srv|root)\/[a-zA-Z0-9_\-\/\.]+)""",
        "debug_info": r"""(?:debug|DEBUG|stacktrace|stack_trace|traceback|Traceback|Error in|exception|Exception)""",
        "version_numbers": r"""(?:version|ver|v)\s*[:=]?\s*['"]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)['"]?""",
        "todo_fixme": r"""(?:TODO|FIXME|HACK|XXX|BUG|WARN)[\s:]+(.{5,80})""",
        "aws_patterns": r"""(?:AKIA[0-9A-Z]{16}|(?:aws[_-]?(?:access|secret|session))[_-]?(?:key[_-]?id|key|token)\s*[:=])""",
        "private_keys": r"""(?:-----BEGIN\s+(?:RSA |DSA |EC )?PRIVATE KEY-----)""",
    }

    results = {}
    for pattern_name, regex in patterns.items():
        try:
            matches = re.findall(regex, html_content, re.IGNORECASE)
            unique_matches = list(set(matches))[:20]
            if unique_matches:
                results[pattern_name] = unique_matches
                log(f"  {Fore.RED}[!]{Style.RESET_ALL} {pattern_name}: {len(unique_matches)} ditemukan", verbose)
        except Exception:
            continue

    if not results:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Tidak ada pola sensitif ditemukan.", verbose)

    return results


# ─── JavaScript Files Analysis ────────────────────────────────────────────────

def analyze_javascript(target_url, html_content, verbose):
    """Cari dan analisa JavaScript files untuk hardcoded secrets."""
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa JavaScript files...", verbose)

    soup = BeautifulSoup(html_content, "html.parser")
    js_findings = []

    # Inline scripts
    inline_scripts = soup.find_all("script")
    inline_count = 0
    for script in inline_scripts:
        if script.string and len(script.string.strip()) > 10:
            inline_count += 1
            content = script.string
            # Cek patterns sensitif di inline JS
            sensitive = detect_sensitive_patterns(content, False)
            if sensitive:
                js_findings.append({
                    "type": "inline_script",
                    "sensitive_data": sensitive
                })

    # External JS files (ambil max 5)
    external_scripts = soup.find_all("script", src=True)
    external_js = []
    for script in external_scripts[:10]:
        src = script.get("src", "")
        full_url = urljoin(target_url, src)
        external_js.append(full_url)

    # Download dan scan max 5 external JS
    for js_url in external_js[:5]:
        try:
            response = requests.get(js_url, timeout=10, headers={"User-Agent": USER_AGENT})
            if response.status_code == 200:
                sensitive = detect_sensitive_patterns(response.text, False)
                if sensitive:
                    js_findings.append({
                        "type": "external_script",
                        "url": js_url,
                        "sensitive_data": sensitive
                    })
                    log(f"  {Fore.RED}[!]{Style.RESET_ALL} Sensitif data di JS: {js_url}", verbose)
        except Exception:
            continue

    log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Inline scripts: {inline_count}, External JS: {len(external_js)}", verbose)

    return {
        "inline_script_count": inline_count,
        "external_js_urls": external_js[:20],
        "js_sensitive_findings": js_findings
    }


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-05.
    Returns dict: wstg_id, title, status, findings, error
    """
    import requests

    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-05: Review Webpage Content for Information Leakage", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    url = ensure_url(target_url)
    findings = []

    # Fetch halaman utama
    try:
        log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching halaman utama: {url}", verbose)
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        html_content = response.text
    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal fetch halaman: {e}", verbose)
        return {
            "wstg_id": "WSTG-INFO-05",
            "title": "Review Webpage Content for Information Leakage",
            "status": "error",
            "findings": [],
            "error": str(e)
        }

    # 1. HTML Comments
    log(f"\n{Fore.CYAN}[PHASE 1] HTML Comments{Style.RESET_ALL}", verbose)
    comments = extract_html_comments(html_content, verbose)
    findings.append({"category": "HTML Comments", "data": comments})

    # 2. Meta Tags
    log(f"\n{Fore.CYAN}[PHASE 2] Meta Tags{Style.RESET_ALL}", verbose)
    meta_tags = extract_meta_tags(html_content, verbose)
    findings.append({"category": "Meta Tags", "data": meta_tags})

    # 3. Sensitive Patterns
    log(f"\n{Fore.CYAN}[PHASE 3] Sensitive Patterns{Style.RESET_ALL}", verbose)
    sensitive = detect_sensitive_patterns(html_content, verbose)
    findings.append({"category": "Sensitive Patterns", "data": sensitive})

    # 4. JavaScript Analysis
    log(f"\n{Fore.CYAN}[PHASE 4] JavaScript Analysis{Style.RESET_ALL}", verbose)
    js_data = analyze_javascript(url, html_content, verbose)
    findings.append({"category": "JavaScript Analysis", "data": js_data})

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-05 selesai.{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-05",
        "title": "Review Webpage Content for Information Leakage",
        "status": "completed",
        "findings": findings,
        "error": None
    }
