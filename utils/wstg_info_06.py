#!/usr/bin/env python3
"""
WSTG-INFO-06: Identify Application Entry Points
Crawl target untuk mengidentifikasi forms, URL parameters, AJAX endpoints, dan HTTP methods.
Max depth: 2, max URLs: 20.
"""

import re
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url, is_same_domain
MAX_DEPTH = 2
MAX_URLS = 20


# ─── Crawl & Extract Links ────────────────────────────────────────────────────

def crawl_for_entries(target_url, verbose):
    """Crawl website dan kumpulkan semua links, forms, dan parameters."""
    import requests
    from bs4 import BeautifulSoup

    base_url = ensure_url(target_url)
    visited = set()
    queue = [(base_url, 0)]
    all_links = []
    all_forms = []
    all_params = []

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memulai crawling (max depth: {MAX_DEPTH}, max URLs: {MAX_URLS})...", verbose)

    while queue and len(visited) < MAX_URLS:
        current_url, depth = queue.pop(0)

        if current_url in visited or depth > MAX_DEPTH:
            continue

        visited.add(current_url)
        log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} [{len(visited)}/{MAX_URLS}] Crawling: {Fore.YELLOW}{current_url}{Style.RESET_ALL}", verbose)

        try:
            response = requests.get(current_url, timeout=10,
                                    headers={"User-Agent": USER_AGENT},
                                    allow_redirects=True)
            if response.status_code != 200:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract links
            for link in soup.find_all("a", href=True):
                href = link.get("href", "")
                absolute_url = urljoin(current_url, href)
                clean_url = absolute_url.split("#")[0]

                if is_same_domain(base_url, clean_url) and clean_url not in visited:
                    all_links.append({
                        "url": clean_url,
                        "text": (link.get_text(strip=True) or "")[:100],
                        "found_on": current_url
                    })
                    if depth + 1 <= MAX_DEPTH:
                        queue.append((clean_url, depth + 1))

                # Extract URL parameters
                parsed = urlparse(clean_url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, param_values in params.items():
                        all_params.append({
                            "url": clean_url,
                            "parameter": param_name,
                            "sample_value": param_values[0] if param_values else "",
                            "method": "GET"
                        })

            # Extract forms
            for form in soup.find_all("form"):
                form_action = form.get("action", current_url)
                form_method = form.get("method", "GET").upper()
                form_url = urljoin(current_url, form_action)
                form_enctype = form.get("enctype", "application/x-www-form-urlencoded")

                form_inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inp_name = inp.get("name", "")
                    inp_type = inp.get("type", "text")
                    inp_value = inp.get("value", "")
                    if inp_name:
                        form_inputs.append({
                            "name": inp_name,
                            "type": inp_type,
                            "value": inp_value[:50]
                        })

                all_forms.append({
                    "action": form_url,
                    "method": form_method,
                    "enctype": form_enctype,
                    "found_on": current_url,
                    "inputs": form_inputs
                })
                log(f"    {Fore.GREEN}[FORM]{Style.RESET_ALL} {form_method} {form_url} "
                     f"({len(form_inputs)} inputs)", verbose)

        except Exception as e:
            log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal crawl {current_url}: {e}", verbose)
            continue

    return all_links, all_forms, all_params, list(visited)


# ─── HTTP Methods Detection ──────────────────────────────────────────────────

def detect_http_methods(target_url, verbose):
    """Cek HTTP methods yang diterima oleh server."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memeriksa HTTP methods...", verbose)

    url = ensure_url(target_url)
    methods_result = {}

    # OPTIONS request
    try:
        response = requests.options(url, timeout=10, headers={"User-Agent": USER_AGENT})
        allow = response.headers.get("Allow", "Not disclosed")
        methods_result["options_allow"] = allow
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} OPTIONS Allow: {allow}", verbose)
    except Exception as e:
        methods_result["options_error"] = str(e)

    # Test each method
    test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    methods_result["tested"] = {}

    for method in test_methods:
        try:
            response = requests.request(method, url, timeout=10,
                                        headers={"User-Agent": USER_AGENT},
                                        allow_redirects=False)
            methods_result["tested"][method] = {
                "status_code": response.status_code,
                "allowed": response.status_code not in [405, 501]
            }
        except Exception:
            methods_result["tested"][method] = {"status_code": "Error", "allowed": False}

    return methods_result


# ─── AJAX/API Endpoint Detection ──────────────────────────────────────────────

def detect_ajax_endpoints(html_content, verbose):
    """Cari AJAX/API endpoints di JavaScript code."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mencari AJAX/API endpoints...", verbose)

    patterns = [
        r"""(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post|\.put|\.delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""(?:url|endpoint|api_url|apiUrl|baseUrl|base_url)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
        r"""\/api\/[a-zA-Z0-9_\/\-]+""",
        r"""\/v[0-9]+\/[a-zA-Z0-9_\/\-]+""",
    ]

    endpoints = set()
    for pattern in patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            if len(match) > 3 and not match.endswith((".css", ".png", ".jpg", ".gif", ".ico")):
                endpoints.add(match)

    result = list(endpoints)[:30]
    log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan {len(result)} potential AJAX/API endpoints.", verbose)
    return result


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-06.
    Returns dict: wstg_id, title, status, findings, error
    """
    import requests

    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-06: Identify Application Entry Points", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    findings = []

    # 1. Crawl & collect entry points
    log(f"\n{Fore.CYAN}[PHASE 1] Crawling & Extracting Entry Points{Style.RESET_ALL}", verbose)
    links, forms, params, visited = crawl_for_entries(target_url, verbose)
    findings.append({"category": "Discovered Links", "data": links[:50]})
    findings.append({"category": "Forms", "data": forms})
    findings.append({"category": "URL Parameters", "data": params})
    findings.append({"category": "Crawled URLs", "data": visited})

    # 2. HTTP Methods
    log(f"\n{Fore.CYAN}[PHASE 2] HTTP Methods Detection{Style.RESET_ALL}", verbose)
    methods = detect_http_methods(target_url, verbose)
    findings.append({"category": "HTTP Methods", "data": methods})

    # 3. AJAX/API Endpoints
    log(f"\n{Fore.CYAN}[PHASE 3] AJAX/API Endpoint Detection{Style.RESET_ALL}", verbose)
    try:
        url = ensure_url(target_url)
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        ajax_endpoints = detect_ajax_endpoints(response.text, verbose)
    except Exception:
        ajax_endpoints = []
    findings.append({"category": "AJAX/API Endpoints", "data": ajax_endpoints})

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-06 selesai. Links: {len(links)}, Forms: {len(forms)}, Params: {len(params)}{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-06",
        "title": "Identify Application Entry Points",
        "status": "completed",
        "findings": findings,
        "error": None
    }
