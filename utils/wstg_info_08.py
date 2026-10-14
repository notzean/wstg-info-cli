#!/usr/bin/env python3
"""
WSTG-INFO-08: Fingerprint Web Application Framework
+ WSTG-INFO-09: Fingerprint Web Application (merged sesuai deskripsi resmi OWASP)

Deteksi framework, CMS, dan teknologi dari HTML patterns, cookies, headers, dan file-specific checks.
"""

import re
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url


# ─── Framework Detection via HTML ─────────────────────────────────────────────

def detect_framework_html(html_content, verbose):
    """Deteksi framework/CMS dari patterns di HTML."""
    from bs4 import BeautifulSoup

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa HTML untuk deteksi framework...", verbose)

    detected = []
    soup = BeautifulSoup(html_content, "html.parser")

    # Generator meta tag
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        gen_content = generator["content"]
        detected.append({
            "technology": gen_content,
            "source": "meta generator",
            "confidence": "high"
        })
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Generator: {gen_content}", verbose)

    # HTML pattern signatures
    html_signatures = {
        "WordPress": [
            lambda s: s.find("script", src=lambda x: x and "wp-content" in x),
            lambda s: s.find("link", href=lambda x: x and "wp-content" in x),
            lambda s: s.find("meta", attrs={"name": "generator", "content": re.compile(r"WordPress", re.I)}),
        ],
        "Joomla": [
            lambda s: s.find("meta", attrs={"name": "generator", "content": re.compile(r"Joomla", re.I)}),
            lambda s: s.find("script", src=lambda x: x and "/media/jui/" in x),
        ],
        "Drupal": [
            lambda s: s.find("meta", attrs={"name": "generator", "content": re.compile(r"Drupal", re.I)}),
            lambda s: s.find("link", href=lambda x: x and "sites/all/themes" in x),
            lambda s: s.find("script", src=lambda x: x and "drupal.js" in str(x).lower()),
        ],
        "Laravel": [
            lambda s: "laravel" in html_content.lower(),
            lambda s: s.find("meta", attrs={"name": "csrf-token"}),
        ],
        "Django": [
            lambda s: s.find("input", attrs={"name": "csrfmiddlewaretoken"}),
        ],
        "React": [
            lambda s: s.find("div", id="root") or s.find("div", id="app"),
            lambda s: s.find("script", src=lambda x: x and "react" in str(x).lower()),
        ],
        "Angular": [
            lambda s: s.find(attrs={"ng-app": True}) or s.find(attrs={"ng-controller": True}),
            lambda s: s.find("script", src=lambda x: x and "angular" in str(x).lower()),
        ],
        "Vue.js": [
            lambda s: s.find(attrs={"v-app": True}) or s.find(attrs={"v-cloak": True}),
            lambda s: s.find("script", src=lambda x: x and "vue" in str(x).lower()),
            lambda s: s.find("div", id="app"),
        ],
        "jQuery": [
            lambda s: s.find("script", src=lambda x: x and "jquery" in str(x).lower()),
        ],
        "Bootstrap": [
            lambda s: s.find("link", href=lambda x: x and "bootstrap" in str(x).lower()),
            lambda s: s.find("script", src=lambda x: x and "bootstrap" in str(x).lower()),
        ],
        "Next.js": [
            lambda s: s.find("script", id="__NEXT_DATA__"),
            lambda s: "__next" in html_content,
        ],
        "Nuxt.js": [
            lambda s: s.find("script", string=lambda x: x and "__nuxt" in str(x)),
            lambda s: "__nuxt" in html_content,
        ],
    }

    already_detected = set()
    for framework, checks in html_signatures.items():
        for check in checks:
            try:
                if check(soup):
                    if framework not in already_detected:
                        detected.append({
                            "technology": framework,
                            "source": "HTML pattern",
                            "confidence": "medium"
                        })
                        already_detected.add(framework)
                        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Terdeteksi: {framework}", verbose)
                    break
            except Exception:
                continue

    return detected


# ─── Framework Detection via Headers ──────────────────────────────────────────

def detect_framework_headers(target_url, verbose):
    """Deteksi framework dari HTTP response headers."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa HTTP headers untuk deteksi framework...", verbose)

    detected = []
    url = ensure_url(target_url)

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT},
                                allow_redirects=True)
        headers = response.headers

        # Server header
        server = headers.get("Server", "")
        if server:
            detected.append({
                "technology": server,
                "source": "Server header",
                "confidence": "high"
            })

        # X-Powered-By
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            detected.append({
                "technology": powered_by,
                "source": "X-Powered-By header",
                "confidence": "high"
            })

        # X-Generator
        x_gen = headers.get("X-Generator", "")
        if x_gen:
            detected.append({
                "technology": x_gen,
                "source": "X-Generator header",
                "confidence": "high"
            })

        # Framework-specific headers
        header_indicators = {
            "X-Drupal-Cache": "Drupal",
            "X-Drupal-Dynamic-Cache": "Drupal",
            "X-Pingback": "WordPress",
            "X-Redirect-By": "WordPress",
            "X-AspNet-Version": "ASP.NET",
            "X-AspNetMvc-Version": "ASP.NET MVC",
        }

        for header_name, framework in header_indicators.items():
            if header_name in headers:
                detected.append({
                    "technology": f"{framework} ({headers[header_name]})",
                    "source": f"{header_name} header",
                    "confidence": "high"
                })

        # All response headers untuk referensi
        all_headers = dict(headers)

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal analisa headers: {e}", verbose)
        all_headers = {"error": str(e)}

    return detected, all_headers


# ─── Cookie-based Detection ───────────────────────────────────────────────────

def detect_framework_cookies(target_url, verbose):
    """Deteksi framework dari nama cookie."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa cookies untuk deteksi framework...", verbose)

    detected = []
    url = ensure_url(target_url)

    cookie_signatures = {
        "JSESSIONID": "Java (Tomcat/Spring)",
        "ASP.NET_SessionId": "ASP.NET",
        "PHPSESSID": "PHP",
        "laravel_session": "Laravel",
        "csrftoken": "Django",
        "django_language": "Django",
        "_rails_session": "Ruby on Rails",
        "rack.session": "Ruby (Rack)",
        "connect.sid": "Node.js (Express)",
        "ci_session": "CodeIgniter",
        "cakephp": "CakePHP",
        "symfony": "Symfony",
        "wp-settings": "WordPress",
    }

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT},
                                allow_redirects=True)

        cookies = response.cookies
        set_cookie_header = response.headers.get("Set-Cookie", "")

        for cookie_name, framework in cookie_signatures.items():
            # Check cookies jar
            if cookie_name in cookies:
                detected.append({
                    "technology": framework,
                    "source": f"Cookie: {cookie_name}",
                    "confidence": "high"
                })
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Cookie '{cookie_name}' -> {framework}", verbose)

            # Check Set-Cookie header
            if cookie_name.lower() in set_cookie_header.lower():
                if not any(d["technology"] == framework for d in detected):
                    detected.append({
                        "technology": framework,
                        "source": f"Set-Cookie header: {cookie_name}",
                        "confidence": "high"
                    })

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal analisa cookies: {e}", verbose)

    return detected


# ─── File/Path-based Detection ────────────────────────────────────────────────

def detect_framework_files(target_url, verbose):
    """Deteksi framework dengan mengecek file/path spesifik."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mengecek file/path framework-specific...", verbose)

    detected = []
    url = ensure_url(target_url).rstrip("/")

    path_checks = [
        ("/wp-login.php", "WordPress"),
        ("/wp-admin/", "WordPress"),
        ("/wp-json/wp/v2/", "WordPress REST API"),
        ("/administrator/", "Joomla"),
        ("/user/login", "Drupal"),
        ("/admin/login", "Django Admin"),
        ("/elmah.axd", "ASP.NET (ELMAH)"),
        ("/web.config", "ASP.NET"),
        ("/phpinfo.php", "PHP"),
        ("/server-status", "Apache"),
        ("/server-info", "Apache"),
        ("/.env", "Laravel/Node.js (.env exposed!)"),
        ("/package.json", "Node.js (package.json exposed!)"),
        ("/composer.json", "PHP Composer (exposed!)"),
    ]

    for path, framework in path_checks:
        try:
            check_url = url + path
            response = requests.get(check_url, timeout=10,
                                    headers={"User-Agent": USER_AGENT},
                                    allow_redirects=False)
            if response.status_code == 200:
                detected.append({
                    "technology": framework,
                    "source": f"Path exists: {path}",
                    "confidence": "medium",
                    "status_code": response.status_code
                })
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Ditemukan: {path} -> {framework}", verbose)
        except Exception:
            continue

    return detected


# ─── Version Detection ────────────────────────────────────────────────────────

def detect_version(html_content, detected_techs, verbose):
    """Coba deteksi versi dari teknologi yang ditemukan."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mencari informasi versi...", verbose)

    versions = []

    # Patterns version umum
    version_patterns = [
        (r'WordPress\s+([\d.]+)', "WordPress"),
        (r'Joomla!\s+([\d.]+)', "Joomla"),
        (r'Drupal\s+([\d.]+)', "Drupal"),
        (r'jQuery\s+v?([\d.]+)', "jQuery"),
        (r'Bootstrap\s+v?([\d.]+)', "Bootstrap"),
        (r'React\s+v?([\d.]+)', "React"),
        (r'Angular\s+v?([\d.]+)', "Angular"),
        (r'Vue\.js\s+v?([\d.]+)', "Vue.js"),
        (r'Laravel\s+v?([\d.]+)', "Laravel"),
    ]

    for pattern, tech in version_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        if matches:
            versions.append({
                "technology": tech,
                "version": matches[0],
                "confidence": "high"
            })
            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {tech} version: {matches[0]}", verbose)

    return versions


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-08 (+ merged WSTG-INFO-09).
    Returns dict: wstg_id, title, status, findings, error
    """
    import requests

    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-08: Fingerprint Web Application Framework", verbose)
    log(f"  (Includes WSTG-INFO-09: Fingerprint Web Application)", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    findings = []
    all_detected = []

    # Fetch halaman utama
    url = ensure_url(target_url)
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        html_content = response.text
    except Exception as e:
        return {
            "wstg_id": "WSTG-INFO-08",
            "title": "Fingerprint Web Application Framework",
            "status": "error",
            "findings": [],
            "error": str(e)
        }

    # 1. HTML-based Detection
    log(f"\n{Fore.CYAN}[PHASE 1] HTML Pattern Analysis{Style.RESET_ALL}", verbose)
    html_techs = detect_framework_html(html_content, verbose)
    all_detected.extend(html_techs)
    findings.append({"category": "HTML-based Detection", "data": html_techs})

    # 2. Header-based Detection
    log(f"\n{Fore.CYAN}[PHASE 2] HTTP Header Analysis{Style.RESET_ALL}", verbose)
    header_techs, all_headers = detect_framework_headers(target_url, verbose)
    all_detected.extend(header_techs)
    findings.append({"category": "Header-based Detection", "data": header_techs})

    # 3. Cookie-based Detection
    log(f"\n{Fore.CYAN}[PHASE 3] Cookie Analysis{Style.RESET_ALL}", verbose)
    cookie_techs = detect_framework_cookies(target_url, verbose)
    all_detected.extend(cookie_techs)
    findings.append({"category": "Cookie-based Detection", "data": cookie_techs})

    # 4. File/Path-based Detection
    log(f"\n{Fore.CYAN}[PHASE 4] File/Path Check{Style.RESET_ALL}", verbose)
    file_techs = detect_framework_files(target_url, verbose)
    all_detected.extend(file_techs)
    findings.append({"category": "File/Path-based Detection", "data": file_techs})

    # 5. Version Detection
    log(f"\n{Fore.CYAN}[PHASE 5] Version Detection{Style.RESET_ALL}", verbose)
    versions = detect_version(html_content, all_detected, verbose)
    findings.append({"category": "Version Information", "data": versions})

    # Summary: deduplicate
    unique_techs = []
    seen = set()
    for tech in all_detected:
        name = tech["technology"]
        if name not in seen:
            seen.add(name)
            unique_techs.append(tech)

    findings.append({"category": "Technology Summary", "data": unique_techs})

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-08 selesai. Teknologi terdeteksi: {len(unique_techs)}{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-08",
        "title": "Fingerprint Web Application Framework",
        "status": "completed",
        "findings": findings,
        "error": None
    }
