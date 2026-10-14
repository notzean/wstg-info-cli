#!/usr/bin/env python3
"""
WSTG-INFO-10: Map Application Architecture
Identifikasi komponen arsitektur (web server, CDN, WAF, load balancer, reverse proxy)
dan generate Mermaid diagram arsitektur.
"""

import re
import socket
from urllib.parse import urlparse
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url, get_hostname


# ─── Web Server Detection ────────────────────────────────────────────────────

def detect_web_server(target_url, verbose):
    """Deteksi web server dari headers."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mendeteksi web server...", verbose)

    result = {"server": "Unknown", "details": {}}
    url = ensure_url(target_url)

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        headers = response.headers

        result["server"] = headers.get("Server", "Unknown")
        result["details"]["x_powered_by"] = headers.get("X-Powered-By", "N/A")
        result["details"]["x_aspnet_version"] = headers.get("X-AspNet-Version", "N/A")
        result["details"]["status_code"] = response.status_code

        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Web Server: {result['server']}", verbose)

    except Exception as e:
        result["error"] = str(e)

    return result


# ─── CDN Detection ────────────────────────────────────────────────────────────

def detect_cdn(target_url, verbose):
    """Deteksi CDN dari headers."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mendeteksi CDN...", verbose)

    url = ensure_url(target_url)
    cdn_detected = []

    cdn_indicators = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
        "Akamai": ["x-akamai-transformed", "x-akamai-staging"],
        "Fastly": ["x-fastly-request-id", "fastly-debug-digest"],
        "Google Cloud CDN": ["x-goog-hash", "x-guploader-uploadid"],
        "Azure CDN": ["x-azure-ref", "x-msedge-ref"],
        "KeyCDN": ["x-edge-location"],
        "StackPath": ["x-sp-url", "x-sp-wl"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Varnish": ["x-varnish", "via"],
    }

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        headers = {k.lower(): v for k, v in response.headers.items()}

        for cdn_name, indicator_headers in cdn_indicators.items():
            for header in indicator_headers:
                if header in headers:
                    cdn_detected.append({
                        "cdn": cdn_name,
                        "indicator": header,
                        "value": headers[header]
                    })
                    log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} CDN terdeteksi: {cdn_name} (via {header})", verbose)
                    break

        # Check Via header for proxy/CDN
        via = headers.get("via", "")
        if via and not any(d["cdn"] == "Varnish" for d in cdn_detected):
            cdn_detected.append({
                "cdn": "Proxy/CDN (Via header)",
                "indicator": "via",
                "value": via
            })

        # Check Server header untuk CDN indicators
        server = headers.get("server", "").lower()
        server_cdn_map = {
            "cloudflare": "Cloudflare",
            "cloudfront": "AWS CloudFront",
            "akamaighost": "Akamai",
            "netlify": "Netlify",
            "vercel": "Vercel",
        }
        for keyword, cdn_name in server_cdn_map.items():
            if keyword in server and not any(d["cdn"] == cdn_name for d in cdn_detected):
                cdn_detected.append({
                    "cdn": cdn_name,
                    "indicator": "server header",
                    "value": headers.get("server", "")
                })

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal deteksi CDN: {e}", verbose)

    if not cdn_detected:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Tidak ada CDN terdeteksi.", verbose)

    return cdn_detected


# ─── WAF Detection ────────────────────────────────────────────────────────────

def detect_waf(target_url, verbose):
    """Deteksi Web Application Firewall."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mendeteksi WAF...", verbose)

    url = ensure_url(target_url)
    waf_detected = []

    try:
        # Normal request
        response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        headers = {k.lower(): v for k, v in response.headers.items()}

        # WAF indicators di headers
        waf_headers = {
            "x-sucuri-id": "Sucuri WAF",
            "x-sucuri-cache": "Sucuri WAF",
            "x-cdn": "Incapsula/Imperva",
            "x-iinfo": "Incapsula/Imperva",
            "x-protected-by": "WAF Protection",
            "x-waf-event-info": "WAF",
        }

        for header, waf_name in waf_headers.items():
            if header in headers:
                waf_detected.append({
                    "waf": waf_name,
                    "indicator": header,
                    "value": headers[header]
                })

        # Cloudflare WAF
        if "cf-ray" in headers:
            waf_detected.append({
                "waf": "Cloudflare WAF",
                "indicator": "cf-ray",
                "value": headers["cf-ray"]
            })

        # Test with malicious-looking request
        try:
            test_url = url.rstrip("/") + "/?id=1' OR '1'='1"
            test_response = requests.get(test_url, timeout=10,
                                         headers={"User-Agent": USER_AGENT},
                                         allow_redirects=False)
            if test_response.status_code in [403, 406, 429, 503]:
                waf_detected.append({
                    "waf": "WAF Detected (blocked malicious request)",
                    "indicator": f"Status {test_response.status_code} on SQLi test",
                    "value": f"Status code: {test_response.status_code}"
                })
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} WAF blocking detected (status {test_response.status_code})", verbose)
        except Exception:
            pass

    except Exception as e:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal deteksi WAF: {e}", verbose)

    if not waf_detected:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Tidak ada WAF terdeteksi.", verbose)

    return waf_detected


# ─── Load Balancer Detection ─────────────────────────────────────────────────

def detect_load_balancer(target_url, verbose):
    """Deteksi load balancer via multiple requests."""
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mendeteksi load balancer...", verbose)

    url = ensure_url(target_url)
    servers_seen = set()
    lb_detected = []

    # Kirim beberapa request dan bandingkan headers
    for i in range(3):
        try:
            response = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
            server = response.headers.get("Server", "Unknown")
            servers_seen.add(server)

            # Check for LB indicators
            if "X-Served-By" in response.headers:
                lb_detected.append({
                    "indicator": "X-Served-By",
                    "value": response.headers["X-Served-By"]
                })
            if "X-Backend-Server" in response.headers:
                lb_detected.append({
                    "indicator": "X-Backend-Server",
                    "value": response.headers["X-Backend-Server"]
                })

        except Exception:
            continue

    if len(servers_seen) > 1:
        lb_detected.append({
            "indicator": "Multiple Server headers detected",
            "value": list(servers_seen)
        })

    return lb_detected


# ─── IP & DNS Architecture ───────────────────────────────────────────────────

def analyze_network_architecture(target_url, verbose):
    """Analisa arsitektur network (IP, DNS)."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Menganalisa arsitektur network...", verbose)

    hostname = get_hostname(target_url)
    arch_info = {}

    # Resolve IPs
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ipv4 = list(set(r[4][0] for r in addr_info if r[0] == socket.AF_INET))
        ipv6 = list(set(r[4][0] for r in addr_info if r[0] == socket.AF_INET6))

        arch_info["ipv4_addresses"] = ipv4
        arch_info["ipv6_addresses"] = ipv6
        arch_info["multiple_ips"] = len(ipv4) > 1

        if len(ipv4) > 1:
            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Multiple IPs detected (possible LB/CDN): {ipv4}", verbose)

    except Exception as e:
        arch_info["error"] = str(e)

    # Check HTTPS
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                arch_info["ssl_issuer"] = ""
                if cert and cert.get("issuer"):
                    for item in cert["issuer"]:
                        for key, val in item:
                            if key == "organizationName":
                                arch_info["ssl_issuer"] = val
                arch_info["ssl_enabled"] = True
    except Exception:
        arch_info["ssl_enabled"] = False

    return arch_info


# ─── Generate Architecture Mermaid Diagram ────────────────────────────────────

def generate_architecture_diagram(web_server, cdn_list, waf_list, lb_list, network_info, target_url):
    """Generate Mermaid diagram arsitektur."""
    hostname = get_hostname(target_url)
    lines = ["graph TD"]

    # Client
    lines.append('    CLIENT["🌐 Client/Browser"]')

    # DNS
    lines.append(f'    DNS["📡 DNS Resolution<br/>{hostname}"]')
    lines.append("    CLIENT --> DNS")

    # WAF layer
    if waf_list:
        waf_names = ", ".join(set(w["waf"] for w in waf_list))
        lines.append(f'    WAF["🛡️ WAF<br/>{waf_names}"]')
        lines.append("    DNS --> WAF")
        prev_node = "WAF"
    else:
        prev_node = "DNS"

    # CDN layer
    if cdn_list:
        cdn_names = ", ".join(set(c["cdn"] for c in cdn_list))
        lines.append(f'    CDN["⚡ CDN<br/>{cdn_names}"]')
        lines.append(f"    {prev_node} --> CDN")
        prev_node = "CDN"

    # Load Balancer
    if lb_list:
        lines.append('    LB["⚖️ Load Balancer"]')
        lines.append(f"    {prev_node} --> LB")
        prev_node = "LB"

    # Web Server
    server_name = web_server.get("server", "Unknown")
    lines.append(f'    WEB["🖥️ Web Server<br/>{server_name}"]')
    lines.append(f"    {prev_node} --> WEB")

    # Application layer
    powered_by = web_server.get("details", {}).get("x_powered_by", "")
    if powered_by and powered_by != "N/A":
        lines.append(f'    APP["⚙️ Application<br/>{powered_by}"]')
        lines.append("    WEB --> APP")
    else:
        lines.append('    APP["⚙️ Application"]')
        lines.append("    WEB --> APP")

    # Database (generic)
    lines.append('    DB["🗄️ Database"]')
    lines.append("    APP --> DB")

    # SSL info
    if network_info.get("ssl_enabled"):
        ssl_issuer = network_info.get("ssl_issuer", "Unknown CA")
        lines.append(f'    SSL["🔒 SSL/TLS<br/>CA: {ssl_issuer}"]')
        lines.append("    CLIENT -.-> SSL")

    # IP addresses
    ipv4_list = network_info.get("ipv4_addresses", [])
    if ipv4_list:
        ip_text = "<br/>".join(ipv4_list[:4])
        lines.append(f'    IPS["📍 IP Addresses<br/>{ip_text}"]')
        lines.append("    WEB -.-> IPS")

    mermaid_text = "\n".join(lines)
    return mermaid_text


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-10.
    Returns dict dengan Mermaid diagram arsitektur di findings.
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-10: Map Application Architecture", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    findings = []

    # 1. Web Server Detection
    log(f"\n{Fore.CYAN}[PHASE 1] Web Server Detection{Style.RESET_ALL}", verbose)
    web_server = detect_web_server(target_url, verbose)
    findings.append({"category": "Web Server", "data": web_server})

    # 2. CDN Detection
    log(f"\n{Fore.CYAN}[PHASE 2] CDN Detection{Style.RESET_ALL}", verbose)
    cdn_list = detect_cdn(target_url, verbose)
    findings.append({"category": "CDN", "data": cdn_list})

    # 3. WAF Detection
    log(f"\n{Fore.CYAN}[PHASE 3] WAF Detection{Style.RESET_ALL}", verbose)
    waf_list = detect_waf(target_url, verbose)
    findings.append({"category": "WAF", "data": waf_list})

    # 4. Load Balancer Detection
    log(f"\n{Fore.CYAN}[PHASE 4] Load Balancer Detection{Style.RESET_ALL}", verbose)
    lb_list = detect_load_balancer(target_url, verbose)
    findings.append({"category": "Load Balancer", "data": lb_list})

    # 5. Network Architecture
    log(f"\n{Fore.CYAN}[PHASE 5] Network Architecture{Style.RESET_ALL}", verbose)
    network_info = analyze_network_architecture(target_url, verbose)
    findings.append({"category": "Network Architecture", "data": network_info})

    # 6. Generate Mermaid Diagram
    log(f"\n{Fore.CYAN}[PHASE 6] Generating Architecture Diagram{Style.RESET_ALL}", verbose)
    mermaid = generate_architecture_diagram(web_server, cdn_list, waf_list, lb_list, network_info, target_url)
    findings.append({
        "category": "Architecture Diagram (Mermaid)",
        "data": mermaid
    })
    log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Mermaid architecture diagram berhasil di-generate.", verbose)

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-10 selesai.{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-10",
        "title": "Map Application Architecture",
        "status": "completed",
        "findings": findings,
        "error": None
    }
