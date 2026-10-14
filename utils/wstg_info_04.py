#!/usr/bin/env python3
"""
WSTG-INFO-04: Enumerate Applications on Webserver
DNS resolution menggunakan dnspython, subdomain brute-force, virtual host check, dan port scanning.
"""

import socket
from urllib.parse import urlparse
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, extract_domain


# ─── DNS Records ──────────────────────────────────────────────────────────────

def dns_enumeration(domain, verbose):
    """Resolusi DNS lokal menggunakan dnspython."""
    import dns.resolver

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Enumerasi DNS records untuk: {Fore.YELLOW}{domain}{Style.RESET_ALL}", verbose)

    dns_results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            dns_results[rtype] = records
            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {rtype}: {', '.join(records[:5])}", verbose)
        except dns.resolver.NoAnswer:
            dns_results[rtype] = []
        except dns.resolver.NXDOMAIN:
            log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Domain '{domain}' tidak ditemukan.", verbose)
            dns_results["error"] = f"Domain '{domain}' tidak ditemukan (NXDOMAIN)"
            break
        except Exception as e:
            dns_results[rtype] = []

    return dns_results


# ─── Subdomain Enumeration ────────────────────────────────────────────────────

def enumerate_subdomains(domain, verbose):
    """Brute-force subdomain umum via DNS dan enumerate via bgp.he.net."""
    import dns.resolver
    import requests

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mencari subdomain via bgp.he.net dan brute-force...", verbose)

    subdomains_to_check = set([
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "admin", "portal", "api", "dev", "staging", "test", "beta",
        "blog", "shop", "store", "app", "mobile", "m", "cdn",
        "static", "media", "assets", "img", "images", "ns1", "ns2",
        "dns", "vpn", "remote", "git", "gitlab", "jenkins", "ci",
        "db", "database", "mysql", "postgres", "redis", "elastic",
        "monitor", "grafana", "kibana", "prometheus", "sentry",
        "docs", "wiki", "support", "help", "status", "dashboard",
        "backup", "server", "stream"
    ])

    # Enumerate from bgp.he.net certificates API
    try:
        cert_url = f"https://bgp.he.net/certs/api/domain?domain={domain}"
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
        response = requests.get(cert_url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            certs = data.get("certificates", [])
            for c in certs:
                sans = c.get("subject_alternative_names", [])
                for san in sans:
                    val = san.get("value", "").strip().lower()
                    if val.startswith("*."):
                        val = val[2:]  # Hapus wildcard di depan
                    
                    if val.endswith(f".{domain}"):
                        prefix = val.replace(f".{domain}", "")
                        if prefix:  # Pastikan bukan string kosong
                            subdomains_to_check.add(prefix)
    except Exception as e:
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} bgp.he.net lookup gagal atau timeout: {e}", verbose)

    found_subdomains = []
    for sub in sorted(list(subdomains_to_check)):
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, "A")
            ips = [str(r) for r in answers]
            found_subdomains.append({
                "subdomain": subdomain,
                "ip_addresses": ips
            })
            log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {subdomain} -> {', '.join(ips)}", verbose)
        except Exception:
            continue

    log(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Ditemukan {len(found_subdomains)} subdomain aktif.", verbose)
    return found_subdomains


# ─── Port Scanning ────────────────────────────────────────────────────────────

def scan_common_ports(domain, verbose):
    """Scan port umum web application."""
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Scanning port umum...", verbose)

    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        8000: "HTTP-Dev",
        8888: "HTTP-Proxy",
        3000: "Node.js/Dev",
        5000: "Flask/Dev",
        9090: "Prometheus",
        9200: "Elasticsearch",
    }

    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Tidak dapat resolve domain.", verbose)
        return open_ports

    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "status": "open"})
                log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Port {port}/{service}: OPEN", verbose)
            sock.close()
        except Exception:
            pass

    return open_ports


# ─── Virtual Host Detection ──────────────────────────────────────────────────

def check_virtual_hosts(target_url, verbose):
    """Cek virtual hosts dengan mengirim request dengan Host header berbeda."""
    import requests
    from utils.helper import extract_domain

    domain = extract_domain(target_url)
    protocol = "https" if target_url.startswith("https") else "http"
    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memeriksa virtual hosts...", verbose)

    vhost_results = []
    test_hosts = [
        domain,
        f"www.{domain}",
        f"admin.{domain}",
        f"api.{domain}",
        f"dev.{domain}",
    ]

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return vhost_results

    base_url = f"{protocol}://{ip}"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for host in test_hosts:
        try:
            response = requests.get(
                base_url, timeout=10,
                headers={"Host": host, "User-Agent": USER_AGENT},
                allow_redirects=False,
                verify=False
            )
            vhost_results.append({
                "host_header": host,
                "status_code": response.status_code,
                "content_length": len(response.text),
                "redirect": response.headers.get("Location", "N/A")
            })
        except Exception:
            continue

    return vhost_results


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-04.
    Returns dict: wstg_id, title, status, findings, error
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-04: Enumerate Applications on Webserver", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    domain = extract_domain(target_url)
    findings = []

    # 1. DNS Enumeration
    log(f"\n{Fore.CYAN}[PHASE 1] DNS Enumeration{Style.RESET_ALL}", verbose)
    dns_data = dns_enumeration(domain, verbose)
    findings.append({"category": "DNS Records", "data": dns_data})

    # 2. Subdomain Enumeration
    log(f"\n{Fore.CYAN}[PHASE 2] Subdomain Enumeration{Style.RESET_ALL}", verbose)
    subdomains = enumerate_subdomains(domain, verbose)
    findings.append({"category": "Subdomain Enumeration", "data": subdomains})

    # 3. Port Scanning
    log(f"\n{Fore.CYAN}[PHASE 3] Port Scanning{Style.RESET_ALL}", verbose)
    ports = scan_common_ports(domain, verbose)
    findings.append({"category": "Open Ports", "data": ports})

    # 4. Virtual Host Detection
    log(f"\n{Fore.CYAN}[PHASE 4] Virtual Host Detection{Style.RESET_ALL}", verbose)
    vhosts = check_virtual_hosts(target_url, verbose)
    findings.append({"category": "Virtual Hosts", "data": vhosts})

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-04 selesai.{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-04",
        "title": "Enumerate Applications on Webserver",
        "status": "completed",
        "findings": findings,
        "error": None
    }
