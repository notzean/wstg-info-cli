#!/usr/bin/env python3
"""
WSTG-INFO-07: Map Execution Paths Through Application
Crawl website dan buat Mermaid diagram dari navigasi/flow yang ditemukan.
Max depth: 2, max URLs: 20.
"""

import re
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from utils.helper import USER_AGENT, log, ensure_url, is_same_domain
MAX_DEPTH = 2
MAX_URLS = 20


def sanitize_label(url, base_domain):
    """Buat label pendek untuk Mermaid node."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path == "/":
        return "Home (/)"
    # Ambil path terakhir yang bermakna
    parts = [p for p in path.split("/") if p]
    if parts:
        label = "/" + "/".join(parts[-2:]) if len(parts) > 1 else "/" + parts[0]
    else:
        label = path
    return label[:40]


def make_node_id(url):
    """Buat ID node yang valid untuk Mermaid."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    # Sanitize path menjadi valid node id
    node_id = re.sub(r"[^a-zA-Z0-9]", "_", path)
    node_id = node_id.strip("_") or "root"
    return node_id


# ─── Crawl & Build Graph ──────────────────────────────────────────────────────

def crawl_and_build_graph(target_url, verbose):
    """Crawl website dan bangun graph adjacency list menggunakan requests + BeautifulSoup."""
    import requests
    from bs4 import BeautifulSoup

    base_url = ensure_url(target_url)
    visited = set()
    edges = []  # list of (from_url, to_url)
    node_info = {}  # url -> {status, title, forms_count}
    queue = [(base_url, 0)]

    log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Crawling untuk mapping execution paths...", verbose)

    while queue and len(visited) < MAX_URLS:
        current_url, depth = queue.pop(0)

        if current_url in visited or depth > MAX_DEPTH:
            continue

        visited.add(current_url)
        log(f"  {Fore.CYAN}[*]{Style.RESET_ALL} [{len(visited)+1}/{MAX_URLS}] Mapping: {Fore.YELLOW}{current_url}{Style.RESET_ALL}", verbose)

        try:
            response = requests.get(current_url, timeout=10,
                                    headers={"User-Agent": USER_AGENT},
                                    allow_redirects=True)
            status_code = response.status_code
            if status_code != 200:
                node_info[current_url] = {"status": status_code, "title": "", "forms": 0, "depth": depth}
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            
            title_tag = soup.find("title")
            title = (title_tag.string.strip() if title_tag and title_tag.string else "")[:60]
            
            forms = soup.find_all("form")
            forms_count = len(forms)

            node_info[current_url] = {
                "status": status_code,
                "title": title,
                "forms": forms_count,
                "depth": depth
            }

            # Extract links
            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(current_url, link.get("href", "")).split("#")[0]
                if is_same_domain(base_url, absolute_url):
                    edges.append((current_url, absolute_url))
                    if absolute_url not in visited and depth + 1 <= MAX_DEPTH:
                        queue.append((absolute_url, depth + 1))
            
            # Form actions sebagai edges
            for form in forms:
                form_action = form.get("action", current_url)
                form_url = urljoin(current_url, form_action).split("#")[0]
                if is_same_domain(base_url, form_url):
                    edges.append((current_url, form_url))

        except Exception as e:
            log(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal crawl {current_url}: {e}", verbose)
            node_info[current_url] = {"status": "Error", "title": str(e), "forms": 0, "depth": depth}
            continue

    return edges, node_info, list(visited)


# ─── Generate Mermaid Diagram ─────────────────────────────────────────────────

def generate_mermaid_diagram(edges, node_info, target_url):
    """Generate Mermaid graph TD diagram dari edges."""
    base_domain = urlparse(ensure_url(target_url)).netloc

    # Deduplicate edges
    unique_edges = list(set(edges))

    # Collect all nodes
    all_nodes = set()
    for src, dst in unique_edges:
        all_nodes.add(src)
        all_nodes.add(dst)

    # Build Mermaid
    lines = ["graph TD"]

    # Node definitions with labels
    node_ids = {}
    counter = 0
    for url in sorted(all_nodes):
        node_id = f"N{counter}"
        node_ids[url] = node_id
        label = sanitize_label(url, base_domain)
        info = node_info.get(url, {})
        forms = info.get("forms", 0)

        if forms > 0:
            # Node dengan form (ditandai khusus)
            lines.append(f'    {node_id}["{label} [FORM]"]')
        else:
            lines.append(f'    {node_id}["{label}"]')
        counter += 1

    # Edges
    added_edges = set()
    for src, dst in unique_edges:
        src_id = node_ids.get(src)
        dst_id = node_ids.get(dst)
        if src_id and dst_id and src_id != dst_id:
            edge_key = (src_id, dst_id)
            if edge_key not in added_edges:
                lines.append(f"    {src_id} --> {dst_id}")
                added_edges.add(edge_key)

    # Limit diagram complexity
    if len(lines) > 100:
        lines = lines[:100]
        lines.append("    %% Diagram dipotong (terlalu banyak nodes)")

    mermaid_text = "\n".join(lines)
    return mermaid_text


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-07.
    Returns dict dengan Mermaid diagram di findings.
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-07: Map Execution Paths Through Application", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    findings = []

    # 1. Crawl & Build Graph
    log(f"\n{Fore.CYAN}[PHASE 1] Crawling & Building Graph{Style.RESET_ALL}", verbose)
    edges, node_info, visited = crawl_and_build_graph(target_url, verbose)

    findings.append({
        "category": "Visited URLs",
        "data": visited
    })
    findings.append({
        "category": "Page Details",
        "data": {url: info for url, info in node_info.items()}
    })
    findings.append({
        "category": "Link Connections",
        "data": [{"from": src, "to": dst} for src, dst in list(set(edges))[:50]]
    })

    # 2. Generate Mermaid Diagram
    log(f"\n{Fore.CYAN}[PHASE 2] Generating Mermaid Diagram{Style.RESET_ALL}", verbose)
    if edges:
        mermaid = generate_mermaid_diagram(edges, node_info, target_url)
        findings.append({
            "category": "Execution Path Diagram (Mermaid)",
            "data": mermaid
        })
        log(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Mermaid diagram berhasil di-generate ({len(visited)} nodes)", verbose)
    else:
        findings.append({
            "category": "Execution Path Diagram (Mermaid)",
            "data": "graph TD\n    A[\"Target\"] --> B[\"No paths discovered\"]"
        })
        log(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Tidak ada execution paths ditemukan.", verbose)

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-07 selesai. Total pages: {len(visited)}, Edges: {len(set(edges))}{Style.RESET_ALL}", verbose)

    return {
        "wstg_id": "WSTG-INFO-07",
        "title": "Map Execution Paths Through Application",
        "status": "completed",
        "findings": findings,
        "error": None
    }
