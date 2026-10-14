#!/usr/bin/env python3
"""
WSTG-INFO-09: Fingerprint Web Application
Di-merge ke WSTG-INFO-08 sesuai deskripsi resmi OWASP.
Modul ini mendelegasikan ke wstg_info_08.run() dan mengubah wstg_id.
"""

from colorama import Fore, Style
from utils import wstg_info_08


from utils.helper import log


def run(target_url, verbose=False):
    """
    Fungsi utama WSTG-INFO-09.
    Delegasi ke WSTG-INFO-08 karena sudah di-merge sesuai deskripsi resmi OWASP.
    """
    log(f"\n{Fore.BLUE}{'='*60}", verbose)
    log(f"  WSTG-INFO-09: Fingerprint Web Application", verbose)
    log(f"  (Merged with WSTG-INFO-08 — delegating...)", verbose)
    log(f"{'='*60}{Style.RESET_ALL}", verbose)

    # Delegasi ke WSTG-INFO-08
    result = wstg_info_08.run(target_url, verbose=verbose)

    # Override identitas
    result["wstg_id"] = "WSTG-INFO-09"
    result["title"] = "Fingerprint Web Application"
    result["note"] = "Merged with WSTG-INFO-08 (Fingerprint Web Application Framework) sesuai referensi resmi OWASP."

    log(f"\n{Fore.GREEN}[*] WSTG-INFO-09 selesai (delegasi ke WSTG-INFO-08).{Style.RESET_ALL}", verbose)

    return result
