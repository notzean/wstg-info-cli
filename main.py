#!/usr/bin/env python3
import argparse
import sys
import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init
from utils import (
    wstg_info_01, wstg_info_02, wstg_info_03, wstg_info_04,
    wstg_info_05, wstg_info_06, wstg_info_07, wstg_info_08,
    wstg_info_09, wstg_info_10
)
import report

init(autoreset=True)

def main():
    custom_usage = (
        "python main.py -u <target_url> [-v]\n\n"
        "Contoh penggunaan:\n"
        "  python main.py -u https://example.com\n"
        "  python main.py -u https://example.com -v"
    )
    parser = argparse.ArgumentParser(
        description="WSTG-INFO Automation CLI v1.0\nAlat otomatisasi pengumpulan informasi berdasarkan standar OWASP WSTG v4.2.",
        usage=custom_usage,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    parser.add_argument("-h", action="help", default=argparse.SUPPRESS, help="Tampilkan pesan bantuan ini")
    parser.add_argument("-u", dest="url", required=True, help="URL target untuk diuji (contoh: https://example.com)")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Aktifkan output verbose")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    import requests
    
    modules = [
        wstg_info_01, wstg_info_02, wstg_info_03, wstg_info_04,
        wstg_info_05, wstg_info_06, wstg_info_07, wstg_info_08,
        wstg_info_09, wstg_info_10
    ]
    
    # Resolve final URL to prevent 308/301 redirects during method testing
    final_url = args.url
    if not final_url.startswith(("http://", "https://")):
        final_url = "http://" + final_url
        
    try:
        print(f"{Fore.CYAN}[*] Resolving final URL...{Style.RESET_ALL}")
        # Disabling verify to prevent SSL errors on some sites, timeout to not hang
        r = requests.get(final_url, timeout=10, allow_redirects=True, verify=False)
        final_url = r.url
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Gagal me-resolve URL: {e}. Menggunakan URL awal.{Style.RESET_ALL}")
        
    args.url = final_url # Override URL for all modules
    
    print(f"{Fore.BLUE}[*] Memulai pengujian WSTG-INFO untuk target: {args.url}{Style.RESET_ALL}")
    
    all_results = []
    
    for module in modules:
        try:
            result = module.run(args.url, verbose=args.verbose)
            all_results.append(result)
        except Exception as e:
            print(f"{Fore.RED}[!] Error menjalankan {module.__name__}: {e}{Style.RESET_ALL}")
            all_results.append({
                "wstg_id": module.__name__.split(".")[-1].replace("_", "-").upper(),
                "title": "Error Execution",
                "status": "error",
                "findings": [],
                "error": str(e)
            })
            
    print(f"\\n{Fore.GREEN}[+] Pengujian selesai. Menghasilkan laporan...{Style.RESET_ALL}")
    
    # Generate domain_timestamp.html
    url_to_parse = args.url
    if not url_to_parse.startswith(("http://", "https://")):
        url_to_parse = "http://" + url_to_parse
    parsed_url = urlparse(url_to_parse)
    domain = parsed_url.netloc.replace("www.", "")
    if not domain:
        domain = "unknown_domain"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{domain}_{timestamp}.html"
    
    report.generate_html(all_results, args.url, report_filename)
    print(f"{Fore.GREEN}[+] Laporan berhasil disimpan ke {report_filename}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
