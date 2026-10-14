from urllib.parse import urlparse

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

def log(msg, verbose):
    """Print pesan ke terminal hanya jika verbose aktif."""
    if verbose:
        print(msg)

def ensure_url(target_url):
    """Pastikan URL memiliki skema http/https."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    return target_url

def extract_domain(target_url):
    """Ekstrak domain bersih dari URL target."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0].strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def get_hostname(target_url):
    """Mendapatkan hostname dari URL."""
    parsed = urlparse(ensure_url(target_url))
    hostname = parsed.netloc.split(":")[0]
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname

def is_same_domain(base_url, check_url):
    """Cek apakah URL masih dalam domain yang sama."""
    try:
        base_domain = urlparse(base_url).netloc
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]
        check_domain = urlparse(check_url).netloc
        if check_domain.startswith("www."):
            check_domain = check_domain[4:]
        return check_domain == base_domain
    except Exception:
        return False
