import requests
from colorama import init, Fore, Style
from src.utils.grading import grade_headers

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cache-Control',
    'Access-Control-Allow-Origin',
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityHeadersScanner/1.0)'}

init(autoreset=True)

def scan_headers(url):
    try:
        resp = requests.get(url, timeout=10, verify=False, headers=HEADERS, allow_redirects=True)
        return {h: resp.headers.get(h) for h in SECURITY_HEADERS}
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def print_headers_result(headers, truncate=120):
    print("\n--- Security Headers ---\n")
    maxlen = max(len(h) for h in headers)
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        padded = h.ljust(maxlen)
        if val:
            shown = (val[:truncate] + '...') if truncate and len(val) > truncate else val
            print(f"{Fore.GREEN}[+] {padded}: {shown}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] {padded}: MISSING{Style.RESET_ALL}")
        print()  # line break between headers

def normalize_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url
    # Try https first, then http
    for scheme in ['https://', 'http://']:
        test_url = scheme + url
        try:
            resp = requests.get(test_url, timeout=5, verify=False, headers=HEADERS, allow_redirects=True)
            if resp.status_code < 400:
                return test_url
        except Exception:
            continue
    return None

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python headerscan.py <url>")
        exit(1)
    headers = scan_headers(sys.argv[1])
    if headers:
        print_headers_result(headers)
        grade, missing, score, max_score = grade_headers(headers)
        print(f"\nGrade: {grade}  (Score: {score}/{max_score})")
        if missing:
            print("Missing:", ", ".join(missing)) 