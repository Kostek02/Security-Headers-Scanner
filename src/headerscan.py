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

HEADER_EXPLANATIONS = {
    'Content-Security-Policy': {
        'basic': "Prevents XSS by restricting sources of scripts and other content.",
        'weight': 3,
        'context': "A strong CSP is one of the most effective defenses against XSS and data injection attacks. It tells browsers what content is allowed to load, reducing the risk of malicious scripts running on your site. Missing or weak CSP leaves your users vulnerable to a wide range of attacks."
    },
    'Strict-Transport-Security': {
        'basic': "Forces browsers to use HTTPS, protecting against protocol downgrade attacks.",
        'weight': 3,
        'context': "HSTS ensures all future requests use HTTPS, even if a user types http://. This prevents attackers from intercepting or modifying traffic via downgrade or SSL-stripping attacks. Essential for any site with authentication or sensitive data."
    },
    'X-Content-Type-Options': {
        'basic': "Prevents MIME-sniffing, reducing exposure to drive-by downloads and XSS.",
        'weight': 2,
        'context': "Without this header, browsers may try to guess the content type, which can lead to security issues if a file is interpreted as something else (e.g., a script). Always set to 'nosniff'."
    },
    'X-Frame-Options': {
        'basic': "Prevents clickjacking by disallowing your site to be framed by others.",
        'weight': 2,
        'context': "Clickjacking attacks trick users into clicking on something different from what they perceive. This header blocks your site from being embedded in iframes on other domains."
    },
    'Referrer-Policy': {
        'basic': "Controls how much referrer information is sent with requests, reducing info leakage.",
        'weight': 1,
        'context': "A strict referrer policy prevents sensitive URLs or data from leaking to third parties via the Referer header. Important for privacy and to avoid leaking internal paths."
    },
    'Permissions-Policy': {
        'basic': "Restricts use of powerful browser features (camera, mic, etc.) to trusted origins.",
        'weight': 1,
        'context': "This header lets you control which origins can use features like geolocation, camera, microphone, and more. Reduces attack surface and enforces least privilege."
    },
    'Cache-Control': {
        'basic': "Controls browser and proxy caching, important for sensitive data.",
        'weight': 1,
        'context': "Improper caching can expose sensitive data to unauthorized users. Use strict cache settings for authenticated or sensitive content."
    },
    'Access-Control-Allow-Origin': {
        'basic': "Controls which domains can access resources via CORS. Important for APIs.",
        'weight': 1,
        'context': "CORS headers are critical for APIs and web apps that share resources across origins. Misconfiguration can lead to data leaks or unauthorized access."
    },
}

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