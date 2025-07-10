import requests
from colorama import init, Fore, Style
from src.utils.grading import grade_headers
import json

# Load header rules from JSON
with open('src/data/scan_rules.json', 'r') as f:
    rules = json.load(f)
SECURITY_HEADERS = [h['name'] for h in rules['headers']]
HEADER_EXPLANATIONS = {h['name']: {k: h[k] for k in h if k != 'name'} for h in rules['headers']}

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityHeadersScanner/1.0)'}

init(autoreset=True)


def scan_headers(url):
    try:
        resp = requests.get(url, timeout=10, verify=False, headers=HEADERS, allow_redirects=True)
        if resp.status_code >= 400:
            return {'error': True, 'error_type': 'http', 'error_message': f'HTTP error {resp.status_code} for {url}'}
        return {h: resp.headers.get(h) for h in SECURITY_HEADERS}
    except requests.exceptions.Timeout:
        return {'error': True, 'error_type': 'timeout', 'error_message': f'Timeout while connecting to {url}'}
    except requests.exceptions.SSLError:
        return {'error': True, 'error_type': 'ssl', 'error_message': f'SSL error while connecting to {url}'}
    except requests.exceptions.ConnectionError:
        return {'error': True, 'error_type': 'connection', 'error_message': f'Connection error (DNS, refused, or network) for {url}'}
    except Exception as e:
        return {'error': True, 'error_type': 'other', 'error_message': f'Unexpected error: {e}'}

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
    errors = []
    for scheme in ['https://', 'http://']:
        test_url = scheme + url
        try:
            resp = requests.get(test_url, timeout=5, verify=False, headers=HEADERS, allow_redirects=True)
            if resp.status_code < 400:
                return test_url
            else:
                errors.append({'scheme': scheme, 'error_type': 'http', 'error_message': f'HTTP error {resp.status_code} for {test_url}'})
        except requests.exceptions.Timeout:
            errors.append({'scheme': scheme, 'error_type': 'timeout', 'error_message': f'Timeout while connecting to {test_url}'})
        except requests.exceptions.SSLError:
            errors.append({'scheme': scheme, 'error_type': 'ssl', 'error_message': f'SSL error while connecting to {test_url}'})
        except requests.exceptions.ConnectionError:
            errors.append({'scheme': scheme, 'error_type': 'connection', 'error_message': f'Connection error (DNS, refused, or network) for {test_url}'})
        except Exception as e:
            errors.append({'scheme': scheme, 'error_type': 'other', 'error_message': f'Unexpected error: {e}'})
    return {'error': True, 'attempts': errors}

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