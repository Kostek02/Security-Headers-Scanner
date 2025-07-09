import argparse
from src.headerscan import scan_headers, normalize_url, HEADER_EXPLANATIONS, SECURITY_HEADERS
from src.utils.grading import grade_headers
from src import VERSION

def scan_url(url):
    url = normalize_url(url)
    if not url:
        return {'error': 'Could not connect to http or https for this host.'}
    headers = scan_headers(url)
    if not headers:
        return {'error': 'Failed to fetch headers from the target URL.'}
    results = []
    maxlen = max(len(h) for h in SECURITY_HEADERS)
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        padded = h.ljust(maxlen)
        explain = HEADER_EXPLANATIONS.get(h, {})
        basic = explain.get('basic', 'No explanation available.')
        weight = explain.get('weight', '?')
        context = explain.get('context', '')
        if val:
            shown = (val[:120] + '...') if val and len(val) > 120 else val
            results.append({'present': True, 'header': padded, 'value': shown, 'basic': basic, 'weight': weight, 'context': context})
        else:
            results.append({'present': False, 'header': padded, 'value': 'MISSING', 'basic': basic, 'weight': weight, 'context': context})
    grade, missing, score, max_score = grade_headers(headers)
    return {
        'results': results,
        'url': url,
        'grade': grade,
        'score': score,
        'max_score': max_score,
        'missing': missing,
        'error': None
    }

def main():
    parser = argparse.ArgumentParser(description="Security Headers Scanner CLI")
    parser.add_argument('url', help='Target website URL to scan')
    parser.add_argument('--grade', action='store_true', help='Show security grade')
    parser.add_argument('--export-csv', metavar='FILE', help='Export results to CSV file')
    args = parser.parse_args()

    print(f"Security Headers Scanner v{VERSION}\n")
    print(f"Scanning: {args.url}")
    scan = scan_url(args.url)
    if scan['error']:
        print(f"[!] {scan['error']}")
        return
    from src.headerscan import print_headers_result
    headers = scan_headers(scan['url'])
    print_headers_result(headers)
    print(f"\nGrade: {scan['grade']}  (Score: {scan['score']}/{scan['max_score']})")
    if scan['missing']:
        print("Missing:", ", ".join(scan['missing']))
    if args.grade:
        print("[Grade output placeholder]")
    if args.export_csv:
        print(f"[Exporting to CSV: {args.export_csv}]")

if __name__ == '__main__':
    main() 