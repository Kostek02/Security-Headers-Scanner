import argparse
from src.headerscan import scan_headers, normalize_url, HEADER_EXPLANATIONS, SECURITY_HEADERS
from src.utils.grading import grade_headers
from src import VERSION
import logging

def scan_url(url):
    url_result = normalize_url(url)
    if isinstance(url_result, dict) and url_result.get('error'):
        # Compose a readable error message for the GUI
        error_msgs = []
        for attempt in url_result.get('attempts', []):
            error_msgs.append(f"{attempt['scheme']} {attempt['error_type']}: {attempt['error_message']}")
        return {
            'error': 'Could not resolve or connect to the target URL. ' + ' | '.join(error_msgs),
            'error_type': 'connection',
            'results': None,
            'url': url,
            'grade': None,
            'score': None,
            'max_score': None,
            'missing': None
        }
    scan = scan_headers(url_result)
    if isinstance(scan, dict) and scan.get('error'):
        return {
            'error': scan['error_message'],
            'error_type': scan['error_type'],
            'results': None,
            'url': url_result,
            'grade': None,
            'score': None,
            'max_score': None,
            'missing': None
        }
    results = []
    maxlen = max(len(h) for h in SECURITY_HEADERS)
    for h in SECURITY_HEADERS:
        val = scan.get(h)
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
    grade, missing, score, max_score = grade_headers(scan)
    return {
        'results': results,
        'url': url_result,
        'grade': grade,
        'score': score,
        'max_score': max_score,
        'missing': missing,
        'error': None
    }

def main():
    parser = argparse.ArgumentParser(description="Scan a website's HTTP response headers for missing or misconfigured security protections.")
    parser.add_argument('url', help='Target website URL to scan (e.g., https://example.com)')
    parser.add_argument('--grade', action='store_true', help='Display the security grade after scanning')
    parser.add_argument('--export-csv', metavar='FILE', help='Export scan results to a CSV file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed error and debug messages')
    parser.add_argument('--logfile', metavar='LOGFILE', help='Write log output to a file')
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    log_handlers = [logging.StreamHandler()]
    if args.logfile:
        log_handlers.append(logging.FileHandler(args.logfile, mode='w'))
    logging.basicConfig(
        level=log_level,
        format='[%(levelname)s] %(message)s',
        handlers=log_handlers
    )
    logger = logging.getLogger("sec-headers-cli")

    print(f"Security Headers Scanner v{VERSION}\n")
    print(f"Scanning: {args.url}")
    logger.debug(f"Normalized input URL: {args.url}")
    url_result = normalize_url(args.url)
    logger.debug(f"normalize_url() result: {url_result}")
    if isinstance(url_result, dict) and url_result.get('error'):
        print("[!] Unable to resolve or connect to the target URL.")
        for attempt in url_result.get('attempts', []):
            print("  -", attempt['scheme'], attempt['error_type'] + ':', attempt['error_message'])
            logger.debug(f"Attempt: {attempt}")
        if args.verbose:
            print("[Verbose] All connection attempts failed. Check your network or the URL and try again.")
        logger.error(f"Connection failed for {args.url}")
        return
    scan = scan_headers(url_result)
    logger.debug(f"scan_headers() result: {scan}")
    if isinstance(scan, dict) and scan.get('error'):
        print(f"[!] {scan['error_message']}")
        logger.error(f"Scan error: {scan['error_message']} (type: {scan['error_type']})")
        if args.verbose:
            print(f"[Verbose] Error type: {scan['error_type']}")
        return
    from src.headerscan import print_headers_result
    headers = scan_headers(scan['url']) if isinstance(scan, dict) and 'url' in scan else scan_headers(url_result)
    logger.debug(f"Headers for grading: {headers}")
    print_headers_result(headers)
    grade, missing, score, max_score = grade_headers(headers)
    logger.debug(f"Grade: {grade}, Score: {score}/{max_score}, Missing: {missing}")
    print(f"\nGrade: {grade}  (Score: {score}/{max_score})")
    if missing:
        print("Missing headers:", ", ".join(missing))
    if args.grade:
        print("[Grade option enabled]")
    if args.export_csv:
        print(f"[Exporting results to CSV: {args.export_csv}]")
    logger.info("Scan complete.")

if __name__ == '__main__':
    main() 