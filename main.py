import argparse
from src.headerscan import scan_headers, normalize_url
from src.utils.grading import grade_headers

def main():
    parser = argparse.ArgumentParser(description="Security Headers Scanner CLI")
    parser.add_argument('url', help='Target website URL to scan')
    parser.add_argument('--grade', action='store_true', help='Show security grade')
    parser.add_argument('--export-csv', metavar='FILE', help='Export results to CSV file')
    args = parser.parse_args()

    print(f"Scanning: {args.url}")
    url = normalize_url(args.url)
    if not url:
        print("[!] Could not connect to http or https for this host.")
        return
    headers = scan_headers(url)
    if not headers:
        print("[!] Failed to fetch headers from the target URL.")
        return
    from src.headerscan import print_headers_result
    print_headers_result(headers)
    grade, missing, score, max_score = grade_headers(headers)
    print(f"\nGrade: {grade}  (Score: {score}/{max_score})")
    if missing:
        print("Missing:", ", ".join(missing))
    if args.grade:
        print("[Grade output placeholder]")
    if args.export_csv:
        print(f"[Exporting to CSV: {args.export_csv}]")

if __name__ == '__main__':
    main() 