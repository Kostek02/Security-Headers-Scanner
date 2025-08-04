"""
export.py - CSV export logic for Security Headers Scanner

Functions:
- export_scan_to_csv(results, url, grade, score, max_score, missing, filename):
    Exports scan results to a CSV file.
"""
import csv

def export_scan_to_csv(results, url, grade, score, max_score, missing, filename):
    """
    Export scan results to a CSV file.
    Args:
        results (list): List of header scan dicts (present, header, value, basic, weight, context)
        url (str): Scanned URL
        grade (str): Security grade
        score (int): Score achieved
        max_score (int): Max possible score
        missing (list): List of missing headers
        filename (str): Output CSV file path
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Summary section
            writer.writerow(["SECURITY HEADERS SCAN REPORT"])
            writer.writerow([])
            writer.writerow(["Target URL", url])
            writer.writerow(["Security Grade", grade])
            writer.writerow(["Score", f"{score}/{max_score}"])
            writer.writerow(["Missing Headers", ", ".join(missing) if missing else "None"])
            writer.writerow([])
            
            # Headers table
            writer.writerow(["Status", "Header", "Value", "Description", "Weight"])
            for r in results:
                status = "✓ Present" if r.get('present') else "✗ Missing"
                header = r.get('header', '').strip()
                value = r.get('value', '')
                # Truncate long values for readability
                if len(value) > 100:
                    value = value[:97] + "..."
                description = r.get('basic', '')
                weight = r.get('weight', '')
                
                writer.writerow([status, header, value, description, weight])
                
    except Exception as e:
        raise RuntimeError(f"Failed to export CSV: {e}") 