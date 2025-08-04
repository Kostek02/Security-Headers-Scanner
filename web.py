from flask import Flask, render_template, request, jsonify, send_file
from main import scan_url
from src import VERSION
from src.export import export_scan_to_csv
import tempfile
import os

"""
API Endpoints:
- POST /api/scan
    Request JSON: {"url": "https://example.com"}
    Response JSON: {
        "results": [...],
        "url": ..., "grade": ..., "score": ..., "max_score": ..., "missing": [...], "error": ..., "error_type": ...
    }
"""

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None, url=None, error=None, version=VERSION)

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url')
    export_csv = request.form.get('export_csv') == 'on'
    scan = scan_url(raw_url)
    if scan['error']:
        return render_template('index.html', results=None, url=raw_url, error=scan['error'], error_type=scan.get('error_type'), version=VERSION)
    if export_csv:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
                export_scan_to_csv(scan['results'], scan['url'], scan['grade'], scan['score'], scan['max_score'], scan['missing'], tmp.name)
                return send_file(tmp.name, as_attachment=True, download_name=f"security_headers_scan_{raw_url.replace('://', '_').replace('/', '_')}.csv")
        except Exception as e:
            return render_template('index.html', results=scan['results'], url=scan['url'], error=f"Failed to export CSV: {e}", grade=scan['grade'], score=scan['score'], max_score=scan['max_score'], version=VERSION)
    return render_template('index.html', results=scan['results'], url=scan['url'], error=None, grade=scan['grade'], score=scan['score'], max_score=scan['max_score'], version=VERSION)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True)
    raw_url = data.get('url')
    scan = scan_url(raw_url)
    return jsonify(scan)

if __name__ == '__main__':
    app.run(debug=True) 