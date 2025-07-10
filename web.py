from flask import Flask, render_template, request, jsonify
from main import scan_url
from src import VERSION

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
    scan = scan_url(raw_url)
    if scan['error']:
        return render_template('index.html', results=None, url=raw_url, error=scan['error'], error_type=scan.get('error_type'), version=VERSION)
    return render_template('index.html', results=scan['results'], url=scan['url'], error=None, grade=scan['grade'], score=scan['score'], max_score=scan['max_score'], version=VERSION)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True)
    raw_url = data.get('url')
    scan = scan_url(raw_url)
    return jsonify(scan)

if __name__ == '__main__':
    app.run(debug=True) 