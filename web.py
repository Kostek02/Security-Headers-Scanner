from flask import Flask, render_template, request
from src.headerscan import scan_headers, SECURITY_HEADERS, normalize_url
from src.utils.grading import grade_headers
import requests

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None, url=None, error=None)

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url')
    url = normalize_url(raw_url)
    if not url:
        return render_template('index.html', results=None, url=raw_url, error="Could not connect to http or https for this host.")
    headers = scan_headers(url)
    if headers is None:
        return render_template('index.html', results=None, url=raw_url, error="Failed to fetch headers from the target URL.")
    results = []
    maxlen = max(len(h) for h in SECURITY_HEADERS)
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        padded = h.ljust(maxlen)
        if val:
            shown = (val[:120] + '...') if val and len(val) > 120 else val
            results.append({'present': True, 'header': padded, 'value': shown})
        else:
            results.append({'present': False, 'header': padded, 'value': 'MISSING'})
    grade, missing, score, max_score = grade_headers(headers)
    return render_template('index.html', results=results, url=url, error=None, grade=grade, score=score, max_score=max_score)

if __name__ == '__main__':
    app.run(debug=True) 