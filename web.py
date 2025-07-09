from flask import Flask, render_template, request
from main import scan_url

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None, url=None, error=None)

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url')
    scan = scan_url(raw_url)
    if scan['error']:
        return render_template('index.html', results=None, url=raw_url, error=scan['error'])
    return render_template('index.html', results=scan['results'], url=scan['url'], error=None, grade=scan['grade'], score=scan['score'], max_score=scan['max_score'])

if __name__ == '__main__':
    app.run(debug=True) 