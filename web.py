from flask import Flask, render_template, request
from main import scan_url
from src import VERSION

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None, url=None, error=None, version=VERSION)

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url')
    scan = scan_url(raw_url)
    if scan['error']:
        return render_template('index.html', results=None, url=raw_url, error=scan['error'], version=VERSION)
    return render_template('index.html', results=scan['results'], url=scan['url'], error=None, grade=scan['grade'], score=scan['score'], max_score=scan['max_score'], version=VERSION)

if __name__ == '__main__':
    app.run(debug=True) 