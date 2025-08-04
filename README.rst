Security Headers Scanner
========================

A lightweight CLI tool to analyze HTTP response headers and evaluate the security posture of web applications.

.. note::
   **Current Version:** v1.0.2-dev (Patch: CSV Export Support)

This scanner inspects key HTTP security headers and provides an overall rating with recommendations for hardening based on industry standards (OWASP, Mozilla Observatory).

.. image:: https://img.shields.io/badge/status-in--progress-yellow
   :alt: Project Status

Project Goals
-------------

- Help developers and cybersecurity students assess websites for missing or misconfigured security headers.
- Reinforce best practices for HTTP security and content protection mechanisms.
- Serve as a starting point for broader web application hardening tools.

**v1.0.2 Patch Goals (Active):**

- Add CSV export option to CLI (command-line)
- Add CSV export option to GUI (web interface)
- Refactor export logic into modular export.py
- Implement --output csv option in CLI
- Implement "Download CSV" button in GUI
- Update documentation for CSV export usage

Key Features
------------

- 🚀 Scan any public-facing website via URL.
- 🧠 Detects presence and correctness of important security headers:
  
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Cache-Control`
  - `Access-Control-Allow-Origin`

- 🛡️ Outputs a security grade (A/B/C/D/F) with rationale.
- 📝 Prints simple remediation advice for each missing header.
- 📦 Optional output as JSON or Markdown (planned).

Why This Project?
-----------------

Security misconfigurations are one of the most common and dangerous OWASP Top 10 vulnerabilities. Many real-world sites neglect basic HTTP header protections that prevent XSS, clickjacking, and other attacks.

This tool provides a hands-on way to:

- Understand how browsers use headers to enforce security policies.
- Learn how to audit real websites for missing protections.
- Build a foundation for automating security audits.

How It Works
------------

1. Sends an HTTPS GET request to the target URL.
2. Inspects the response headers for a known list of security headers.
3. Evaluates presence and values against best practices.
4. Outputs a grade and suggestions.

Quick Example
-------------

.. code-block:: bash

    $ python main.py https://github.com

    Scanning: https://github.com

    --- Security Headers ---

    [+] Content-Security-Policy    : default-src 'none'; base-uri 'self'; ...
    [+] Strict-Transport-Security  : max-age=31536000; includeSubdomains; preload
    [+] X-Content-Type-Options     : nosniff
    [+] X-Frame-Options            : deny
    [+] Referrer-Policy            : origin-when-cross-origin, strict-origin-when-cross-origin
    [!] Permissions-Policy         : MISSING
    [+] Cache-Control              : max-age=0, private, must-revalidate
    [!] Access-Control-Allow-Origin: MISSING

    Grade: A  (Score: 12/14)
    Missing: Permissions-Policy, Access-Control-Allow-Origin

    # Or use the web GUI:
    $ python web.py
    # Then open http://127.0.0.1:5000

    # Export results to CSV (CLI):
    $ python main.py https://github.com --export-csv results.csv

    # Note: Some test sites (like badssl.com) may block automated requests. For demos, use github.com or httpbin.org.

CSV Export
----------

The scanner supports exporting results to CSV format for compliance reporting and record-keeping.

**CLI Export:**
.. code-block:: bash

    $ python main.py https://example.com --export-csv scan_results.csv

**GUI Export:**
1. Open the web interface: `python web.py`
2. Enter a URL and click "Start Scan"
3. After results appear, click "Download CSV" button
4. CSV file will be downloaded with filename including the scanned URL

**CSV Format:**
The exported CSV includes:
- Summary: Target URL, Security Grade, Score, Missing Headers
- Detailed results: Status, Header Name, Value, Description, Weight for each security header

Planned Features
----------------

- [x] Output as CSV for easy logging/reporting (implemented in v1.0.2)
- [ ] Output as JSON or Markdown for easy logging/reporting (planned)
- [ ] Add batch scanning mode (multiple URLs from file) (planned)
- [ ] Dockerfile for containerized use (planned)
- [ ] GitLab CI integration for automated scans in CI/CD (planned)
- [ ] Add API endpoint for programmatic scans (planned)
- [ ] Add support for custom user-defined headers (planned)
- [ ] Improve scan_rules.json validation (planned)

Project Structure
-----------------

.. code-block:: text

    security-headers-scanner/
    ├── main.py                  # Main CLI entry point
    ├── web.py                   # Flask web GUI
    ├── src/
    │   ├── headerscan.py        # Scanning logic
    │   └── utils/
    │       └── grading.py       # Header evaluation and scoring logic
    │   └── data/
    │       └── scan_rules.json      # Header rules and expected values
    ├── reports/
    │   └── (optional output logs)
    ├── README.rst
    └── requirements.txt

Installation
------------

.. code-block:: bash

    git clone https://github.com/Kostek02/Security-Headers-Scanner.git
    cd security-headers-scanner
    pip install -r requirements.txt

Dependencies:

- Python 3.8+
- `requests`
- `colorama` (for colorful output, optional)

Usage
-----

.. code-block:: bash

    python main.py <url>
    # Example:
    python main.py github.com

    # Or run the web GUI:
    python web.py
    # Then open http://127.0.0.1:5000

License
-------

MIT License - see `LICENSE` file for details.

Contributions
-------------

Pull requests are welcome! This tool is designed to be beginner-friendly, especially for cybersecurity students learning Python and HTTP security.

Acknowledgments
---------------

- Mozilla Observatory Guidelines
- OWASP Secure Headers Project
- PortSwigger Web Security Academy