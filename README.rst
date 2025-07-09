Security Headers Scanner
========================

A lightweight CLI tool to analyze HTTP response headers and evaluate the security posture of web applications.

This scanner inspects key HTTP security headers and provides an overall rating with recommendations for hardening based on industry standards (OWASP, Mozilla Observatory).

.. image:: https://img.shields.io/badge/status-in--progress-yellow
   :alt: Project Status

Project Goals
-------------

- Help developers and cybersecurity students assess websites for missing or misconfigured security headers.
- Reinforce best practices for HTTP security and content protection mechanisms.
- Serve as a starting point for broader web application hardening tools.

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

    # Note: Some test sites (like badssl.com) may block automated requests. For demos, use github.com or httpbin.org.

Planned Features
----------------

- [ ] Output as JSON or Markdown for easy logging/reporting
- [ ] Add batch scanning mode (multiple URLs from file)
- [ ] Dockerfile for containerized use
- [ ] GitLab CI integration for automated scans in CI/CD

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

    git clone https://github.com/yourusername/security-headers-scanner.git
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