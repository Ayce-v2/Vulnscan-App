# VulnScan 🛡️

A Python-based web endpoint vulnerability scanner with a clean terminal-inspired UI.

> **⚠️ IMPORTANT**: Only use this tool on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

## Features

Runs **20 automated security checks** including:

| Check | CVE / Reference |
|-------|----------------|
| Security Headers (HSTS, CSP, X-Frame-Options, etc.) | CWE-693 |
| SSL/TLS Configuration | CVE-2014-3566 (POODLE), CVE-2011-3389 (BEAST) |
| SQL Injection | CVE-2017-5638, CWE-89 |
| Cross-Site Scripting (XSS) | CWE-79 |
| CORS Misconfiguration | CWE-942 |
| Open Redirect | CWE-601 |
| Directory Listing | CWE-548 |
| Sensitive File Exposure (.env, .git, wp-config, etc.) | CVE-2017-9798 |
| HTTP Methods (TRACE, PUT, DELETE) | CVE-2004-2320 |
| Clickjacking | CWE-1021 |
| Rate Limiting | CWE-307 |
| Information Disclosure (stack traces) | CWE-209 |
| Exposed Admin Panels | CWE-284 |
| Cookie Security Flags | CWE-614 |
| Log4Shell | **CVE-2021-44228** |
| Spring4Shell | **CVE-2022-22965** |
| Path Traversal | CVE-2021-41773, CWE-22 |
| SSRF (AWS/GCP metadata) | CVE-2019-11510, CWE-918 |
| Shellshock | **CVE-2014-6271** |
| HSTS Implementation | CWE-319 |

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/vulnscan.git
cd vulnscan
pip install -r requirements.txt
python app.py
```

Then open your browser to: `http://localhost:5000`

## Usage

1. Enter the target endpoint URL (e.g. `https://example.com`)
2. Read and accept the authorization disclaimer
3. Click **SCAN**
4. Review results — failures are sorted by severity (Critical → High → Medium)

## Tech Stack

- **Backend**: Python 3, Flask, requests
- **Frontend**: Vanilla HTML/CSS/JS with a terminal-inspired dark UI
- **Scanning**: Concurrent checks via `ThreadPoolExecutor`

## Disclaimer

This tool is intended for **authorized security testing only**. The authors are not responsible for any misuse or damage caused by this software. Always obtain written permission before scanning any system.

## License

MIT
