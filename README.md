# VulnScan 🛡️ v2.0

A Python-based web endpoint vulnerability scanner with a terminal-inspired UI, 100+ checks, and Excel/CSV export with remediation advice.

> **⚠️ IMPORTANT**: Only use this tool on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

## Features

- ✅ **68 check functions** covering **100+ individual vulnerability tests**
- 📊 **Export reports** as Excel (.xlsx) or CSV with full remediation advice
- 🔍 **Filter results** by status (FAIL / WARN / PASS) and severity (CRITICAL / HIGH / MEDIUM)
- 🔧 **Remediation guidance** built into every finding
- ⚡ **Concurrent scanning** via ThreadPoolExecutor for fast results
- 🖥️ **Terminal-inspired dark UI** with live scan log animation

## Installation

```bash
git clone https://github.com/Ayce-v2/Vulnscan-App.git
cd Vulnscan-App
pip install -r requirements.txt
python app.py
```

Then open your browser to: `http://localhost:5000`

## Usage

1. Enter the target endpoint URL (e.g. `https://example.com`)
2. Read and accept the authorization disclaimer
3. Click **▶ SCAN**
4. Review results — sorted by severity (Critical → High → Medium)
5. Click any result to expand and see issues + recommended fix
6. Export as **Excel** or **CSV** for a full report

## Vulnerability Checks (100+)

### 🔐 Authentication & Session
| Check | CVE / Reference |
|-------|----------------|
| JWT None Algorithm Bypass | CVE-2015-9235 |
| JWT Weak Secret | CWE-326 |
| Session Fixation | CWE-384 |
| Account Enumeration | CWE-204 |
| Weak Default Credentials | CWE-521 |
| Insecure Password Reset | CWE-640 |
| OAuth Misconfiguration | CWE-601, CWE-352 |
| SAML Vulnerabilities | CVE-2017-11427 |
| Missing Function Level Access Control | CWE-285 |

### 🌐 API & Modern App
| Check | CVE / Reference |
|-------|----------------|
| GraphQL Introspection Enabled | CWE-200 |
| GraphQL Depth Attack (DoS) | CWE-400 |
| GraphQL Mutation Abuse | CWE-285 |
| REST API Versioning Exposure | CWE-200 |
| API Key in URL | CWE-598 |
| Mass Assignment | CWE-915 |
| API Rate Limiting | CWE-770 |
| Swagger / OpenAPI Exposure | CWE-200 |
| API Endpoint Enumeration | CWE-200 |
| Insecure Direct Object Reference (IDOR) | CWE-639 |
| Broken Object Level Authorization | CWE-639 |
| HTTP Parameter Pollution | CWE-235 |
| WebSocket Security | CWE-346 |
| Prototype Pollution | CWE-1321 |

### 💉 Injection
| Check | CVE / Reference |
|-------|----------------|
| SQL Injection | CVE-2017-5638, CWE-89 |
| Cross-Site Scripting (XSS) | CWE-79 |
| XML External Entity (XXE) | CVE-2019-0227, CWE-611 |
| Server-Side Template Injection (SSTI) | CWE-94 |
| Command Injection | CWE-78 |
| LDAP Injection | CWE-90 |
| CRLF Injection | CWE-113 |
| HTTP Parameter Pollution | CWE-235 |
| HTTP Request Smuggling | CWE-444 |
| ReDoS | CWE-1333 |

### 🔑 Access Control & Authorization
| Check | CVE / Reference |
|-------|----------------|
| Path Traversal | CVE-2021-41773, CWE-22 |
| Server-Side Request Forgery (SSRF) | CVE-2019-11510, CWE-918 |
| Open Redirect | CWE-601 |
| Insecure File Upload | CWE-434 |
| Insecure Deserialization | CVE-2015-8562, CWE-502 |
| Directory Listing | CWE-548 |
| Exposed Admin Panels | CWE-284 |
| Exposed Debug Endpoints | CWE-215 |

### 🛡️ Headers & Transport
| Check | CVE / Reference |
|-------|----------------|
| Security Headers (HSTS, CSP, X-Frame-Options, etc.) | CWE-693 |
| SSL/TLS Configuration | CVE-2014-3566 (POODLE), CVE-2011-3389 (BEAST) |
| HSTS Implementation | CWE-319 |
| CORS Misconfiguration | CWE-942 |
| Clickjacking | CWE-1021 |
| Host Header Injection | CWE-74 |
| Content Type Sniffing | CWE-430 |
| Subresource Integrity Missing | CWE-353 |
| Feature Policy Misconfiguration | CWE-693 |
| Cache Poisoning | CWE-524 |
| DNS Rebinding | CWE-346 |

### 🍪 Cookies & State
| Check | CVE / Reference |
|-------|----------------|
| Cookie Security Flags | CWE-614, CWE-1004 |
| Session Fixation | CWE-384 |

### 📡 Known CVEs
| Check | CVE |
|-------|-----|
| Log4Shell | **CVE-2021-44228** |
| Spring4Shell | **CVE-2022-22965** |
| Shellshock | **CVE-2014-6271** |
| ProxyLogon (Exchange) | **CVE-2021-26855** |
| F5 BIG-IP RCE | **CVE-2022-1388** |
| HTTP/2 Rapid Reset DoS | **CVE-2023-44487** |

### ⚙️ Miscellaneous
| Check | CVE / Reference |
|-------|----------------|
| Sensitive File Exposure (.env, .git, wp-config, etc.) | CVE-2017-9798, CWE-538 |
| HTTP Methods (TRACE, PUT, DELETE) | CVE-2004-2320, CWE-749 |
| Rate Limiting | CWE-307 |
| Information Disclosure / Stack Traces | CWE-209 |
| Verbose Server Errors | CWE-209 |
| Server Timing Information Leak | CWE-200 |
| Security Misconfiguration | CWE-16 |
| Dependency Confusion | CWE-427 |
| Insufficient Logging | CWE-778 |

## Export

After scanning, click **Download Excel** or **Download CSV** to get a full report including:

- Check name, status, and severity
- CVE / reference number
- All issues found
- Recommended fix for each finding

## Tech Stack

- **Backend**: Python 3, Flask, requests
- **Frontend**: Vanilla HTML/CSS/JS — terminal-inspired dark UI
- **Scanning**: Concurrent checks via `ThreadPoolExecutor`
- **Export**: openpyxl (Excel), csv (CSV)

## Requirements

```
flask>=3.0.0
requests>=2.31.0
urllib3>=2.0.0
openpyxl>=3.1.0
```

## Disclaimer

This tool is intended for **authorized security testing only**. The authors are not responsible for any misuse or damage caused by this software. Always obtain written permission before scanning any system. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction.

## License

MIT
