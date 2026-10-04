# kv-fisa

kv-fisa is a lightweight web vulnerability scanner focused on checking public web addresses for common issues such as missing security headers, exposed sensitive paths, directory listing, and insecure configuration.

It is designed as a small, extensible scanning tool for learning, research, and authorized security testing.

## Safety & legality

Only scan websites you own or have explicit written permission to test.

## Features

- Checks for missing security headers
- Detects common sensitive file exposure such as `.git`, `.env`, and backup files
- Detects directory listing behavior
- Accepts a target URL and writes a JSON report
- Small, modular architecture for extending with additional checks

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py https://example.com --output results.json
```

Optional active checks can be added later for payload-based testing.

## Project structure

```text
.
├── README.md
├── requirements.txt
├── .gitignore
├── scanner.py
├── checks/
│   ├── __init__.py
│   └── security_checks.py
└── tests/
    └── test_basic.py
```

## Example output

```json
{
  "target": "https://example.com",
  "findings": [
    {
      "id": "missing-security-headers:https://example.com",
      "url": "https://example.com",
      "title": "Missing security headers",
      "description": "Missing headers: strict-transport-security, content-security-policy",
      "severity": "medium",
      "evidence": {
        "status_code": 200,
        "headers": {
          "content-type": "text/html; charset=utf-8"
        }
      },
      "remediation": "Add recommended security headers. See OWASP Secure Headers guide."
    }
  ]
}
```

## Future roadmap

- Add active payload-based checks for XSS and SQL injection
- Add crawling and same-origin traversal
- Add reporting in HTML and CSV formats
- Add plugin-based scanning checks
- Add authentication support and more advanced scanning logic

## License

This project is intended for learning and authorized security testing.
