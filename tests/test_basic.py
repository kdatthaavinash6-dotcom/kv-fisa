import re
from dataclasses import dataclass
from typing import Any, Dict, List

from bs4 import BeautifulSoup


@dataclass
class Finding:
    id: str
    url: str
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] | None = None
    remediation: str | None = None

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class Check:
    name = "base"

    async def run(self, client, url: str) -> List[Finding]:
        raise NotImplementedError


class MissingSecurityHeaders(Check):
    name = "missing-security-headers"

    async def run(self, client, url: str) -> List[Finding]:
        try:
            response = await client.get(url)
        except Exception:
            return []

        headers = {key.lower(): value for key, value in response.headers.items()}
        required_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ]

        missing = [header for header in required_headers if header not in headers]
        if not missing:
            return []

        return [
            Finding(
                id=f"{self.name}:{url}",
                url=url,
                title="Missing security headers",
                description=f"Missing headers: {', '.join(missing)}",
                severity="medium",
                evidence={"status_code": response.status_code, "headers": dict(response.headers)},
                remediation="Add recommended security headers such as HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.",
            )
        ]


class ExposedSensitiveFiles(Check):
    name = "exposed-sensitive-files"

    async def run(self, client, url: str) -> List[Finding]:
        findings: List[Finding] = []
        base = url.rstrip("/")
        for candidate in [
            "/.git",
            "/.env",
            "/.env.example",
            "/wp-config.php",
            "/config.php",
            "/server.log",
            "/backup.zip",
            "/backup.sql",
            "/database.sql",
            "/.svn",
            "/.hg",
        ]:
            target = base + candidate
            try:
                response = await client.get(target, follow_redirects=True)
            except Exception:
                continue

            if response.status_code == 200:
                findings.append(
                    Finding(
                        id=f"{self.name}:{target}",
                        url=target,
                        title="Sensitive file exposed",
                        description=f"The path {target} returned HTTP 200 and may expose sensitive content.",
                        severity="high",
                        evidence={"status_code": response.status_code, "content_type": response.headers.get("content-type")},
                        remediation="Remove or restrict access to sensitive files and disable directory browsing or backup exposure.",
                    )
                )

        return findings


class DirectoryListing(Check):
    name = "directory-listing"

    async def run(self, client, url: str) -> List[Finding]:
        base = url.rstrip("/")
        candidates = [
            base + "/",
            base + "/admin",
            base + "/static",
            base + "/assets",
            base + "/uploads",
        ]

        for candidate in candidates:
            try:
                response = await client.get(candidate)
            except Exception:
                continue

            if response.status_code != 200:
                continue

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type.lower():
                continue

            text = response.text.lower()
            soup = BeautifulSoup(response.text, "html.parser")
            directory_markers = [
                "index of",
                "parent directory",
                "directory listing",
                "name modified",
                "last modified",
            ]
            if any(marker in text for marker in directory_markers) or soup.find_all("a"):
                if len(soup.find_all("a")) > 5:
                    return [
                        Finding(
                            id=f"{self.name}:{candidate}",
                            url=candidate,
                            title="Directory listing exposed",
                            description=f"The endpoint {candidate} appears to expose directory listing or file index information.",
                            severity="medium",
                            evidence={"status_code": response.status_code, "content_type": content_type},
                            remediation="Disable directory browsing and restrict access to sensitive folders.",
                        )
                    ]

        return []


def _is_html_directory_listing(html: str) -> bool:
    patterns = [
        r"<title>index of",
        r"parent directory",
        r"directory listing",
        r"name\s+last modified",
    ]
    lower = html.lower()
    return any(re.search(pattern, lower) for pattern in patterns)
