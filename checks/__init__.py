#!/usr/bin/env python3
import argparse
import asyncio
import json
from urllib.parse import urlparse

import httpx

from checks.security_checks import DirectoryListing, ExposedSensitiveFiles, MissingSecurityHeaders


async def run_checks(target_url: str, checks):
    findings = []
    headers = {
        "User-Agent": "kv-fisa/0.1 (+https://github.com/kdatthaavinash6-dotcom/kv-fisa)"
    }

    async with httpx.AsyncClient(timeout=15.0, headers=headers, follow_redirects=True) as client:
        for check in checks:
            findings.extend(await check.run(client, target_url))

    return findings


def normalize_target_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme:
        return f"https://{value}"
    return value


def parse_args():
    parser = argparse.ArgumentParser(
        description="kv-fisa: lightweight web vulnerability scanner for authorized testing."
    )
    parser.add_argument("url", help="Target URL to scan, such as https://example.com")
    parser.add_argument("--output", "-o", default="findings.json", help="Output JSON file path")
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active payload-based checks in future versions.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target_url = normalize_target_url(args.url)

    checks = [
        MissingSecurityHeaders(),
        ExposedSensitiveFiles(),
        DirectoryListing(),
    ]

    findings = asyncio.run(run_checks(target_url, checks))

    output = {
        "target": target_url,
        "findings": [f.to_dict() for f in findings],
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    print(f"Scanned {target_url}")
    print(f"Found {len(findings)} finding(s). Report saved to {args.output}")


if __name__ == "__main__":
    main()
