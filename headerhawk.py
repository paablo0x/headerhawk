#!/usr/bin/env python3
"""A simple HTTP security header checker."""

import argparse
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


HEADERS_TO_CHECK = {
    "strict-transport-security": (
        "Strict-Transport-Security",
        "Helps browsers stick to HTTPS after a secure visit.",
    ),
    "content-security-policy": (
        "Content-Security-Policy",
        "Helps control which sources a page can load content from.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Helps prevent browsers from guessing a file's content type.",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Helps control whether a page can be loaded inside a frame.",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Controls how much referrer information is sent to other sites.",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "Controls access to browser features such as camera and microphone.",
    ),
}


def normalize_url(target):
    """Add HTTPS if no scheme is provided and validate the URL."""
    target = target.strip()
    if not target:
        raise ValueError("Please enter a target URL.")

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Invalid URL. Try something like https://example.com.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not supported.")

    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params,
        parsed.query, ""
    ))


def fetch_headers(url, timeout):
    """Make one GET request and return its status, final URL and headers."""
    request = Request(
        url,
        headers={"User-Agent": "HeaderHawk/1.0"},
        method="GET",
    )

    with urlopen(request, timeout=timeout) as response:
        return (
            response.status,
            response.geturl(),
            {key.lower(): value.strip() for key, value in response.headers.items()},
        )


def main():
    parser = argparse.ArgumentParser(
        description="Check common HTTP security headers on an authorized target."
    )
    parser.add_argument("url", help="URL to check, e.g. https://example.com")
    parser.add_argument(
        "--timeout", type=float, default=8,
        help="Request timeout in seconds (default: 8)",
    )
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        url = normalize_url(args.url)
        status, final_url, headers = fetch_headers(url, args.timeout)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except HTTPError as error:
        # Error responses can still contain useful security headers.
        status = error.code
        final_url = error.geturl()
        headers = {
            key.lower(): value.strip()
            for key, value in error.headers.items()
        }
        print(f"Received HTTP {status}; checking the response headers.")
    except (URLError, TimeoutError, OSError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 1

    print("\nHeaderHawk - HTTP Security Header Checker")
    print("=" * 43)
    print(f"Target: {final_url}")
    print(f"HTTP status: {status}")
    print("\nResults")
    print("-" * 43)

    present = 0
    missing = 0

    for key, (name, explanation) in HEADERS_TO_CHECK.items():
        value = headers.get(key)
        if value:
            present += 1
            print(f"[+] {name}")
            print(f"    Value: {value}")
        else:
            missing += 1
            print(f"[-] Missing: {name}")
            print(f"    Why it matters: {explanation}")

    print("\nSummary")
    print("-" * 43)
    print(f"Present: {present}/{len(HEADERS_TO_CHECK)}")
    print(f"Missing: {missing}/{len(HEADERS_TO_CHECK)}")
    print("\nThis is a basic header check, not a full security audit.")
    print("A header can be present and still be configured incorrectly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
