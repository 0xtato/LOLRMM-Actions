#!/usr/bin/env python3
"""
sync_lolrmm.py

Fetches the LOLRMM public API, diffs against the committed snapshot,
opens GitHub Issues for new RMM tools, and updates local block lists.

Dependencies: Python stdlib only (urllib, json, os, csv, datetime)
No pip installs required.
"""

import csv
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOLRMM_API_URL = "https://lolrmm.io/api/rmm_tools.json"
KNOWN_TOOLS_PATH = "known_tools.json"

BLOCKLIST_DOMAINS = "blocklists/domains.txt"
BLOCKLIST_IPS     = "blocklists/ips.txt"
BLOCKLIST_CSV     = "blocklists/blocklist.csv"

# GitHub / GHE settings — injected from environment by the workflow
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GHE_HOST     = os.environ.get("GHE_HOST", "")     # e.g. "github.corp.example.com"
REPO         = os.environ.get("REPO", "")          # e.g. "your-org/lolrmm-internal"

# Build the correct API base depending on GHE vs github.com
if GHE_HOST:
    GITHUB_API_BASE = f"https://{GHE_HOST}/api/v3"
else:
    GITHUB_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_json(url: str) -> object:
    """Fetch a URL and return parsed JSON. No third-party libraries."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "lolrmm-internal-sync/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"[ERROR] Failed to fetch {url}: {exc}", file=sys.stderr)
        sys.exit(1)


def github_api(method: str, path: str, body: dict | None = None) -> dict:
    """Make an authenticated GitHub (or GHE) API request."""
    url = f"{GITHUB_API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "lolrmm-internal-sync/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        print(f"[ERROR] GitHub API {method} {url} → {exc.code}: {body_text}", file=sys.stderr)
        sys.exit(1)


def github_api_exists(path: str) -> bool:
    """
    Return True if a GET to path returns 200, False if 404.
    Any other HTTP error (403, 500, etc.) is a real failure and exits.
    """
    url = f"{GITHUB_API_BASE}{path}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "lolrmm-internal-sync/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        body_text = exc.read().decode("utf-8", errors="replace")
        print(f"[ERROR] GitHub API GET {url} → {exc.code}: {body_text}", file=sys.stderr)
        sys.exit(1)


def ensure_label(label: str, color: str, description: str) -> None:
    """Create a GitHub label if it doesn't already exist."""
    if not github_api_exists(f"/repos/{REPO}/labels/{label}"):
        github_api("POST", f"/repos/{REPO}/labels", {
            "name": label,
            "color": color,
            "description": description,
        })
        print(f"[INFO] Created label '{label}'")


def extract_iocs(tool: dict) -> tuple[list[str], list[str], list[dict]]:
    """
    Pull domains, IPs, and structured rows from a tool's Network entries.
    Returns (domains, ips, rows) where rows are dicts for the CSV.
    """
    domains: list[str] = []
    ips: list[str]     = []
    rows: list[dict]   = []

    tool_name = tool.get("Name", "Unknown")
    date_added = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for entry in (tool.get("Artifacts") or {}).get("Network", []) or []:
        ports = entry.get("Ports", []) or []
        port_str = ",".join(str(p) for p in ports) if ports else ""

        for domain in entry.get("Domains", []) or []:
            if domain and domain not in domains:
                domains.append(domain)
                rows.append({
                    "tool_name": tool_name,
                    "type": "domain",
                    "value": domain,
                    "ports": port_str,
                    "date_added": date_added,
                })

        for ip in entry.get("IPs", []) or []:
            if ip and ip not in ips:
                ips.append(ip)
                rows.append({
                    "tool_name": tool_name,
                    "type": "ip",
                    "value": ip,
                    "ports": port_str,
                    "date_added": date_added,
                })

    return domains, ips, rows


def build_issue_body(tool: dict, domains: list[str], ips: list[str]) -> str:
    """Build a Markdown issue body for a new RMM tool."""
    name        = tool.get("Name", "Unknown")
    description = tool.get("Description", "No description provided.")
    website     = (tool.get("Details") or {}).get("Website", "")
    category    = tool.get("Category", "")
    date_today  = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f"## New RMM Tool Detected: {name}",
        "",
        f"**Source:** [lolrmm.io](https://lolrmm.io)",
        f"**Date detected:** {date_today}",
    ]

    if category:
        lines.append(f"**Category:** {category}")
    if website:
        lines.append(f"**Vendor website:** {website}")

    lines += ["", f"**Description:** {description}", ""]

    # Network indicators table
    has_iocs = domains or ips
    if has_iocs:
        lines += [
            "## Network Indicators",
            "",
            "| Type | Value |",
            "|------|-------|",
        ]
        for d in domains:
            lines.append(f"| Domain | `{d}` |")
        for ip in ips:
            lines.append(f"| IP | `{ip}` |")
    else:
        lines += [
            "## Network Indicators",
            "",
            "_No network indicators found in this entry._",
        ]

    # Sigma detections
    sigma_links = [
        d for d in (tool.get("Detections") or [])
        if d.get("Sigma")
    ]
    if sigma_links:
        lines += ["", "## Sigma Detections", ""]
        for s in sigma_links:
            desc = s.get("Description", "Sigma rule")
            url  = s["Sigma"]
            lines.append(f"- [{desc}]({url})")

    lines += [
        "",
        "## Action Checklist",
        "",
        "- [ ] Review domains/IPs above",
        "- [ ] Submit domains/IPs to your network enforcement tool or ticketing system",
        "        <!-- Add your link here, e.g. firewall ACL request, DNS filter, SIEM import -->",
        "- [ ] Review Sigma detection rules above",
        "- [ ] Close this issue when complete",
        "",
        "---",
        "_Opened automatically by the LOLRMM sync workflow._",
    ]

    return "\n".join(lines)


def open_issue(tool: dict, domains: list[str], ips: list[str]) -> str:
    """Open a GitHub Issue for a new RMM tool. Returns the issue URL."""
    name = tool.get("Name", "Unknown")
    body = build_issue_body(tool, domains, ips)

    result = github_api("POST", f"/repos/{REPO}/issues", {
        "title": f"[New RMM] {name}",
        "body": body,
        "labels": ["new-rmm", "needs-review"],
    })
    return result.get("html_url", "")


def load_known_tools() -> dict[str, dict]:
    """Load known_tools.json → dict keyed by tool Name."""
    if not os.path.exists(KNOWN_TOOLS_PATH):
        return {}
    with open(KNOWN_TOOLS_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Support both a list of tools or a dict
    if isinstance(data, list):
        return {t.get("Name", ""): t for t in data if t.get("Name")}
    return data


def save_known_tools(tools: list[dict]) -> None:
    with open(KNOWN_TOOLS_PATH, "w", encoding="utf-8") as fh:
        json.dump(tools, fh, indent=2)
    print(f"[INFO] Saved {len(tools)} tools to {KNOWN_TOOLS_PATH}")


def _load_existing_values(path: str) -> set[str]:
    """
    Read a flat blocklist file and return a set of non-comment, non-empty lines.
    Used to deduplicate across runs.
    """
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as fh:
        return {
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        }


def _load_existing_csv_values(path: str) -> set[str]:
    """
    Read blocklist.csv and return a set of 'value' column entries.
    Used to deduplicate rows across runs.
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return set()
    with open(path, "r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return {row["value"] for row in reader if row.get("value")}


def append_blocklists(all_rows: list[dict], new_domains: list[str], new_ips: list[str]) -> None:
    """Append new IOCs to the flat block list files and the CSV audit log.

    Deduplicates against existing entries to prevent the same value
    appearing multiple times across different sync runs.
    """
    # domains.txt — skip any already present
    if new_domains:
        existing_domains = _load_existing_values(BLOCKLIST_DOMAINS)
        to_write = [d for d in new_domains if d not in existing_domains]
        if to_write:
            with open(BLOCKLIST_DOMAINS, "a", encoding="utf-8") as fh:
                for d in to_write:
                    fh.write(d + "\n")
            print(f"[INFO] Appended {len(to_write)} domain(s) to {BLOCKLIST_DOMAINS}")
        skipped = len(new_domains) - len(to_write)
        if skipped:
            print(f"[INFO] Skipped {skipped} duplicate domain(s) already in {BLOCKLIST_DOMAINS}")

    # ips.txt — skip any already present
    if new_ips:
        existing_ips = _load_existing_values(BLOCKLIST_IPS)
        to_write = [ip for ip in new_ips if ip not in existing_ips]
        if to_write:
            with open(BLOCKLIST_IPS, "a", encoding="utf-8") as fh:
                for ip in to_write:
                    fh.write(ip + "\n")
            print(f"[INFO] Appended {len(to_write)} IP(s) to {BLOCKLIST_IPS}")
        skipped = len(new_ips) - len(to_write)
        if skipped:
            print(f"[INFO] Skipped {skipped} duplicate IP(s) already in {BLOCKLIST_IPS}")

    # blocklist.csv — skip rows whose value already appears in the CSV
    if all_rows:
        existing_csv_values = _load_existing_csv_values(BLOCKLIST_CSV)
        rows_to_write = [r for r in all_rows if r["value"] not in existing_csv_values]
        write_header = not os.path.exists(BLOCKLIST_CSV) or os.path.getsize(BLOCKLIST_CSV) == 0
        if rows_to_write:
            with open(BLOCKLIST_CSV, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=["tool_name", "type", "value", "ports", "date_added"])
                if write_header:
                    writer.writeheader()
                writer.writerows(rows_to_write)
            print(f"[INFO] Appended {len(rows_to_write)} row(s) to {BLOCKLIST_CSV}")
        skipped = len(all_rows) - len(rows_to_write)
        if skipped:
            print(f"[INFO] Skipped {skipped} duplicate row(s) already in {BLOCKLIST_CSV}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not GITHUB_TOKEN:
        print("[ERROR] GITHUB_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)
    if not REPO:
        print("[ERROR] REPO env var is not set.", file=sys.stderr)
        sys.exit(1)

    print("[INFO] Fetching LOLRMM API...")
    api_data = fetch_json(LOLRMM_API_URL)

    # The API returns a list of tool dicts
    if not isinstance(api_data, list):
        print("[ERROR] Unexpected API response format.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] {len(api_data)} tools returned from LOLRMM API")

    # Basic per-tool schema validation — skip malformed entries rather than crashing
    # or allowing bad data (e.g. empty/None Name) to flow into Issue titles.
    REQUIRED_TOOL_FIELDS = ("Name", "Artifacts")
    valid_tools: list[dict] = []
    for tool in api_data:
        if not isinstance(tool, dict):
            print(f"[WARN] Skipping non-dict entry in API response: {tool!r}", file=sys.stderr)
            continue
        missing = [f for f in REQUIRED_TOOL_FIELDS if not tool.get(f)]
        if missing:
            print(
                f"[WARN] Skipping tool with missing/empty field(s) {missing}: "
                f"Name={tool.get('Name')!r}",
                file=sys.stderr,
            )
            continue
        valid_tools.append(tool)
    if len(valid_tools) < len(api_data):
        print(
            f"[WARN] {len(api_data) - len(valid_tools)} tool(s) skipped due to schema issues. "
            f"Processing {len(valid_tools)} valid tool(s).",
            file=sys.stderr,
        )
    api_data = valid_tools

    # Ensure GitHub labels exist
    ensure_label("new-rmm",      "e11d48", "New RMM tool detected by LOLRMM sync")
    ensure_label("needs-review", "fbca04", "Requires human review before blocking")

    known = load_known_tools()
    print(f"[INFO] {len(known)} tools in local snapshot")

    api_names = {t["Name"] for t in api_data if t.get("Name")}
    new_tools = [t for t in api_data if t.get("Name") and t["Name"] not in known]
    print(f"[INFO] {len(new_tools)} new tool(s) detected")

    # Warn if known tool names have disappeared from the API — could indicate a rename
    removed_names = set(known.keys()) - api_names
    if removed_names:
        print(
            f"[WARN] {len(removed_names)} tool name(s) in the local snapshot are no longer "
            f"present in the LOLRMM API. These may have been renamed or removed upstream. "
            f"Review manually: {', '.join(sorted(removed_names))}",
            file=sys.stderr,
        )

    all_new_domains: list[str] = []
    all_new_ips:     list[str] = []
    all_csv_rows:    list[dict] = []

    for tool in new_tools:
        name = tool.get("Name", "Unknown")
        print(f"[INFO] Processing new tool: {name}")

        domains, ips, rows = extract_iocs(tool)
        all_new_domains.extend(domains)
        all_new_ips.extend(ips)
        all_csv_rows.extend(rows)

        issue_url = open_issue(tool, domains, ips)
        print(f"[INFO] Issue opened: {issue_url}")

    if new_tools:
        append_blocklists(all_csv_rows, all_new_domains, all_new_ips)
        # Overwrite snapshot with the full latest data
        save_known_tools(api_data)
        print(f"[INFO] Done. {len(new_tools)} new tool(s) processed.")
    else:
        # Still save the latest snapshot in case the tool count changed
        # (e.g., a tool was renamed or removed upstream)
        save_known_tools(api_data)
        print("[INFO] No new tools. Snapshot refreshed.")


if __name__ == "__main__":
    main()
