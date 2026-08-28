# lolrmm

Automated alerting system for [LOLRMM](https://lolrmm.io) — a community-maintained catalog of Remote Monitoring and Management (RMM) tools used in threat actor campaigns with GitHub Actions.

## What this does

A GitHub Actions workflow runs daily and:

1. Fetches the LOLRMM public API (`lolrmm.io/api/rmm_tools.json`)
2. Diffs against `known_tools.json` (the committed baseline snapshot)
3. For each **new** RMM tool detected:
   - Opens a GitHub Issue with extracted network indicators (domains, IPs)
   - Appends indicators to the `blocklists/` files
   - Updates the `known_tools.json` snapshot

## Repository structure

```
.github/workflows/sync-lolrmm.yml   # Scheduled workflow
scripts/sync_lolrmm.py              # Sync script (stdlib only, no pip)
known_tools.json                    # Baseline snapshot — do not edit manually
blocklists/
  domains.txt                       # Domain block list (one per line)
  ips.txt                           # IP block list (one per line)
  blocklist.csv                     # Full audit trail with metadata
CODEOWNERS                          # Workflow + script changes require owner review
```

## One-time setup

### 1. Fork or create the repo

Fork this repo or create a new one on github.com and push the contents.

### 2. Enable Actions write permissions

In **Settings → Actions → General → Workflow permissions**, select:
- "Read and write permissions"

This allows the workflow to commit updated blocklists and open Issues using the
built-in `GITHUB_TOKEN` — no PAT required.

### 3. Update CODEOWNERS

Replace `@0xtato` in `CODEOWNERS` with your GitHub username or team slug.

### 4. Enable branch protection (recommended)

In **Settings → Branches**, add a rule for `main`:
- Require pull request reviews before merging
- Require review from Code Owners
- Do not allow bypassing the above settings

This ensures no one can modify the workflow or script without a review.

### 5. Pin the SHA in the workflow (keep it current)

The workflow uses `actions/checkout` pinned to a full commit SHA, not a tag.
When you want to update to a newer version of `actions/checkout`, get the latest SHA from
[github.com/actions/checkout/commits](https://github.com/actions/checkout/commits)
and update `.github/workflows/sync-lolrmm.yml` accordingly.

### 6. Customize the action checklist (optional)

In `scripts/sync_lolrmm.py`, the issue body includes an action checklist. Add a
link to your own ticketing system or network enforcement tool where indicated by
the placeholder comment.

## Block list consumption

The files in `blocklists/` are designed to be consumed by your enforcement tooling:

| File | Format | Use |
|---|---|---|
| `domains.txt` | One domain per line | DNS filters, web proxies (Zscaler, etc.) |
| `ips.txt` | One IP per line | Firewall/NGFW ACLs |
| `blocklist.csv` | CSV with metadata | Audit trail, SIEM ingestion |

> **Note:** Wildcard entries like `*.anydesk.com` may require manual handling depending on your enforcement tool.

## Workflow security

- **No third-party Actions** — only `actions/checkout` (GitHub first-party), pinned to a commit SHA
- **No pip installs** — script uses Python stdlib only (`urllib`, `json`, `csv`, `os`)
- **Minimal permissions** — `contents: write` and `issues: write` only
- **CODEOWNERS** — workflow and script changes require owner review
- **Data, not code** — the LOLRMM API response is treated as structured data only, never executed
