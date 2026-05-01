#!/usr/bin/env python3
"""
parse_dependabot.py
Fetches open Dependabot alerts from the GitHub API and normalises
them into the common findings JSON format used by aggregate_findings.py.

Uses the `gh` CLI (pre-installed on GitHub-hosted runners) as the
primary method because the default GITHUB_TOKEN cannot access the
Dependabot alerts REST API via raw HTTP.  Falls back to `requests`
for PAT-based usage outside of Actions.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

try:
    import requests
except ImportError:
    requests = None

GITHUB_API = 'https://api.github.com'

SEVERITY_MAP = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
}


# ── gh CLI approach (works with GITHUB_TOKEN on Actions runners) ─────

def _gh_available():
    return shutil.which('gh') is not None


def fetch_dependabot_alerts_gh(repo):
    """Fetch all open Dependabot alerts using the gh CLI."""
    all_alerts = []

    cmd = [
        'gh', 'api',
        f'/repos/{repo}/dependabot/alerts?state=open&per_page=100',
        '--paginate',
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print('[WARN] gh CLI not found.')
        return None
    except subprocess.TimeoutExpired:
        print('[WARN] gh CLI timed out.')
        return None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        print(f'[WARN] gh api failed (rc={result.returncode}): {stderr}')
        return None

    stdout = result.stdout.strip()
    if not stdout:
        return all_alerts

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # --paginate may concatenate multiple JSON arrays; try wrapping
        try:
            data = json.loads(f'[{stdout.replace("][", ",")}]')
        except json.JSONDecodeError as exc:
            print(f'[WARN] Could not parse gh output: {exc}')
            return None

    if isinstance(data, list):
        all_alerts.extend(data)
    else:
        all_alerts.append(data)

    return all_alerts


# ── requests approach (works with PAT that has security_events scope) ─

def fetch_dependabot_alerts_requests(repo, token):
    """Fetch all open Dependabot alerts via requests (needs PAT)."""
    if requests is None:
        print('[ERROR] requests library required — pip install requests')
        return []

    url = f'{GITHUB_API}/repos/{repo}/dependabot/alerts'
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    params = {
        'state': 'open',
        'per_page': 100,
    }

    all_alerts = []
    page = 1

    while True:
        params['page'] = page
        resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 403:
            print('[WARN] Dependabot alerts API returned 403 — GITHUB_TOKEN '
                  'cannot access Dependabot alerts. Create a PAT with '
                  'security_events scope and store it as DEPENDABOT_PAT secret.')
            break
        if resp.status_code == 404:
            print('[WARN] Dependabot alerts not enabled or repo not found.')
            break

        resp.raise_for_status()
        alerts = resp.json()

        if not alerts:
            break

        all_alerts.extend(alerts)
        page += 1

    return all_alerts


def normalise(alert, repo):
    """Convert a Dependabot alert to the common finding format."""
    advisory = alert.get('security_advisory', {})
    vuln = alert.get('security_vulnerability', {})
    dep = alert.get('dependency', {})

    severity = SEVERITY_MAP.get(
        advisory.get('severity', 'medium').lower(), 'medium'
    )

    package_name = dep.get('package', {}).get('name', 'unknown')
    manifest_path = dep.get('manifest_path', 'package.json')
    vulnerable_range = vuln.get('vulnerable_version_range', '')
    patched_version = vuln.get('first_patched_version', {}).get('identifier', 'N/A')

    ghsa_id = advisory.get('ghsa_id', alert.get('number', 'unknown'))
    cve_id = advisory.get('cve_id', '')

    fix_hint = f'Upgrade `{package_name}` to `{patched_version}`.'
    if patched_version == 'N/A':
        fix_hint = f'No patched version available for `{package_name}`. Consider replacing the dependency.'

    return {
        'id': f'dependabot-{ghsa_id}',
        'source': 'dependabot',
        'rule_id': cve_id if cve_id else ghsa_id,
        'severity': severity,
        'file': manifest_path,
        'line': 0,
        'message': (
            f'{advisory.get("summary", "Vulnerability")} in `{package_name}` '
            f'(vulnerable: {vulnerable_range})'
        ),
        'help_url': advisory.get('permalink', alert.get('html_url', '')),
        'fixable': patched_version != 'N/A',
        'fix_hint': fix_hint,
        'package': package_name,
        'vulnerable_range': vulnerable_range,
        'patched_version': patched_version,
    }


def main():
    parser = argparse.ArgumentParser(description='Fetch and normalise Dependabot alerts')
    parser.add_argument('--repo', required=True, help='GitHub repository (owner/repo)')
    parser.add_argument('--token', required=True, help='GitHub token')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    print(f'[INFO] Fetching Dependabot alerts for {args.repo}')

    alerts = None

    # Prefer gh CLI — it works with the default GITHUB_TOKEN on Actions runners
    if _gh_available():
        print('[INFO] Using gh CLI to fetch Dependabot alerts ...')
        alerts = fetch_dependabot_alerts_gh(args.repo)
        if alerts is not None:
            print(f'[INFO] gh CLI retrieved {len(alerts)} open Dependabot alerts')

    # Fallback to requests (needs a PAT with security_events scope)
    if alerts is None:
        if requests is not None and args.token:
            print('[INFO] Falling back to requests library ...')
            alerts = fetch_dependabot_alerts_requests(args.repo, args.token)
            print(f'[INFO] requests retrieved {len(alerts)} open Dependabot alerts')
        else:
            print('[WARN] No method available to fetch Dependabot alerts. '
                  'Set DEPENDABOT_PAT secret with a PAT that has security_events scope.')
            alerts = []

    findings = [normalise(alert, args.repo) for alert in alerts]

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({'findings': findings}, f, indent=2)

    print(f'[INFO] Wrote {len(findings)} normalised findings to {args.output}')


if __name__ == '__main__':
    main()
