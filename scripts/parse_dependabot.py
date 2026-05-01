#!/usr/bin/env python3
"""
parse_dependabot.py
Fetches open Dependabot alerts from the GitHub API and normalises
them into the common findings JSON format used by aggregate_findings.py.
"""
import argparse
import json
import sys

try:
    import requests
except ImportError:
    print('[ERROR] requests library required — pip install requests')
    sys.exit(1)

GITHUB_API = 'https://api.github.com'

SEVERITY_MAP = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
}


def fetch_dependabot_alerts(repo, token):
    """Fetch all open Dependabot alerts for the given repository."""
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
            print('[WARN] Dependabot alerts API returned 403 — check token permissions.')
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
    parser.add_argument('--token', required=True, help='GitHub token with security_events scope')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    print(f'[INFO] Fetching Dependabot alerts for {args.repo}')
    alerts = fetch_dependabot_alerts(args.repo, args.token)
    print(f'[INFO] Retrieved {len(alerts)} open Dependabot alerts')

    findings = [normalise(alert, args.repo) for alert in alerts]

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({'findings': findings}, f, indent=2)

    print(f'[INFO] Wrote {len(findings)} normalised findings to {args.output}')


if __name__ == '__main__':
    main()
