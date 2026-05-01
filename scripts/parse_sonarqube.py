#!/usr/bin/env python3
"""
parse_sonarqube.py
Fetches issues from SonarQube Web API and normalises them into the
common findings JSON format used by aggregate_findings.py.
"""
import argparse
import json
import sys

try:
    import requests
except ImportError:
    print('[ERROR] requests library required — pip install requests')
    sys.exit(1)

SEVERITY_MAP = {
    'BLOCKER': 'critical',
    'CRITICAL': 'critical',
    'MAJOR': 'high',
    'MINOR': 'medium',
    'INFO': 'low',
}


def fetch_issues(host, token, project_key, page_size=100):
    """Fetch all open issues from SonarQube for the given project."""
    url = f'{host.rstrip("/")}/api/issues/search'
    issues = []
    page = 1

    while True:
        params = {
            'componentKeys': project_key,
            'statuses': 'OPEN,CONFIRMED,REOPENED',
            'types': 'VULNERABILITY,BUG,CODE_SMELL',
            'ps': page_size,
            'p': page,
        }
        resp = requests.get(url, params=params, auth=(token, ''), timeout=30)
        resp.raise_for_status()
        data = resp.json()

        issues.extend(data.get('issues', []))
        total = data.get('paging', {}).get('total', 0)

        if page * page_size >= total:
            break
        page += 1

    return issues


def normalise(issue, host):
    """Convert a SonarQube issue to the common finding format."""
    component = issue.get('component', '')
    # component is like "project-key:src/foo.js"
    file_path = component.split(':', 1)[-1] if ':' in component else component

    severity = SEVERITY_MAP.get(issue.get('severity', 'INFO'), 'low')
    rule = issue.get('rule', 'unknown')
    line = issue.get('line', 0)

    return {
        'id': issue.get('key', ''),
        'source': 'sonarqube',
        'rule_id': rule,
        'severity': severity,
        'file': file_path,
        'line': line,
        'message': issue.get('message', ''),
        'help_url': f'{host.rstrip("/")}/coding_rules?open={rule}&rule_key={rule}',
        'fixable': True,
        'fix_hint': issue.get('message', 'Review and fix per SonarQube rule documentation.'),
    }


def main():
    parser = argparse.ArgumentParser(description='Fetch and normalise SonarQube issues')
    parser.add_argument('--host', required=True, help='SonarQube server URL')
    parser.add_argument('--token', required=True, help='SonarQube authentication token')
    parser.add_argument('--project', required=True, help='SonarQube project key')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    print(f'[INFO] Fetching issues from SonarQube for project: {args.project}')
    raw_issues = fetch_issues(args.host, args.token, args.project)
    print(f'[INFO] Retrieved {len(raw_issues)} issues from SonarQube')

    findings = [normalise(issue, args.host) for issue in raw_issues]

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({'findings': findings}, f, indent=2)

    print(f'[INFO] Wrote {len(findings)} normalised findings to {args.output}')


if __name__ == '__main__':
    main()
