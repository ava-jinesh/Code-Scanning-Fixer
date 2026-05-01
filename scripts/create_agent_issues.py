#!/usr/bin/env python3
"""
create_agent_issues.py
Reads the aggregated findings JSON and creates one GitHub Issue per
finding, assigned to @copilot for autonomous fixing.
"""
import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print('[ERROR] requests library required — pip install requests')
    sys.exit(1)

GITHUB_API = 'https://api.github.com'

ISSUE_BODY_TEMPLATE = """\
## Security Finding — {source} ({severity})

| Field | Value |
|-------|-------|
| **Tool** | {source} |
| **Rule** | `{rule_id}` |
| **Severity** | {severity} |
| **File** | `{file}` |
| **Line** | {line} |
| **Fingerprint** | `{fingerprint}` |
| **Workflow Run** | [{run_id}](https://github.com/{repo}/actions/runs/{run_id}) |

### Description

{message}

### Suggested Fix

{fix_hint}

### Reference

{help_url}

---

> **Instructions for @copilot:**
> 1. Check out this repository
> 2. Locate `{file}` at line {line}
> 3. Apply the suggested fix following `.github/copilot-instructions.md`
> 4. Run `npm test` — do **not** open a PR if tests fail
> 5. Open a Pull Request linking back to this Issue
"""


def create_issue(repo, token, finding, run_id):
    """Create a single GitHub Issue assigned to @copilot."""
    url = f'{GITHUB_API}/repos/{repo}/issues'
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }

    severity = finding.get('severity', 'unknown')
    source = finding.get('source', 'unknown')
    rule_id = finding.get('rule_id', 'N/A')
    file_path = finding.get('file', 'unknown')

    title = f'[{severity.upper()}] {source}: {rule_id} in {file_path}'

    body = ISSUE_BODY_TEMPLATE.format(
        source=source,
        severity=severity.upper(),
        rule_id=rule_id,
        file=file_path,
        line=finding.get('line', '?'),
        fingerprint=finding.get('fingerprint', 'N/A'),
        run_id=run_id,
        repo=repo,
        message=finding.get('message', 'No description provided.'),
        fix_hint=finding.get('fix_hint', 'Review and fix according to the rule documentation.'),
        help_url=finding.get('help_url', 'N/A'),
    )

    labels = ['security', f'severity:{severity.lower()}', f'tool:{source}', 'copilot-autofix']

    payload = {
        'title': title,
        'body': body,
        'assignees': ['copilot'],
        'labels': labels,
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=30)

    if resp.status_code == 201:
        issue_url = resp.json().get('html_url', '')
        print(f'[OK]   Created issue: {issue_url}')
        return True
    elif resp.status_code == 422:
        errors = resp.json().get('errors', [])
        assignee_invalid = any(e.get('field') == 'assignees' for e in errors)

        # Retry without assignee if @copilot is not available
        if assignee_invalid:
            print('[WARN] @copilot assignee not available — creating unassigned issue.')
            payload.pop('assignees', None)
            resp2 = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp2.status_code == 201:
                issue_url = resp2.json().get('html_url', '')
                print(f'[OK]   Created issue (unassigned): {issue_url}')
                return True
            elif resp2.status_code == 422:
                # Labels may also not exist — retry with minimal labels
                payload['labels'] = ['security']
                resp3 = requests.post(url, headers=headers, json=payload, timeout=30)
                if resp3.status_code == 201:
                    issue_url = resp3.json().get('html_url', '')
                    print(f'[OK]   Created issue (minimal): {issue_url}')
                    return True
                print(f'[FAIL] Could not create issue: {resp3.status_code} {resp3.text}')
                return False
            print(f'[FAIL] Could not create issue: {resp2.status_code} {resp2.text}')
            return False

        # Label validation error — retry without custom labels
        payload['labels'] = ['security']
        resp2 = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp2.status_code == 201:
            issue_url = resp2.json().get('html_url', '')
            print(f'[OK]   Created issue (minimal labels): {issue_url}')
            return True
        print(f'[FAIL] Could not create issue: {resp2.status_code} {resp2.text}')
        return False
    else:
        print(f'[FAIL] Could not create issue: {resp.status_code} {resp.text}')
        return False


def main():
    parser = argparse.ArgumentParser(description='Create GitHub Issues for Copilot agent')
    parser.add_argument('--findings', required=True, help='Path to aggregated findings JSON')
    parser.add_argument('--repo', required=True, help='GitHub repository (owner/repo)')
    parser.add_argument('--token', required=True, help='GitHub token with issues:write')
    parser.add_argument('--max-issues', type=int, default=10, help='Maximum issues to create')
    parser.add_argument('--run-id', default='manual', help='GitHub Actions run ID')
    args = parser.parse_args()

    with open(args.findings, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = data.get('findings', [])
    if not findings:
        print('[INFO] No findings to process. Exiting.')
        return

    to_create = findings[:args.max_issues]
    print(f'[INFO] Creating {len(to_create)} issues (max {args.max_issues}) assigned to @copilot ...')

    created = 0
    for finding in to_create:
        ok = create_issue(args.repo, args.token, finding, args.run_id)
        if ok:
            created += 1
        # Respect GitHub API rate limits
        time.sleep(1)

    print(f'[INFO] Done. Created {created}/{len(to_create)} issues.')


if __name__ == '__main__':
    main()
