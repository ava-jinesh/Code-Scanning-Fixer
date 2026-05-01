#!/usr/bin/env python3
"""
create_agent_issues.py
Reads the aggregated findings JSON and creates one GitHub Issue per
finding, assigned to an AI agent (copilot, claude, codex) for autonomous fixing.
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

# Map agent names to GitHub assignee usernames
AGENT_ASSIGNEES = {
    'copilot': 'copilot',
    'claude':  'claude',
    'codex':   'codex',
    'none':    None,
}

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

{agent_mention}

> **Instructions for the AI agent:**
> 1. Check out this repository
> 2. Locate `{file}` at line {line}
> 3. Apply the suggested fix following `.github/copilot-instructions.md`
> 4. Run `npm test` — do **not** open a PR if tests fail
> 5. Open a Pull Request linking back to this Issue
"""

# Agent @mention triggers — these go into the issue body so the agent picks it up
AGENT_MENTIONS = {
    'copilot': '@copilot',
    'claude':  '@claude fix this issue',
    'codex':   '@codex fix this issue',
    'none':    '',
}


def create_issue(repo, token, finding, run_id, assignee=None, agent_name='none'):
    """Create a single GitHub Issue, then assign to the AI agent separately."""
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

    agent_mention = AGENT_MENTIONS.get(agent_name, '')

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
        agent_mention=agent_mention,
    )

    labels = ['security', f'severity:{severity.lower()}', f'tool:{source}']

    # Step 1: Create issue WITHOUT assignee (avoids 422 validation)
    payload = {
        'title': title,
        'body': body,
        'labels': labels,
    }

    resp = _post_issue(url, headers, payload)

    # Retry without labels if they don't exist
    if resp.status_code == 422:
        payload.pop('labels', None)
        resp = _post_issue(url, headers, payload)

    if resp.status_code != 201:
        print(f'[FAIL] Could not create issue: {resp.status_code} {resp.text}')
        return False

    issue_data = resp.json()
    issue_number = issue_data.get('number')
    _log_created(resp)

    # Step 2: Assign agent via the assignment API (same as manual assignment)
    if assignee:
        _assign_agent(repo, headers, issue_number, assignee)

    # Step 3: Post @mention comment as backup trigger
    _post_agent_comment(repo, token, headers, issue_data, agent_name)

    return True


def _post_issue(url, headers, payload):
    return requests.post(url, headers=headers, json=payload, timeout=30)


def _log_created(resp, note=''):
    issue_url = resp.json().get('html_url', '')
    print(f'[OK]   Created issue {note}: {issue_url}'.strip())


def _assign_agent(repo, headers, issue_number, assignee):
    """Assign agent to issue using the assignment API (same as manual UI)."""
    url = f'{GITHUB_API}/repos/{repo}/issues/{issue_number}/assignees'
    resp = requests.post(
        url,
        headers=headers,
        json={'assignees': [assignee]},
        timeout=30,
    )
    if resp.status_code == 201:
        print(f'[OK]   Assigned @{assignee} to #{issue_number}')
    else:
        print(f'[WARN] Could not assign @{assignee} to #{issue_number}: '
              f'{resp.status_code} — issue created but unassigned')


def _post_agent_comment(repo, token, headers, issue_data, agent_name):
    """Post a comment @mentioning the agent to trigger it."""
    if agent_name == 'none' or not agent_name:
        return
    mention = AGENT_MENTIONS.get(agent_name, '')
    if not mention:
        return
    issue_number = issue_data.get('number')
    if not issue_number:
        return
    comment_url = f'{GITHUB_API}/repos/{repo}/issues/{issue_number}/comments'
    comment_body = f'{mention}\n\nPlease fix the security vulnerability described in this issue.'
    resp = requests.post(
        comment_url,
        headers=headers,
        json={'body': comment_body},
        timeout=30,
    )
    if resp.status_code == 201:
        print(f'[OK]   Posted {mention} trigger comment on #{issue_number}')
    else:
        print(f'[WARN] Could not post agent comment on #{issue_number}: {resp.status_code}')


def main():
    parser = argparse.ArgumentParser(description='Create GitHub Issues for AI agent')
    parser.add_argument('--findings', required=True, help='Path to aggregated findings JSON')
    parser.add_argument('--repo', required=True, help='GitHub repository (owner/repo)')
    parser.add_argument('--token', required=True, help='GitHub token with issues:write')
    parser.add_argument('--max-issues', type=int, default=10, help='Maximum issues to create')
    parser.add_argument('--run-id', default='manual', help='GitHub Actions run ID')
    parser.add_argument('--assignee', default='copilot',
                        choices=['copilot', 'claude', 'codex', 'none'],
                        help='AI agent to assign issues to')
    args = parser.parse_args()

    with open(args.findings, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = data.get('findings', [])
    if not findings:
        print('[INFO] No findings to process. Exiting.')
        return

    assignee = AGENT_ASSIGNEES.get(args.assignee)
    agent_label = f'@{args.assignee}' if assignee else 'no agent'
    to_create = findings[:args.max_issues]
    print(f'[INFO] Creating {len(to_create)} issues (max {args.max_issues}) assigned to {agent_label} ...')

    created = 0
    for finding in to_create:
        ok = create_issue(args.repo, args.token, finding, args.run_id,
                          assignee=assignee, agent_name=args.assignee)
        if ok:
            created += 1
        # Respect GitHub API rate limits
        time.sleep(1)

    print(f'[INFO] Done. Created {created}/{len(to_create)} issues.')

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
