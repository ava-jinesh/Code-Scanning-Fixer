#!/usr/bin/env python3
"""
aggregate_findings.py
Reads normalised JSON outputs from CodeQL, SonarQube, and Dependabot,
deduplicates them, and writes a single aggregated findings file.
"""
import argparse
import glob
import hashlib
import json
import os
import sys

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def severity_rank(sev):
    return SEVERITY_ORDER.get(sev.lower(), 99)


def passes_threshold(severity, min_severity):
    if min_severity.lower() == 'all':
        return True
    return severity_rank(severity) <= severity_rank(min_severity)


def fingerprint(finding):
    """Create a stable fingerprint for deduplication."""
    key = f"{finding.get('file', '')}:{finding.get('line', '')}:{finding.get('rule_id', '')}:{finding.get('message', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def load_findings_from_dir(input_dir):
    """Load all *-findings.json files from the artifact directory tree."""
    findings = []
    patterns = [
        os.path.join(input_dir, '**', '*findings*.json'),
        os.path.join(input_dir, '*findings*.json'),
    ]
    seen_files = set()
    for pattern in patterns:
        for filepath in glob.glob(pattern, recursive=True):
            real = os.path.realpath(filepath)
            if real in seen_files:
                continue
            seen_files.add(real)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    findings.extend(data)
                elif isinstance(data, dict) and 'findings' in data:
                    findings.extend(data['findings'])
                else:
                    print(f'[WARN] Unexpected format in {filepath}, skipping.')
            except (json.JSONDecodeError, IOError) as exc:
                print(f'[WARN] Could not read {filepath}: {exc}')
    return findings


def deduplicate(findings):
    """Remove duplicates based on file + line + rule_id + message."""
    seen = {}
    deduped = []
    for f in findings:
        fp = fingerprint(f)
        if fp not in seen:
            seen[fp] = True
            f['fingerprint'] = fp
            deduped.append(f)
    return deduped


def build_summary(findings):
    counts = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'dependencies': 0}
    for f in findings:
        counts['total'] += 1
        sev = f.get('severity', 'low').lower()
        if sev in counts:
            counts[sev] += 1
        if f.get('source') == 'dependabot':
            counts['dependencies'] += 1
    counts['issues_to_create'] = counts['total']
    return counts


def main():
    parser = argparse.ArgumentParser(description='Aggregate security scan findings')
    parser.add_argument('--input-dir', required=True, help='Directory containing scan result artifacts')
    parser.add_argument('--output', required=True, help='Output aggregated JSON file')
    parser.add_argument('--min-severity', default='medium', help='Minimum severity threshold')
    args = parser.parse_args()

    raw_findings = load_findings_from_dir(args.input_dir)
    print(f'[INFO] Loaded {len(raw_findings)} raw findings from {args.input_dir}')

    # Filter by severity threshold
    filtered = [f for f in raw_findings if passes_threshold(f.get('severity', 'low'), args.min_severity)]
    print(f'[INFO] {len(filtered)} findings at or above {args.min_severity} severity')

    # Deduplicate
    deduped = deduplicate(filtered)
    print(f'[INFO] {len(deduped)} unique findings after deduplication')

    # Sort: critical first
    deduped.sort(key=lambda f: severity_rank(f.get('severity', 'low')))

    summary = build_summary(deduped)
    summary['issues_to_create'] = len(deduped)

    output = {
        'summary': summary,
        'findings': deduped,
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f'[INFO] Wrote {len(deduped)} findings to {args.output}')

    if summary['critical'] > 0:
        print(f'[ALERT] {summary["critical"]} CRITICAL findings detected!')


if __name__ == '__main__':
    main()
