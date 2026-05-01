#!/usr/bin/env python3
"""
parse_codeql_sarif.py
Converts CodeQL SARIF output into the common findings JSON format
used by aggregate_findings.py.
"""
import argparse
import json
import sys


CODEQL_SEVERITY_MAP = {
    'error': 'high',
    'warning': 'medium',
    'note': 'low',
    'none': 'low',
}

SECURITY_SEVERITY_MAP = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
}


def parse_sarif(sarif_path):
    """Parse a SARIF file and return normalised findings."""
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif = json.load(f)

    findings = []

    for run in sarif.get('runs', []):
        # Build a rule lookup for help URLs and descriptions
        rules = {}
        tool_driver = run.get('tool', {}).get('driver', {})
        for rule in tool_driver.get('rules', []):
            rules[rule.get('id', '')] = rule

        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'unknown')
            rule_meta = rules.get(rule_id, {})

            # Determine severity: prefer security-severity tag, fall back to level
            severity = 'medium'
            props = rule_meta.get('properties', {})
            sec_sev = props.get('security-severity', '')
            if sec_sev:
                try:
                    score = float(sec_sev)
                    if score >= 9.0:
                        severity = 'critical'
                    elif score >= 7.0:
                        severity = 'high'
                    elif score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                except ValueError:
                    severity = SECURITY_SEVERITY_MAP.get(sec_sev.lower(), 'medium')
            else:
                level = result.get('level', 'warning')
                severity = CODEQL_SEVERITY_MAP.get(level, 'medium')

            # Extract location
            locations = result.get('locations', [])
            file_path = 'unknown'
            line = 0
            if locations:
                phys = locations[0].get('physicalLocation', {})
                artifact = phys.get('artifactLocation', {})
                file_path = artifact.get('uri', 'unknown')
                region = phys.get('region', {})
                line = region.get('startLine', 0)

            # Help URL
            help_url = ''
            help_obj = rule_meta.get('help', {})
            if isinstance(help_obj, dict):
                help_url = help_obj.get('markdown', help_obj.get('text', ''))
            help_uri = rule_meta.get('helpUri', '')
            if help_uri:
                help_url = help_uri

            # Message
            message = result.get('message', {}).get('text', 'No description.')

            # Fix hint from rule description
            desc = rule_meta.get('shortDescription', {}).get('text', '')
            fix_hint = desc if desc else f'Fix {rule_id} per CodeQL documentation.'

            findings.append({
                'id': f'codeql-{rule_id}-{file_path}-{line}',
                'source': 'codeql',
                'rule_id': rule_id,
                'severity': severity,
                'file': file_path,
                'line': line,
                'message': message,
                'help_url': help_url,
                'fixable': True,
                'fix_hint': fix_hint,
            })

    return findings


def main():
    parser = argparse.ArgumentParser(description='Convert CodeQL SARIF to normalised findings JSON')
    parser.add_argument('--input', required=True, help='Path to SARIF file')
    parser.add_argument('--output', required=True, help='Output JSON file')
    args = parser.parse_args()

    findings = parse_sarif(args.input)
    print(f'[INFO] Parsed {len(findings)} findings from CodeQL SARIF')

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({'findings': findings}, f, indent=2)

    print(f'[INFO] Wrote findings to {args.output}')


if __name__ == '__main__':
    main()
