# Copilot Instructions for Security AutoFix

## Context
This repository uses automated security scanning (CodeQL + Dependabot) to detect
vulnerabilities. Issues assigned to you contain structured findings with file paths,
line numbers, rule IDs, and suggested fixes.

## Fix Guidelines

1. **Read the issue carefully** — every issue includes the exact file, line number,
   rule ID, and a fix hint.
2. **Apply the minimal secure fix** — do not refactor unrelated code.
3. **For CodeQL findings:**
   - SQL injection → use parameterised queries / prepared statements.
   - Command injection → use `execFile` with argument arrays; never pass user input to `exec`.
   - Path traversal → validate/resolve paths and ensure they stay within the expected root.
   - XSS → escape or sanitise user input before reflecting it in HTML.
   - Hardcoded credentials → move secrets to environment variables.
   - Insecure randomness → use `crypto.randomBytes` or `crypto.randomUUID`.
4. **For Dependabot findings:**
   - Upgrade the vulnerable package to the patched version listed in the issue.
   - Run `npm install` and commit the updated `package-lock.json`.
5. **Run `npm test`** before opening a PR. Do not open a PR if tests fail.
6. **Link the PR** back to the originating issue using `Fixes #<issue-number>`.
