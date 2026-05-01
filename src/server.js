const express = require('express');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { safeJoinWithinRoot, escapeHtml, filterPrototypePollution } = require('./security');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── VULNERABILITY: SQL Injection (CodeQL: js/sql-injection) ─────────
// This uses string concatenation with user input in a query
// For the demo app we keep this in-memory and avoid native modules.
const users = [
  { id: 1, name: 'alice' },
  { id: 2, name: 'bob' },
];

app.get('/users', (req, res) => {
  const name = req.query.name;
  try {
    const rows = typeof name === 'string' ? users.filter(u => u.name === name) : users;
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── VULNERABILITY: Command Injection (CodeQL: js/command-line-injection) ──
app.post('/run-tool', (req, res) => {
  const tool = req.body.tool;
  // Allowlist tools to avoid command injection.
  const allowlist = new Set(['node', 'npm']);
  if (!allowlist.has(tool)) return res.status(400).send('Tool not allowed');

  execFile(`/usr/bin/${tool}`, ['--version'], (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr || err.message);
    res.send(stdout);
  });
});

// ─── VULNERABILITY: Path Traversal (CodeQL: js/path-injection) ───────
app.get('/files', (req, res) => {
  const filename = req.query.file;
  const filepath = safeJoinWithinRoot('/data/uploads', filename);
  if (!filepath) return res.status(400).send('Invalid file path');

  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// ─── VULNERABILITY: XSS / Reflected input (CodeQL: js/reflected-xss) ─
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<html><body><h1>Results for: ${escapeHtml(query)}</h1></body></html>`);
});

// ─── VULNERABILITY: Hardcoded credentials (CodeQL: js/hardcoded-credentials) ─
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const config = {
  host: 'db.example.com',
  user: 'admin',
  password: DB_PASSWORD,
};

// ─── VULNERABILITY: Missing rate limiting on auth endpoint ───────────
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // BAD: no rate limiting, no brute-force protection
  if (!config.password) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  if (username === 'admin' && password === config.password) {
    res.json({ token: 'fake-jwt-token' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ─── VULNERABILITY: Prototype Pollution (CodeQL: js/prototype-polluting-assignment) ─
app.post('/settings', (req, res) => {
  const settings = filterPrototypePollution(req.body);
  res.json(settings);
});

// ─── VULNERABILITY: Insecure randomness (CodeQL: js/insecure-randomness) ─
app.get('/token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
