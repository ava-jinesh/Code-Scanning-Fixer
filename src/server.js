const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── VULNERABILITY: SQL Injection (CodeQL: js/sql-injection) ─────────
// This uses string concatenation with user input in a query
const sqlite3 = require('better-sqlite3');
const db = sqlite3('app.db');

app.get('/users', (req, res) => {
  const name = req.query.name;
  // BAD: user input directly interpolated into SQL query
  const query = `SELECT * FROM users WHERE name = '${name}'`;
  try {
    const rows = db.prepare(query).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── VULNERABILITY: Command Injection (CodeQL: js/command-line-injection) ──
app.post('/run-tool', (req, res) => {
  const tool = req.body.tool;
  // BAD: unsanitised user input passed directly to exec
  exec(`/usr/bin/${tool} --version`, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

// ─── VULNERABILITY: Path Traversal (CodeQL: js/path-injection) ───────
app.get('/files', (req, res) => {
  const filename = req.query.file;
  // BAD: no sanitisation of relative path components
  const filepath = path.join('/data/uploads', filename);
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// ─── VULNERABILITY: XSS / Reflected input (CodeQL: js/reflected-xss) ─
app.get('/search', (req, res) => {
  const query = req.query.q;
  // BAD: user input reflected directly in HTML response
  res.send(`<html><body><h1>Results for: ${query}</h1></body></html>`);
});

// ─── VULNERABILITY: Hardcoded credentials (CodeQL: js/hardcoded-credentials) ─
const DB_PASSWORD = 'SuperSecret123!';
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
  // BAD: merging user input without filtering __proto__
  Object.keys(req.body).forEach(key => {
    settings[key] = req.body[key];
  });
  res.json(settings);
});

// ─── VULNERABILITY: Insecure randomness (CodeQL: js/insecure-randomness) ─
app.get('/token', (req, res) => {
  // BAD: Math.random is not cryptographically secure
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
