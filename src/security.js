const path = require('path');

function safeJoinWithinRoot(rootDir, userPath) {
  if (typeof userPath !== 'string') return null;

  // Treat user input as a path segment, normalise, and reject anything
  // that escapes the root (including Windows-style separators).
  const normalised = userPath.replace(/\\/g, '/');
  const resolvedPath = path.resolve(rootDir, normalised);
  const resolvedRoot = path.resolve(rootDir);

  const rel = path.relative(resolvedRoot, resolvedPath);
  if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
    return resolvedPath;
  }
  return null;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function filterPrototypePollution(input) {
  if (!input || typeof input !== 'object') return {};
  const blocked = new Set(['__proto__', 'prototype', 'constructor']);
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (blocked.has(key)) continue;
    output[key] = value;
  }
  return output;
}

function isSafeRedirectTarget(target) {
  if (typeof target !== 'string') return false;
  // Allow only relative paths (no scheme, no protocol-relative, no backslashes)
  if (target.startsWith('http://') || target.startsWith('https://')) return false;
  if (target.startsWith('//')) return false;
  if (target.includes('\\')) return false;
  return target.startsWith('/') || /^[A-Za-z0-9._~!$&'()*+,;=:@/-]+$/.test(target);
}

module.exports = {
  safeJoinWithinRoot,
  escapeHtml,
  filterPrototypePollution,
  isSafeRedirectTarget,
};

