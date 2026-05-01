const test = require('node:test');
const assert = require('node:assert/strict');

const { safeJoinWithinRoot, isSafeRedirectTarget } = require('./security');

test('safeJoinWithinRoot prevents path traversal', () => {
  const root = '/var/app/uploads';

  assert.equal(safeJoinWithinRoot(root, 'a/b.txt'), '/var/app/uploads/a/b.txt');
  assert.equal(safeJoinWithinRoot(root, '../secret.txt'), null);
  assert.equal(safeJoinWithinRoot(root, '..\\secret.txt'), null);
});

test('isSafeRedirectTarget only allows relative paths', () => {
  assert.equal(isSafeRedirectTarget('/dashboard'), true);
  assert.equal(isSafeRedirectTarget('dashboard'), true);
  assert.equal(isSafeRedirectTarget('https://evil.example/'), false);
  assert.equal(isSafeRedirectTarget('//evil.example/'), false);
  assert.equal(isSafeRedirectTarget('\\\\evil.example\\share'), false);
});
