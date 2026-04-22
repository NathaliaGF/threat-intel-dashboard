import assert from 'node:assert/strict';
import test from 'node:test';
import { detectType, normalizeQuery } from '../js/detectors.js';

test('detects IPv4 and IPv6 addresses', () => {
  assert.equal(detectType('8.8.8.8'), 'ip');
  assert.equal(detectType('2001:db8::1'), 'ip');
});

test('detects domains and URLs', () => {
  assert.equal(detectType('example.com'), 'domain');
  assert.equal(detectType('sub.example.co.uk'), 'domain');
  assert.equal(detectType('example.com/login'), 'url');
});

test('detects common hash lengths', () => {
  assert.equal(detectType('44d88612fea8a8f36de82e1278abb02f'), 'hash');
  assert.equal(detectType('3395856ce81f2b7382dee72602f798b642f14140'), 'hash');
  assert.equal(detectType('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'), 'hash');
});

test('normalizes browser-friendly input', () => {
  assert.equal(normalizeQuery(' HTTPS://Example.com/Login '), 'example.com/Login');
  assert.equal(normalizeQuery('https://example.com/login?token=secret'), 'example.com/login');
  assert.equal(normalizeQuery('Example.COM'), 'example.com');
});

test('rejects malformed indicators', () => {
  assert.equal(detectType('not a domain'), 'unknown');
  assert.equal(detectType('999.8.8.8'), 'unknown');
  assert.equal(detectType('example-.com'), 'unknown');
});
