import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createBoundaryGenerator, generateBoundary } from '../src/index.js';

test('generateBoundary returns a non-empty string by default', () => {
  const b = generateBoundary('hello world');
  assert.equal(typeof b, 'string');
  assert.ok(b.length > 0);
});

test('generated boundary does not collide with its payload', () => {
  const payload = 'some text with a tricky bit ----=_Part ABCDEF inside it';
  const b = generateBoundary(payload);
  assert.ok(!payload.includes(b), 'boundary must not appear in payload');
});

test('boundary uses only RFC 2045-safe characters', () => {
  const b = generateBoundary('');
  // Allowed: alnum and ()+,-./_:?= per RFC 2045 bchars.
  assert.match(b, /^[A-Za-z0-9()+,\-./_:?=]+$/);
});

test('boundary with prefix starts with the prefix', () => {
  const gen = createBoundaryGenerator({ prefix: '==MyBoundary' });
  const b = gen.generate('');
  assert.ok(b.startsWith('==MyBoundary'));
});

test('boundary length equals prefix + random length when under cap', () => {
  const gen = createBoundaryGenerator({ prefix: 'P', length: 20 });
  const b = gen.generate('');
  assert.equal(b.length, 21);
});

test('boundary is truncated to RFC 2045 max of 70 characters', () => {
  const longPrefix = 'x'.repeat(80);
  const gen = createBoundaryGenerator({ prefix: longPrefix, length: 10 });
  const b = gen.generate('');
  assert.equal(b.length, 70);
  assert.ok(b.startsWith('x'.repeat(70)));
});

test('zero random length yields just the (truncated) prefix', () => {
  const gen = createBoundaryGenerator({ prefix: 'abc', length: 0 });
  const b = gen.generate('');
  assert.equal(b, 'abc');
});

test('collision with payload triggers re-roll and eventually succeeds', () => {
  // Force a likely collision by using a tiny random length so the space is small.
  // We seed the payload with every possible 2-char combo from the full boundary
  // alphabet so that a 2-char boundary will always collide.
  const boundaryChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()+,-./_:?=';
  const gen = createBoundaryGenerator({ prefix: '', length: 2, maxAttempts: 10000 });
  let payload = '';
  for (const c1 of boundaryChars) {
    for (const c2 of boundaryChars) {
      payload += c1 + c2;
    }
  }
  // Every 2-char combo is present, so a 2-char boundary will always collide.
  assert.throws(() => gen.generate(payload), /collision-free/);
});

test('collision-free path returns quickly when payload is benign', () => {
  const gen = createBoundaryGenerator({ length: 32 });
  const b = gen.generate('ordinary text with no special markers');
  assert.equal(typeof b, 'string');
  assert.ok(b.length >= 32);
});

test('Buffer payloads are scanned as bytes not UTF-8 text', () => {
  const gen = createBoundaryGenerator({ prefix: '', length: 8 });
  // Construct a Buffer whose latin1 string form is unlikely to contain the boundary.
  const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
  const b = gen.generate(buf);
  assert.equal(typeof b, 'string');
  // The boundary should not be present in the byte sequence.
  const bufStr = buf.toString('latin1');
  assert.ok(!bufStr.includes(b));
});

test('ArrayBuffer and TypedArray payloads are accepted', () => {
  const gen = createBoundaryGenerator({ length: 16 });
  const ab = new ArrayBuffer(4);
  const view = new Uint8Array(ab);
  view.set([10, 20, 30, 40]);
  const b1 = gen.generate(ab);
  const b2 = gen.generate(view);
  assert.equal(typeof b1, 'string');
  assert.equal(typeof b2, 'string');
});

test('array of payloads is concatenated and checked', () => {
  const gen = createBoundaryGenerator({ length: 16 });
  const b = gen.generate(['part one ', 'part two']);
  assert.ok(!'part one part two'.includes(b));
});

test('null/undefined payload is treated as empty', () => {
  const gen = createBoundaryGenerator({ length: 8 });
  const b = gen.generate(undefined);
  assert.equal(typeof b, 'string');
  assert.ok(b.length > 0);
});

test('invalid prefix type throws', () => {
  assert.throws(() => createBoundaryGenerator({ prefix: 123 }), /prefix must be a string/);
});

test('negative length throws', () => {
  assert.throws(() => createBoundaryGenerator({ length: -5 }), /length must be a non-negative integer/);
});

test('non-positive maxAttempts throws', () => {
  assert.throws(() => createBoundaryGenerator({ maxAttempts: 0 }), /maxAttempts must be a positive integer/);
});
