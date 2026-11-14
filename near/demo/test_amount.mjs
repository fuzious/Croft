import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decimalToYocto } from './amount.mjs';

test('preserves tiny amounts and all 24 decimal places exactly', () => {
  assert.equal(decimalToYocto('0.000000000000000000000001'), '1');
  assert.equal(decimalToYocto('1.123456789012345678901234'), '1123456789012345678901234');
  assert.equal(decimalToYocto(' 0.0000001 '), '100000000000000000');
  assert.equal(decimalToYocto('0'), '0');
  assert.equal(decimalToYocto('340282366920938.463463374607431768211455'), (2n ** 128n - 1n).toString());
});

test('rejects ambiguous, rounded and out-of-range input', () => {
  for (const value of ['', 'NaN', '1e-7', '-1', '1,000', '0.0000000000000000000000001',
    '340282366920938.463463374607431768211456', 0.1]) {
    assert.throws(() => decimalToYocto(value));
  }
});
