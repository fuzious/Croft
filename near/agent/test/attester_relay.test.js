import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { attestationFromCheck, relayVerdict } from '../src/attester_relay.js';

const check = {
  verdict: 'allow', score: 0.3, reasons: ['no risk signals: account checks passed'],
  receiver_id: 'shop.test.near', signals: { code_hash: { value: '11111111111111111111111111111111', available: true } },
};

test('maps a /v1/check answer to submit_verdict arguments', () => {
  const a = attestationFromCheck(check, 1_000n, 3600);
  assert.deepEqual(a, {
    account_id: 'shop.test.near',
    code_hash: '11111111111111111111111111111111',
    verdict: 'allow',
    score_bps: 3000,
    reasons_hash: createHash('sha256').update(JSON.stringify(check.reasons)).digest('hex'),
    expires_at_ns: (1_000n + 3600n * 1_000_000_000n).toString(),
  });
});

test('missing code hash becomes an empty string; score is clamped to 0..10000 bps', () => {
  const a = attestationFromCheck({ ...check, score: 1.7, signals: { code_hash: { value: null } } }, 0n, 60);
  assert.equal(a.code_hash, '');
  assert.equal(a.score_bps, 10000);
});

test('refuses an answer without a known verdict', () => {
  assert.throws(() => attestationFromCheck({ ...check, verdict: 'maybe' }, 0n, 60), /verdict/);
});

test('relayVerdict refuses to attest when the service answers about another account', async (t) => {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ...check, receiver_id: 'other.test.near' }));
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  t.after(() => server.close());
  const calls = [];
  const attester = { accountId: 'attester.test.near', functionCall: async (args) => { calls.push(args); } };

  await assert.rejects(
    relayVerdict({ serviceUrl: `http://127.0.0.1:${server.address().port}`, attester, oracleId: 'oracle.test.near',
      accountId: 'shop.test.near', nowNs: 0n, log: () => {} }),
    /other\.test\.near.*shop\.test\.near|shop\.test\.near.*other\.test\.near/,
  );
  assert.equal(calls.length, 0, 'submit_verdict must not be called');
});
