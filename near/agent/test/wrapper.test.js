import { test } from 'node:test';
import assert from 'node:assert/strict';
import { payWithOracle, routerPayOutcome, assertRouterScopedKey, nearToYocto } from '../src/wrapper.js';

const ONE = '1000000000000000000000000';

function deps(verdict, extra = {}) {
  const calls = { checks: [], signs: [], logs: [], asks: [] };
  return {
    calls,
    agentId: 'agent.human.test.near',
    check: async (body) => { calls.checks.push(body); return verdict; },
    signPay: async (receiverId, amountYocto) => { calls.signs.push([receiverId, amountYocto]); return { paid: true, events: [] }; },
    log: (line) => calls.logs.push(line),
    interactive: false,
    ...extra,
  };
}

test('nearToYocto converts decimal NEAR to a yocto string', () => {
  assert.equal(nearToYocto('2'), '2' + '0'.repeat(24));
  assert.equal(nearToYocto('0.5'), '5' + '0'.repeat(23));
  assert.throws(() => nearToYocto('-1'));
  assert.throws(() => nearToYocto('abc'));
});

test('sends agent_id, receiver_id and deposit_yocto to /v1/check', async () => {
  const d = deps({ verdict: 'allow', reasons: ['ok'] });
  await payWithOracle({ receiver: 'shop.test.near', amount: '1', reason: 'invoice' }, d);
  assert.deepEqual(d.calls.checks, [{ agent_id: 'agent.human.test.near', receiver_id: 'shop.test.near', deposit_yocto: ONE }]);
});

test('block: refuses to sign and logs the reasons', async () => {
  const d = deps({ verdict: 'block', reasons: ['the on-chain security oracle lists the receiver as blocked'] });
  const r = await payWithOracle({ receiver: 'bad.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'refused');
  assert.equal(d.calls.signs.length, 0);
  assert.ok(d.calls.logs.some((l) => l.includes('lists the receiver as blocked')));
});

test('warn: asks the human; a no means no signature', async () => {
  const d = deps({ verdict: 'warn', reasons: ['account is 0 days old (under 7)'] }, {
    approve: async (q) => { d.calls.asks.push(q); return false; },
  });
  const r = await payWithOracle({ receiver: 'new.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'declined');
  assert.equal(d.calls.signs.length, 0);
  assert.equal(d.calls.asks.length, 1);
  assert.equal(d.calls.asks[0].reasons[0], 'account is 0 days old (under 7)');
});

test('warn: a yes from the human signs router.pay', async () => {
  const d = deps({ verdict: 'warn', reasons: ['r'] }, { approve: async () => true });
  const r = await payWithOracle({ receiver: 'new.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'paid');
  assert.deepEqual(d.calls.signs, [['new.test.near', ONE]]);
});

test('warn without an approver in a non-interactive run is denied', async () => {
  const d = deps({ verdict: 'warn', reasons: ['r'] });
  const r = await payWithOracle({ receiver: 'new.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'declined');
  assert.equal(d.calls.signs.length, 0);
});

test('allow: signs router.pay with the amount in yocto', async () => {
  const d = deps({ verdict: 'allow', reasons: ['no risk signals'] });
  const r = await payWithOracle({ receiver: 'shop.test.near', amount: '2', reason: 'invoice' }, d);
  assert.equal(r.status, 'paid');
  assert.deepEqual(d.calls.signs, [['shop.test.near', '2' + '0'.repeat(24)]]);
});

test('allow but the router refuses on chain: reports refused_on_chain with the reason', async () => {
  const d = deps({ verdict: 'allow', reasons: [] }, {
    signPay: async () => ({ paid: false, events: [{ event: 'payment_refused', data: [{ reason: 'no_verdict' }] }] }),
  });
  const r = await payWithOracle({ receiver: 'shop.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'refused_on_chain');
  assert.equal(r.onChainReason, 'no_verdict');
});

test('reads the refusal reason from a near-sdk event whose data is an object', async () => {
  const d = deps({ verdict: 'allow', reasons: [] }, {
    signPay: async () => ({ paid: false, events: [{ event: 'payment_refused', data: { reason: 'receiver_blocked' } }] }),
  });
  const r = await payWithOracle({ receiver: 'shop.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.onChainReason, 'receiver_blocked');
});

test('oracle unreachable is treated as warn (ask the human), never as allow', async () => {
  const d = deps(null, { check: async () => { throw new Error('ECONNREFUSED'); } });
  const r = await payWithOracle({ receiver: 'shop.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'declined');
  assert.equal(r.verdict, 'warn');
  assert.ok(r.reasons[0].includes('ECONNREFUSED'));
  assert.equal(d.calls.signs.length, 0);
});

test('an unknown verdict value is treated as block', async () => {
  const d = deps({ verdict: 'maybe', reasons: [] });
  const r = await payWithOracle({ receiver: 'shop.test.near', amount: '1', reason: 'x' }, d);
  assert.equal(r.status, 'refused');
  assert.equal(d.calls.signs.length, 0);
});

const b64 = (s) => Buffer.from(s).toString('base64');
const outcome = (ret, logs) => ({
  status: { SuccessValue: b64(ret) },
  transaction_outcome: { outcome: { logs: [] } },
  receipts_outcome: logs.map((l) => ({ outcome: { logs: [l] } })),
});

test('routerPayOutcome reads the return value and NEP-297 events', () => {
  const ev = { standard: 'guarded_router', version: '1.0.0', event: 'payment_refused', data: [{ reason: 'receiver_blocked' }] };
  const r = routerPayOutcome(outcome('false', ['EVENT_JSON:' + JSON.stringify(ev), 'plain log']));
  assert.equal(r.paid, false);
  assert.deepEqual(r.events, [ev]);
  assert.deepEqual(r.logs, ['EVENT_JSON:' + JSON.stringify(ev), 'plain log']);
  assert.equal(routerPayOutcome(outcome('true', [])).paid, true);
});

test('assertRouterScopedKey accepts only a function-call key for router/pay', () => {
  const fc = { FunctionCall: { allowance: '1', receiver_id: 'router.test.near', method_names: ['pay'] } };
  assert.doesNotThrow(() => assertRouterScopedKey(fc, 'router.test.near'));
  assert.throws(() => assertRouterScopedKey('FullAccess', 'router.test.near'), /full-access/);
  assert.throws(() => assertRouterScopedKey({ FunctionCall: { ...fc.FunctionCall, receiver_id: 'x.near' } }, 'router.test.near'), /receiver/);
  assert.throws(() => assertRouterScopedKey({ FunctionCall: { ...fc.FunctionCall, method_names: [] } }, 'router.test.near'), /pay/);
  assert.throws(() => assertRouterScopedKey({ FunctionCall: { ...fc.FunctionCall, method_names: ['pay', 'withdraw'] } }, 'router.test.near'), /pay/);
});
