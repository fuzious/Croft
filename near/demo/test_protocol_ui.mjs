import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const context = { document: { getElementById: () => ({ addEventListener() {} }) } };
vm.runInNewContext(script.slice(0, script.indexOf('const pill =')) + '\nglobalThis.assess = assessmentState; globalThis.accounting = accountingEvidence; globalThis.history = historyEvidence; globalThis.categories = categoryEvidence;', context);
const assess = context.assess;
const normal = { label: 'low', touches_intents: true, receipts_complete: true, rule_hits: [] };

test('a complete supported low result says no known pattern, never safe', () => {
  const state = assess(normal);
  assert.equal(state.key, 'no_known_pattern');
  assert.equal(state.word, 'No known attack pattern');
  assert.match(state.summary, /misses remain possible/);
});

test('non-Intents results are unsupported regardless of a low or high raw label', () => {
  for (const label of ['low', 'high']) {
    const state = assess({ ...normal, touches_intents: false, label, assessment: 'no_known_pattern' });
    assert.equal(state.key, 'unsupported');
    assert.match(state.summary, /outside NEAR Intents/);
  }
});

test('incomplete low, medium and anomaly-only high results remain inconclusive', () => {
  for (const label of ['low', 'medium', 'high']) {
    assert.equal(assess({ ...normal, receipts_complete: false, label }).key, 'inconclusive');
  }
  assert.equal(assess({ ...normal, receipts_complete: false, assessment: 'no_known_pattern' }).key, 'inconclusive');
});

test('observed high rule evidence remains visible even with missing receipts', () => {
  assert.equal(assess({ ...normal, receipts_complete: false, label: 'high', rule_hits: [{ severity: 'high' }] }).key, 'malicious_pattern');
  // Scan summaries carry authoritative assessment metadata without full rule hits.
  assert.equal(assess({ ...normal, receipts_complete: false, label: 'high', assessment: 'malicious_pattern' }).key, 'malicious_pattern');
});

test('missing scope or receipt completeness cannot produce a clean-looking result', () => {
  assert.equal(assess({ label: 'low' }).key, 'inconclusive');
  assert.equal(assess({ label: 'low', touches_intents: true }).key, 'inconclusive');
});

test('supported complete anomaly highs are suspicious, not confirmed attacks', () => {
  assert.equal(assess({ ...normal, label: 'high' }).key, 'suspicious');
});

test('new API evidence metadata and its explanation are used', () => {
  const state = assess({ label: 'low', scope: { protocol_supported: true }, evidence_coverage: { receipts_complete: false }, assessment: 'inconclusive', assessment_reason: 'One receipt is missing.' });
  assert.equal(state.key, 'inconclusive');
  assert.equal(state.summary, 'One receipt is missing.');
});

test('accounting preserves exact atomic amounts and labels the evidence boundary', () => {
  const amount = '340282366920938463463374607431768211455';
  const result = context.accounting({ status: 'checked', coverage: { checked_deposit_flows: 1, unchecked_deposit_flows: 0 },
    checks: [{ status: 'excess_credit', token_id: 'nep141:token.near', owner_ids: ['alice.near'], deposited: amount, refunded: amount, credit_retained: '3', excess: '3' }] });
  assert.ok(result.includes(amount));
  assert.match(result, /Credit retained/);
  assert.match(result, /Exact atomic units/);
  assert.match(result, /not a balance query or a solvency check/);
  assert.doesNotMatch(result, /3\.402823|e\+38/);
});

test('inconclusive accounting does not invent zero balances and escapes token content', () => {
  const result = context.accounting({ status: 'inconclusive', coverage: { checked_deposit_flows: 0, unchecked_deposit_flows: 1 },
    checks: [{ status: 'inconclusive', token_id: '<img src=x onerror=alert(1)>', reason: 'A receipt is missing.' }] });
  assert.match(result, /Incomplete/);
  assert.match(result, /1 uncheckable/);
  assert.match(result, /<dd>—<\/dd>/);
  assert.doesNotMatch(result, /<dd>0<\/dd>|<img /);
  assert.match(result, /&lt;img/);
});

test('history unavailable is explicit and cannot change a receipt assessment', () => {
  const result = context.history({ status: 'unavailable', reason: 'The history request timed out.' });
  assert.match(result, /Unavailable/);
  assert.match(result, /timed out/);
  assert.match(result, /not a complete account audit/);
  assert.equal(assess({ ...normal, history: { status: 'available', findings: [{ severity: 'medium' }] } }).key, 'no_known_pattern');
});

test('history links only well-formed transaction hashes and does not infer guilt from participation', () => {
  const hash = '3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC';
  const result = context.history({ status: 'available', coverage: { eligible_prior_transactions: 3, related_transactions: 2, window_seconds: 86400 },
    related_transactions: [{ tx_hash: hash, block_height: 123, shared_accounts: ['alice.near'], observations: ['failed_callback'] },
      { tx_hash: 'javascript:alert(1)', shared_accounts: ['<script>x</script>'] }] });
  assert.ok(result.includes(`href="https://nearblocks.io/txns/${hash}"`));
  assert.match(result, /failed callback/);
  assert.match(result, /at most 24 hours/);
  assert.match(result, /does not prove an attack/);
  assert.doesNotMatch(result, /href="javascript:|<script>/);
});

test('history opt-out remains distinguishable from a failed history request', () => {
  const result = context.history({ status: 'not_requested' });
  assert.match(result, /Not requested/);
  assert.match(result, /Enable earlier activity/);
  assert.doesNotMatch(result, /No earlier match/);
});

test('attack categories remain escaped observed patterns, not verified root causes', () => {
  assert.equal(context.categories(), '');
  const result = context.categories([{ id: 'callback_accounting', label: 'Callback accounting' }, { label: '<script>unsafe</script>' }]);
  assert.match(result, /Callback accounting/);
  assert.match(result, /not a verified root cause/);
  assert.doesNotMatch(result, /<script>/);
});
