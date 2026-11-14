import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const context = { document: { getElementById: () => ({ addEventListener() {} }) } };
vm.runInNewContext(script.slice(0, script.indexOf('const pill =')) + '\nglobalThis.assess = assessmentState;', context);
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
