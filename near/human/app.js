const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short = value => value ? `${value.slice(0, 9)}…${value.slice(-7)}` : 'Not provided';
const label = {pending:'Pending review', confirmed:'Confirmed', dismissed:'Dismissed'};
let items = [], status = 'pending', selected = null, loading = false;
const high = item => item.evidence.assessment === 'malicious_pattern';
const title = item => high(item) ? 'High-severity pattern' : 'Suspicious activity';
const date = value => new Date(value).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
function announce(message) { $('message').textContent = message; $('message').hidden = !message; }
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers:{'Content-Type':'application/json'}, signal:AbortSignal.timeout(15000)});
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === 'string' ? body.detail : `Could not save or load reviews (${response.status}). Please retry.`);
  }
  return response.json();
}
function render() {
  const pending = items.filter(i => i.status === 'pending');
  $('pendingCount').textContent = $('tabCount').textContent = $('navCount').textContent = pending.length;
  $('highCount').textContent = pending.filter(high).length;
  $('confirmedCount').textContent = items.filter(i => i.status === 'confirmed').length;
  $('dismissedCount').textContent = items.filter(i => i.status === 'dismissed').length;
  $('totalCount').textContent = items.length;
  const query = $('search').value.trim().toLowerCase(), priority = $('severity').value;
  const visible = items.filter(i => (status === 'all' || (status === 'reviewed' ? i.status !== 'pending' : i.status === 'pending')) &&
    (priority === 'all' || (priority === 'high' ? high(i) : !high(i))) &&
    `${i.evidence.tx_hash} ${i.account_id || ''} ${i.evidence.signer_id || ''} ${i.evidence.receiver_id || ''}`.toLowerCase().includes(query))
    .sort((a,b) => Number(high(b)) - Number(high(a)) || b.created_at.localeCompare(a.created_at));
  $('rows').innerHTML = visible.length ? visible.map(i => {
    const e = i.evidence, rules = e.rule_hits?.map(r => r.rule) || e.rules || [];
    return `<tr><td><button class="tx" data-id="${esc(i.id)}" aria-label="Review transaction ${esc(e.tx_hash)}">${esc(short(e.tx_hash))}</button><div class="account" title="${esc(i.account_id)}">${esc(i.account_id || 'NEAR Intents transaction')}</div></td><td><div class="finding-name">${title(i)}</div><div class="finding-sub">${esc(rules[0]?.replaceAll('_',' ') || 'Anomaly threshold exceeded')}${rules.length > 1 ? ` +${rules.length - 1}` : ''}</div></td><td><span class="badge ${high(i) ? 'high' : 'medium'}">${high(i) ? '↑ HIGH' : '• MEDIUM'}</span></td><td><span class="badge ${esc(i.status)}">${esc(label[i.status])}</span>${i.demo ? '<div class="finding-sub">HISTORICAL DEMO</div>' : ''}</td><td class="queued">${esc(date(i.created_at))}</td><td><button class="open-case" data-id="${esc(i.id)}" aria-label="Open case ${esc(short(e.tx_hash))}">↗</button></td></tr>`;
  }).join('') : `<tr><td colspan="6" class="empty"><strong>${items.length ? 'No matching cases' : 'Your review queue is ready'}</strong>${items.length ? 'Try another filter or inspect a new transaction.' : 'Flagged inspections and scans will appear here. Load demo cases to explore a historical review.'}</td></tr>`;
  $('showing').textContent = `${visible.length} of ${items.length} cases · ${items.filter(i => i.demo).length} historical demos`;
}
async function refresh() {
  if (loading) return;
  loading = true; $('refresh').disabled = true;
  try {
    items = (await api('/v1/reviews')).items; render();
    $('sync').textContent = `Synced ${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`;
  } catch (e) {
    $('sync').textContent = 'Connection interrupted'; announce(e.message);
    if (!items.length) $('rows').innerHTML = '<tr><td colspan="6" class="empty"><strong>Queue unavailable</strong>Check the service connection and refresh to retry.</td></tr>';
  } finally { loading = false; $('refresh').disabled = false; }
}
function openReview(id) {
  const item = items.find(i => i.id === id); if (!item) return;
  selected = item;
  const e = item.evidence;
  const rules = e.rule_hits || (e.rules || []).map(rule => ({rule}));
  $('caseDetail').innerHTML = `<div class="detail-badges"><span class="badge ${high(item) ? 'high':'medium'}">${high(item) ? 'HIGH PRIORITY':'SUSPICIOUS'}</span><span class="badge ${esc(item.status)}">${esc(label[item.status])}</span>${item.demo ? '<span class="demo-tag">HISTORICAL DEMO</span>' : ''}</div><h2 id="reviewTitle">${title(item)}</h2><p>${esc(e.assessment_reason || 'The detector flagged this transaction for human investigation.')}</p>
  <dl class="details-grid"><div class="wide"><dt>TRANSACTION HASH</dt><dd><code>${esc(e.tx_hash)}</code></dd></div><div><dt>${e.signer_id ? 'TRANSACTION SIGNER' : 'SCANNED ACCOUNT'}</dt><dd><code>${esc(e.signer_id || item.account_id || 'Not provided')}</code></dd></div><div><dt>PROTOCOL</dt><dd>NEAR Intents · Mainnet</dd></div><div><dt>RECEIPT COVERAGE</dt><dd>${e.receipts_complete === true ? 'Complete receipt graph' : e.receipts_complete === false ? 'Incomplete — investigate gaps' : 'Not available'}</dd></div><div><dt>QUEUED AT</dt><dd>${esc(date(item.created_at))}</dd></div>${item.reviewed_at ? `<div class="wide"><dt>LAST REVIEW DECISION</dt><dd>${esc(label[item.status])} · ${esc(date(item.reviewed_at))}</dd></div>` : ''}</dl>
  <h3 class="detail-heading">DETECTOR EVIDENCE / ${String(rules.length).padStart(2,'0')}</h3>${rules.length ? rules.map(r => `<div class="evidence-item"><strong>${esc((r.rule || 'Finding').replaceAll('_',' '))}</strong><p>${esc(r.message || r.reason || (r.severity ? `${r.severity} severity detector rule` : 'Inspect the original evidence for context.'))}</p></div>`).join('') : '<p>An anomaly threshold triggered this review. No explicit attack rule matched.</p>'}
  <a class="evidence-link" href="https://nearblocks.io/txns/${encodeURIComponent(e.tx_hash)}" target="_blank" rel="noopener noreferrer">View transaction on NEARBlocks ↗</a>
  <details><summary>Original evidence · accounting, history & coverage</summary><pre>${esc(JSON.stringify(e,null,2))}</pre></details>`;
  $('note').value = item.note; $('decisionError').textContent = '';
  document.querySelector('[value="pending"]').hidden = item.status === 'pending';
  if (!$('reviewDialog').open) $('reviewDialog').showModal();
}
$('rows').addEventListener('click', event => { const button = event.target.closest('[data-id]'); if (button) openReview(button.dataset.id); });
document.querySelectorAll('[data-status]').forEach(button => button.addEventListener('click', () => {
  status = button.dataset.status;
  document.querySelectorAll('[data-status]').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
  render();
}));
$('search').addEventListener('input', render); $('severity').addEventListener('change', render);
$('refresh').addEventListener('click', () => { announce(''); refresh(); });
$('closeReview').addEventListener('click', () => $('reviewDialog').close());
$('loadDemo').addEventListener('click', async () => {
  const button = $('loadDemo'); button.disabled = true;
  try { await api('/v1/reviews/demo', {method:'POST'}); await refresh(); announce('Historical examples loaded. These are recorded transactions, clearly labelled as demo cases.'); }
  catch (e) { announce(e.message); } finally { button.disabled = false; }
});
$('decisionForm').addEventListener('submit', async event => {
  event.preventDefault();
  const note = $('note').value.trim(), decision = event.submitter?.value;
  if (!note || !decision || !selected) { $('decisionError').textContent = 'Add a review note before saving your decision.'; return; }
  const buttons = [...$('decisionForm').querySelectorAll('button')]; buttons.forEach(b => b.disabled = true);
  try {
    await api(`/v1/reviews/${encodeURIComponent(selected.id)}`, {method:'PATCH', body:JSON.stringify({status:decision, note})});
    $('reviewDialog').close(); announce(`Decision saved: ${label[decision].toLowerCase()}. Your note is stored with the case.`); await refresh();
  } catch (e) { $('decisionError').textContent = e.message; }
  finally { buttons.forEach(b => b.disabled = false); }
});
refresh(); setInterval(refresh, 15000);
