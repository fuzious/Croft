// Agent-side guard for NEAR payments: ask the security oracle before signing anything.
// block -> refuse to sign and log the reasons; warn -> ask a human (default deny when nobody can answer);
// allow -> sign guarded_router.pay with the agent's function-call key (scoped to the router's `pay` method).
// The router asks the on-chain oracle again, so a bypassed or compromised wrapper is still stopped on chain.
import { createInterface } from 'node:readline/promises';
import { connectAccount } from './near_account.js';

const PAY_GAS = 100_000_000_000_000n; // 100 Tgas; the router needs at least 60 Tgas
const VERDICTS = new Set(['allow', 'warn', 'block']);

/** Decimal NEAR string ("2", "0.5") -> yoctoNEAR string. */
export function nearToYocto(near) {
  const m = /^(\d+)(?:\.(\d{1,24}))?$/.exec(String(near));
  if (!m) throw new Error(`invalid NEAR amount: ${near}`);
  return (BigInt(m[1]) * 10n ** 24n + BigInt((m[2] || '').padEnd(24, '0'))).toString();
}

/** POST {serviceUrl}/v1/check; returns the parsed verdict or throws. */
export async function checkReceiver(serviceUrl, body, fetchImpl = fetch) {
  const r = await fetchImpl(`${serviceUrl.replace(/\/$/, '')}/v1/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  if (!r.ok) throw new Error(`oracle service HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

/** Ask on the terminal; resolves true only on an explicit "yes". */
export async function askHumanOnStdin({ receiver, amount, reason, reasons }) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(
      `\nThe security oracle WARNS about paying ${amount} NEAR to ${receiver} (${reason}):\n` +
      reasons.map((r) => `  - ${r}`).join('\n') + '\nApprove this payment? type "yes" to approve: ');
    return answer.trim().toLowerCase() === 'yes';
  } finally {
    rl.close();
  }
}

/**
 * Pay `amount` NEAR to `receiver` only if the oracle lets it through.
 * deps: {agentId, check(body) -> verdict, signPay(receiverId, amountYocto) -> {paid, events},
 *        approve?(question) -> bool, interactive?: bool, log?(line)}
 * Returns {status: paid|refused|declined|refused_on_chain, verdict, reasons, receiver, amountYocto, ...}.
 */
export async function payWithOracle({ receiver, amount, reason }, deps) {
  const log = deps.log || console.log;
  const amountYocto = nearToYocto(amount);
  const base = { receiver, amount, amountYocto, reason };
  let answer;
  try {
    answer = await deps.check({ agent_id: deps.agentId, receiver_id: receiver, deposit_yocto: amountYocto });
  } catch (e) {
    answer = { verdict: 'warn', reasons: [`oracle service unavailable (${e.message}); cannot verify the receiver`] };
  }
  let verdict = answer.verdict;
  const reasons = answer.reasons || [];
  if (!VERDICTS.has(verdict)) {
    reasons.unshift(`oracle returned an unknown verdict ${JSON.stringify(verdict)}`);
    verdict = 'block';
  }
  const result = { ...base, verdict, reasons, score: answer.score };
  log(`[wrapper] oracle verdict for ${receiver} (${amount} NEAR, "${reason}"): ${verdict.toUpperCase()}`);
  for (const r of reasons) log(`[wrapper]   - ${r}`);

  if (verdict === 'block') {
    log(`[wrapper] REFUSED to sign: payment to ${receiver} blocked by the security oracle`);
    return { ...result, status: 'refused' };
  }
  if (verdict === 'warn') {
    const approve = deps.approve || (deps.interactive ? askHumanOnStdin : null);
    const ok = approve ? await approve({ receiver, amount, reason, reasons }) === true : false;
    if (!ok) {
      log(`[wrapper] DECLINED: ${approve ? 'the human did not approve' : 'no human available to approve (default deny)'}`);
      return { ...result, status: 'declined' };
    }
    log('[wrapper] human approved the warned payment; signing router.pay (the router still requires an on-chain allow)');
  }
  const tx = await deps.signPay(receiver, amountYocto);
  if (tx.paid) {
    log(`[wrapper] PAID ${amount} NEAR to ${receiver} through guarded_router`);
    return { ...result, status: 'paid', tx };
  }
  const refused = (tx.events || []).find((e) => e.event === 'payment_refused');
  const data = Array.isArray(refused?.data) ? refused.data[0] : refused?.data; // near-sdk emits an object
  const onChainReason = data?.reason || 'unknown';
  log(`[wrapper] router refused the payment on chain (${onChainReason})`);
  return { ...result, status: 'refused_on_chain', onChainReason, tx };
}

/** {paid, events, logs} from a router.pay FinalExecutionOutcome. */
export function routerPayOutcome(outcome) {
  const logs = [outcome.transaction_outcome, ...outcome.receipts_outcome].flatMap((o) => o?.outcome?.logs || []);
  const events = logs.filter((l) => l.startsWith('EVENT_JSON:')).map((l) => JSON.parse(l.slice('EVENT_JSON:'.length)));
  const ret = outcome.status?.SuccessValue;
  const paid = ret ? Buffer.from(ret, 'base64').toString() === 'true' : false;
  return { paid, events, logs };
}

/** Throws unless `permission` (view_access_key) is a function-call key for exactly routerId / ["pay"]. */
export function assertRouterScopedKey(permission, routerId) {
  if (permission === 'FullAccess' || !permission?.FunctionCall) {
    throw new Error('refusing to run with a full-access key: the agent must hold only a function-call key for router/pay');
  }
  const fc = permission.FunctionCall;
  if (fc.receiver_id !== routerId) throw new Error(`function-call key receiver is ${fc.receiver_id}, expected ${routerId}`);
  if (fc.method_names.length !== 1 || fc.method_names[0] !== 'pay') {
    throw new Error(`function-call key must allow only ["pay"], got ${JSON.stringify(fc.method_names)}`);
  }
}

/**
 * signPay(receiverId, amountYocto) for the agent: checks on chain that its key is a function-call key scoped to
 * routerId/pay, then signs router.pay with it. {nodeUrl, networkId, agentId, agentSecretKey, routerId}
 */
export async function createRouterPaySigner({ nodeUrl, networkId, agentId, agentSecretKey, routerId }) {
  const { account, keyPair } = await connectAccount({ nodeUrl, networkId, accountId: agentId, secretKey: agentSecretKey });
  const key = await account.connection.provider.query({
    request_type: 'view_access_key', finality: 'final', account_id: agentId, public_key: keyPair.getPublicKey().toString(),
  });
  assertRouterScopedKey(key.permission, routerId);
  return async (receiverId, amountYocto) => routerPayOutcome(await account.functionCall({
    contractId: routerId, methodName: 'pay', args: { receiver_id: receiverId, amount: amountYocto }, gas: PAY_GAS, attachedDeposit: 0n,
  }));
}
