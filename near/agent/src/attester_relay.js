// Attester relay: ask the oracle service about an account and publish its verdict on chain with
// security_oracle.submit_verdict, signed by an attester key.
//
//   node src/attester_relay.js <account_id> [ttl_seconds]
//   env: ORACLE_SERVICE_URL, NEAR_NODE_URL, NEAR_NETWORK_ID, ORACLE_CONTRACT_ID, ATTESTER_ID, ATTESTER_KEY
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { assertCheckResponse, checkReceiver } from './wrapper.js';
import { connectAccount } from './near_account.js';

const SUBMIT_GAS = 30_000_000_000_000n;

/** submit_verdict args from a /v1/check answer. reasons_hash = sha256(JSON.stringify(reasons)). */
export function attestationFromCheck(check, nowNs, ttlSeconds) {
  assertCheckResponse(check, check?.receiver_id);
  if (typeof check.score !== 'number' || !Number.isFinite(check.score) || check.score < 0 || check.score > 1) {
    throw new Error('cannot attest a score outside 0..1');
  }
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 7 * 24 * 3600) {
    throw new Error('attestation TTL must be an integer from 1 to 604800 seconds');
  }
  const codeHash = check.signals?.code_hash?.value ?? '';
  if (typeof codeHash !== 'string') throw new Error('cannot attest a malformed code hash');
  const bps = Math.round(check.score * 10_000);
  return {
    account_id: check.receiver_id,
    code_hash: codeHash,
    verdict: check.verdict,
    score_bps: bps,
    reasons_hash: createHash('sha256').update(JSON.stringify(check.reasons)).digest('hex'),
    expires_at_ns: (BigInt(nowNs) + BigInt(ttlSeconds) * 1_000_000_000n).toString(),
  };
}

/** Check `accountId` with the service and submit the verdict; returns {check, attestation}. */
export async function relayVerdict({ serviceUrl, attester, oracleId, accountId, ttlSeconds = 3600, nowNs, log = console.log }) {
  const check = await checkReceiver(serviceUrl, { receiver_id: accountId });
  assertCheckResponse(check, accountId);
  const attestation = attestationFromCheck(check, nowNs ?? BigInt(Date.now()) * 1_000_000n, ttlSeconds);
  await attester.functionCall({ contractId: oracleId, methodName: 'submit_verdict', args: attestation, gas: SUBMIT_GAS, attachedDeposit: 0n });
  log(`[relay] ${attester.accountId} attested ${attestation.verdict.toUpperCase()} for ${accountId} on ${oracleId} ` +
      `(score ${attestation.score_bps} bps, expires in ${ttlSeconds} s, reasons_hash ${attestation.reasons_hash.slice(0, 12)}...)`);
  for (const r of check.reasons || []) log(`[relay]   - ${r}`);
  return { check, attestation };
}

async function main() {
  const [accountId, ttl] = process.argv.slice(2);
  const env = process.env;
  const missing = ['ORACLE_SERVICE_URL', 'NEAR_NODE_URL', 'NEAR_NETWORK_ID', 'ORACLE_CONTRACT_ID', 'ATTESTER_ID', 'ATTESTER_KEY']
    .filter((k) => !env[k]);
  if (!accountId || missing.length) {
    console.error(`usage: node src/attester_relay.js <account_id> [ttl_seconds]; missing env: ${missing.join(', ') || '-'}`);
    process.exit(2);
  }
  const { account } = await connectAccount({ nodeUrl: env.NEAR_NODE_URL, networkId: env.NEAR_NETWORK_ID,
    accountId: env.ATTESTER_ID, secretKey: env.ATTESTER_KEY });
  await relayVerdict({ serviceUrl: env.ORACLE_SERVICE_URL, attester: account, oracleId: env.ORACLE_CONTRACT_ID,
    accountId, ttlSeconds: Number(ttl || 3600) });
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}
