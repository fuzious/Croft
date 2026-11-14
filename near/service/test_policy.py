import unittest

from near.service import policy

NOW = 1_800_000_000 * 10**9
NEAR = 10**24


def S(value, available=True, source="test", error=None):
    return {"value": value, "source": source, "available": available, "error": error}


def base(**over):
    """Signals of an old, active, verified contract with low code risk: the allow case."""
    sig = {
        "exists": S(True), "is_contract": S(True), "code_hash": S("H1"), "balance_yocto": S(str(5 * NEAR)),
        "age_days": S(900.0), "tx_count": S(5000), "code_changed_days": S(400.0),
        "prior_interactions": S(True),
        "local_blocklist": S({"blocked": False, "confirmed": [], "pending": 0}),
        "onchain_blocked": S(False), "onchain_verdict": S(None),
        "source": S({"origin": "nep330", "verified": True, "repo": "https://github.com/o/r", "rev": "abc"}),
        "code_risk": S({"risk": 0.1, "label": "low", "version": "m1", "top": []}),
    }
    sig.update(over)
    return sig


def eoa(**over):
    sig = base(is_contract=S(False), code_hash=S("11111111111111111111111111111111"),
               code_changed_days=S(None), source=S(None), code_risk=S(None))
    sig.update(over)
    return sig


TOP_FN = {"fn": "ft_on_transfer", "vuln_class_guess": "ft_receiver_trust", "label": "high", "detector_hits": []}
HIGH_AGREED = {"risk": 0.91, "label": "high", "version": "m1",
               "top": [TOP_FN | {"detector_hits": [{"severity": "high", "detector": "ft_on_transfer_no_token_check"}]}]}

def ia(*txs):
    """intents_activity signal value with the given scored txs: (tx_hash, label, rules)."""
    return S({"n_scored": len(txs), "requests": 2,
              "txs": [{"tx_hash": h, "label": lab, "risk": 0.9, "flow": "deposit", "rules": rules}
                      for h, lab, rules in txs]})


IA_LOW = ("LowTx1", "low", [])
IA_MED = ("MedTx1", "medium", ["notify_receiver_in_deposit"])
IA_HIGH = ("HighTx1", "high", ["failed_resolve_callback", "credit_kept"])
IA_HIGH_ANOMALY = ("HighTx2", "high", [])

CASES = [
    # (name, signals, kwargs, verdict, reason substring or None)
    ("verified low-risk contract", base(), {}, "allow", None),
    ("old active EOA", eoa(), {}, "allow", None),
    ("high code risk, a high-severity rule agrees", base(code_risk=S(HIGH_AGREED)), {}, "block", "code risk is high"),
    ("high code risk, no rule agrees", base(code_risk=S({"risk": 0.91, "label": "high", "version": "m1",
                                                         "top": [TOP_FN]})),
     {}, "warn", "no high-severity rule agrees"),
    ("high-severity rule on a function the model does not score",
     base(code_risk=S({"risk": 0.1, "label": "low", "version": "m1", "top": [],
                       "functions": [{"fn": "set_owner", "is_public": True, "model_scored": False,
                                      "detector_hits": [{"severity": "high", "detector": "privileged_without_auth"}]}]})),
     {}, "warn", "set_owner"),
    ("medium code risk", base(code_risk=S({"risk": 0.5, "label": "medium", "version": "m1", "top": []})),
     {}, "warn", "code risk is medium"),
    ("local blocklist", eoa(local_blocklist=S({"blocked": True, "confirmed": [{"evidence_url": "https://x/y"}],
                                               "pending": 0})), {}, "block", "local blocklist"),
    ("pending local report", eoa(local_blocklist=S({"blocked": False, "confirmed": [], "pending": 2})),
     {}, "warn", "2 unconfirmed report"),
    ("on-chain blocked", eoa(onchain_blocked=S(True)), {}, "block", "blocked"),
    ("on-chain block verdict", base(onchain_verdict=S({"verdict": "block", "code_hash": "H1", "score_bps": 9000,
                                                       "expires_at_ns": str(NOW + 1)})), {}, "block", "attested"),
    ("expired on-chain block verdict ignored",
     base(onchain_verdict=S({"verdict": "block", "code_hash": "H1", "score_bps": 9000,
                             "expires_at_ns": str(NOW - 1)})), {}, "allow", None),
    ("attestation for other code", base(onchain_verdict=S({"verdict": "allow", "code_hash": "H0", "score_bps": 0,
                                                           "expires_at_ns": str(NOW + 1)})),
     {}, "warn", "code changed since"),
    ("on-chain oracle unreachable", eoa(onchain_blocked=S(None, available=False, error="timeout")),
     {}, "warn", "blocklist"),
    ("on-chain verdict unreadable while blocklist succeeds",
     eoa(onchain_verdict=S(None, available=False, error="timeout")), {}, "warn", "verdict could not be checked"),
    ("young account", eoa(age_days=S(2.4)), {}, "warn", "2 days old"),
    ("age unknown", eoa(age_days=S(None, available=False, error="429")), {}, "warn", "age is unknown"),
    ("recent code change", base(code_changed_days=S(3.2)), {}, "warn", "deployed 3 days ago"),
    ("code change unknown", base(code_changed_days=S(None, available=False, error="429")),
     {}, "warn", "code change"),
    ("no verifiable source", base(source=S({"origin": "none", "verified": False, "error": "no NEP-330 metadata"}),
                                  code_risk=S(None)), {}, "warn", "no verifiable source"),
    ("NEP-330 source with no scorable functions",
     base(code_risk=S({"risk": 0.0, "label": "low", "version": "m1", "top": [], "n_functions": 0})),
     {}, "warn", "no functions to score"),
    ("caller-supplied source", base(source=S({"origin": "caller", "verified": False})),
     {}, "warn", "supplied by the caller"),
    ("unpinned source", base(source=S({"origin": "nep330", "verified": False, "repo": "https://github.com/o/r",
                                       "rev": None})), {}, "warn", "not pinned"),
    ("receiver advertises pinned clean source without a deployed code comparison",
     base(source=S({"origin": "nep330", "verified": False, "pinned": True,
                    "repo": "https://github.com/o/r", "rev": "abc"})),
     {}, "warn", "verified against the deployed code"),
    ("large deposit, first interaction", eoa(prior_interactions=S(False)), {"deposit_yocto": str(250 * NEAR)},
     "warn", "no prior transactions"),
    ("small deposit, first interaction", eoa(prior_interactions=S(False)), {"deposit_yocto": str(1 * NEAR)},
     "allow", None),
    ("large deposit, interactions unknown", eoa(prior_interactions=S(None, available=False, error="no agent_id")),
     {"deposit_yocto": str(250 * NEAR)}, "warn", "unknown"),
    ("account missing", eoa(exists=S(False), is_contract=S(False)), {}, "warn", "does not exist"),
    ("rpc unavailable", eoa(exists=S(None, available=False, error="timeout"),
                            is_contract=S(None, available=False, error="timeout")), {}, "warn", "RPC"),
    ("sandbox skips history checks", eoa(age_days=S(None, available=False, error="no indexer"),
                                         prior_interactions=S(None, available=False)),
     {"network": "sandbox", "deposit_yocto": str(250 * NEAR)}, "allow", "sandbox"),
    ("block beats warn", base(code_risk=S(HIGH_AGREED), age_days=S(1.0)), {}, "block", "1 days old"),
    # NEAR Intents activity of the receiver
    ("intents: recent txs all low", eoa(intents_activity=ia(IA_LOW, IA_LOW)), {}, "allow", None),
    ("intents: no intents txs", eoa(intents_activity=ia()), {}, "allow", None),
    ("intents: a high tx warns, naming the rule", eoa(intents_activity=ia(IA_LOW, IA_HIGH)), {}, "warn",
     "failed_resolve_callback"),
    ("intents: a high tx warns, naming the tx", eoa(intents_activity=ia(IA_HIGH)), {}, "warn", "HighTx1"),
    ("intents: high from the anomaly model alone", eoa(intents_activity=ia(IA_HIGH_ANOMALY)), {}, "warn",
     "anomaly score"),
    ("intents: high alone never blocks", base(intents_activity=ia(IA_HIGH, IA_HIGH)), {}, "warn", "HighTx1"),
    ("intents: medium is info only", eoa(intents_activity=ia(IA_LOW, IA_MED)), {}, "allow", "MedTx1"),
    ("intents: unreadable warns for an EOA",
     eoa(intents_activity=S(None, available=False, error="FastNEAR request failed: 429")), {}, "warn", "429"),
    ("intents: unreadable warns for a verified low-risk contract",
     base(intents_activity=S(None, available=False, error="FastNEAR timed out after 15 s")), {}, "warn",
     "FastNEAR timed out"),
    ("intents: not applicable off mainnet", eoa(intents_activity=S(None, source="n/a")), {}, "allow", None),
]


class PolicyTest(unittest.TestCase):
    def test_table(self):
        for name, sig, kw, verdict, reason in CASES:
            with self.subTest(name):
                out = policy.decide(sig, now_ns=NOW, **kw)
                self.assertEqual(out["verdict"], verdict, out["reasons"])
                self.assertTrue(out["reasons"], "every verdict carries at least one reason")
                if reason:
                    self.assertTrue(any(reason in r for r in out["reasons"]), out["reasons"])

    def test_deterministic(self):
        sig = base(age_days=S(1.0), code_changed_days=S(2.0))
        self.assertEqual(policy.decide(sig, now_ns=NOW), policy.decide(sig, now_ns=NOW))

    def test_score_is_code_risk_and_one_when_blocklisted(self):
        self.assertEqual(policy.decide(base(), now_ns=NOW)["score"], 0.1)
        self.assertEqual(policy.decide(eoa(), now_ns=NOW)["score"], 0.0)
        self.assertEqual(policy.decide(eoa(onchain_blocked=S(True)), now_ns=NOW)["score"], 1.0)

    def test_risk_label_thresholds(self):
        self.assertEqual(policy.risk_label(0.95), "high")
        self.assertEqual(policy.risk_label(policy.THRESHOLDS["risk_medium"]), "medium")
        self.assertEqual(policy.risk_label(0.0), "low")


if __name__ == "__main__":
    unittest.main()
