# Results log (sealed tests are scored once, numbers recorded as-is)

## Sealed test v1 — frozen feature model (logreg, v6 cards), scored 2026-10-15
- Model: trained on 476 ETH rows (92 verified-harmful exploits); threshold 0.324 picked by training-only CV.
- Test: 913 txs never trained on — 66 held-out exploits (36 ETH incidents from 2025-06 on, 30 BSC = unseen chain)
  + 847 normals (810 fresh real-world: flash loans, liquidations, aggregators, bridges, Safe, timelock, MEV bots,
  vaults/staking; + 37 held-out victim normals).
- **Exploits caught 62/66 = 93.9%** (ETH 33/36, BSC 29/30)
- **False alarms 12/847 = 1.42%**, precision 83.8% at this mix (7.2% exploits)
- False alarms by type: liquidations 5, MEV bots 2, Uniswap V3 flash 2, Aave V3 flash 1, sDAI 1, Safe 1.
- After this scoring, test v1 is development data (errors inspected); the next honest number comes from test v2.

## Development after test v1 (test v1 became dev data once its errors were inspected)
v7 card fixes from v1 errors: EIP-7702 delegated EOAs; unverified tx target = attacker side; profit-receiving EOAs;
debt-token burns offset liquidation "losses"; wrapped-native unwrap legs; signer-is-owner (Ownable/Safe).
Data hygiene: victim normals must be >= 7,200 blocks (~1 day) before the attack (attack-window txs re-sampled/dropped).
Dev CV (v7, 1,374 rows, incident-grouped, nested threshold for P>=0.95): avg(logreg,hgb) P=0.957 R=0.981 (FP 7/1216).

Independent label audit (separate agent, no model access) of all 243 exploit rows: 208 confirmed, 24 likely,
11 excluded by policy (not_exploit 2, doubtful 4 incl. whitehat front-runs, non_technical key compromises 5).
Audit also found BSC stablecoin pricing gaps (DefiLlama) -> v8: ±12h price search, $1 stablecoin fallback,
no caching of empty price responses. v8 = v7 + pricing fix + label policy. Re-freeze before scoring test v2.

## External review: GPT-6-Astra (xhigh) via codex, read-only secret-free copy (runs/codex_gpt6astra_review.md)
Accepted and fixed:
- freeze_v7 overwrote the estimator with a metadata string -> freeze_v9 stores estimator separately, reload-verified.
- "nested threshold" was not truly nested -> scripts/eval_nested.py (outer/inner grouped CV). On v7 data the effect was
  small: avg(logreg,hgb) recall 152/158 = 96.2% [92.0-98.2], FPR 6/1216 = 0.49% [0.23-1.07] (truly nested).
- verify_labels silently dropped extractive-looking normals -> now kept (flagged only). (None had been dropped.)
- Unpriced protected drains could not trigger the drain rule -> per-token drain share regardless of price.
- Zero-value transfers could merge a victim EOA into the attacker side -> edges need amount > 0; profit receiver must
  be a pure receiver.
- signer_prior_txs_to_prot = -1 on non-ETH chains is a chain proxy -> excluded from model features.
- Duplicate txs (2, from resampling: two incidents sharing a victim) -> deduped; CV now grouped by victim contract.
- Whitehat front-runs re-labelled as positives (same unauthorized drain); SELLC/H2O replaced by their real drain txs.
- Test v2 chain confound (exploits BSC/Base, normals ETH) -> adding BSC + Base normals; results reported per chain,
  with Wilson CIs, false alerts per million and precision as a function of prevalence.
Acknowledged, not yet fixed (documented limits):
- Test v2 is "development-informed": the label audit read v2 exploit cards and found the pricing bug fixed in v8/v9
  (no predictions were inspected). A fully untouched holdout would be the cleanest remedy.
- Protected set for exploits uses hindsight (largest verified loser); negatives use the sampled protocol address.
  Needs a pre-declared protocol registry applied identically to all rows.
- Historical traces are an ideal-execution benchmark, not proof of live pre-execution equivalence; replay "matched"
  checks status + log count only; prices use a ±12h window.
- Precision at real prevalence needs FPR in the per-million range; current measurements are ~0.5% (thousands per
  million). Production use needs either far lower FPR or a review tier rather than hard blocking.

## v10 (after second Astra consult) — frozen before test v2 is scored
Changes: mints no longer wipe a token's price (only supply shocks do); operation-semantics features (liquidation,
protected withdraw/deposit/borrow/swap/admin/flash, Safe exec); read-only re-entry separated; token-contract method
names decoded; feature-schema check. Price client: local index over cached DefiLlama answers, throttling, loud
failure instead of silent empty prices, Alchemy hourly prices (at/before ts) when DefiLlama fails, $1 stablecoins.
Truly nested dev CV (1,366 rows, 152 exploits, victim-grouped; chain-proxy feature excluded):
  logreg  recall 147/152 = 96.7% [92.5-98.6]  FPR 7/1214 = 0.58% [0.28-1.19]  precision@dev-mix 95.5%  (stable over seeds)
  avg     recall 148/152 = 97.4% [93.4-99.0]  FPR 11/1214 = 0.91% [0.51-1.62]  (less stable)
Frozen: models/frozen_v10.{pkl,json} — logreg, threshold 0.188 (OOF, P>=0.95 at dev mix), reload-verified.

## SEALED TEST v3 — untouched (built by an isolated agent; nobody inspected it), frozen v10, scored once
950 txs on chains never seen in training: Polygon, Arbitrum, Optimism. 32 exploits + 918 normals
(900 random background + 19 victim normals >= 1.1 days before attacks).
- Exploits caught 31/32 = 96.9% [95% CI 84.3-99.4] (arbitrum 18/19, optimism 5/5, polygon 8/8)
- False alarms 0/918 (95% upper bound ~0.4%; "3/n" rule ~0.33%)
- Caveats: small exploit count (wide CI); normals mostly random background traffic (easier than DeFi hard negatives);
  Optimism cards degraded (no contract-creation info on free explorer tier); Arbitrum replays approximate (anvil lacks
  ArbOS). Bugs found by the builder (not fixed before scoring): Arbitrum WETH wrap counted as mint; eth_getCode
  "account not found" crash; explorer error bodies cached forever; failed non-eth replays cached forever.

## SEALED TEST v2 — frozen v10, scored once (3,108 txs; recall caveat: label audit read v2 exploit cards earlier)
- Exploits caught 81/82 = 98.8% [93.4-99.8] (BSC 65/65, Base 16/17; 2 setup-only exploit rows dropped by the
  pre-declared harm rule: TSURU, RedKeysCoin)
- False alarms: Base 0/389, BSC 0/134, Ethereum 32/2,503 = 1.28% [0.91-1.80] (12,785 per million)
- Pooled precision on this chain-mixed set 81/113 = 71.7% -> BELOW the 95% target
- Ethereum false alarms concentrate in normal families absent from training ("withdrawal entitlement" family):
  Lido withdrawal claims 8/50, sDAI withdrawals 5/50, Aave supply/borrow/withdraw 7/240, Compound v3 withdraw 2/60.
  Families seen in training stayed clean: liquidations 0/240, aggregators 0/280, bridges 0/55, Uniswap swaps 0/120.
- Diagnosis: cards don't account for claims surrendered (ERC-721/1155 withdrawal NFTs, share burns), so a legit
  redemption looks like an unexplained protocol outflow. Test v2 is now spent (becomes development data).

## v12 (NFT flows + floor pricing, vault/receipt-token pricing ladder, claim-surrender accounting, drainer data)
Training side: 4,443 rows (351 exploits) after per-category holdouts were reserved (newest ~25% per category, whole
victim groups). Truly nested CV on the training side: hist-gboost recall 98.9% [97.1-99.6], FPR 0.34% [0.20-0.57]
(chosen: lowest FPR, stable over seeds); avg 99.4% / 0.42%; logreg 97.7% / 0.49%. Frozen: models/frozen_v12 (hgb,
threshold 0.063).

## SEALED per-category holdouts — frozen v12, scored once (1,504 txs, never trained on)
Exploits caught 125/130 = 96.2% [91.3-98.3]: drainer-token 31/31, drainer-nft 24/24, vault 8/8, nft 3/3, bridge 2/2,
dex 28/30, other 15/16, lending 7/8, token 7/8. False alarms 5/1,374 = 0.36% (dex 4/335, lending 1/317; all others 0).
Pooled precision on this set 125/130 = 96.2% (at a ~9% exploit mix; not a deployment number). Small categories
(bridge 2, nft 3, lending/token 8) have wide CIs.

## SEALED TEST v4 — frozen v12, scored once (2,332 txs; untouched, collected by an isolated agent)
- Exploits caught 65/66 = 98.5% [91.9-99.7] (bsc 25/25, eth 34/35, avalanche 3/3, base 2/2, blast 1/1).
  Counting the one exploit whose card could not be built (Linea PerpPair, missing block data) as missed: 65/67 = 97.0%.
  6 listed exploits dropped by the pre-declared harm rule (< $1k moved in their own trace), incl. 2 small Unizen txs.
- False alarms 13/2,266 = 0.57%: Ethereum 13/1,866 = 0.70% [0.41-1.19], BSC 0/200, Base 0/200.
- v2's failure families fixed: withdrawals 1/120 (Lido claims were 8/50), vaults 0/120 (sDAI withdrawals were 5/50),
  lending 0/120 (was 9/300). Remaining false alarms: Compound timelock executions 3/60, Compound v3 liquidations 2/20,
  Liquity 1/20, MEV bots 3/120, Safe 2/120, Uniswap v4 1/24, rETH burn 1/30.
- Pooled precision 65/78 = 83.3% at a ~3% exploit mix -> still below the 95% target. Remaining false alarms are
  authorised/privileged actions (governance, Safe, liquidators) -> second-stage authorization/accounting checks.

## Two-stage system: frozen v12 + stage 2 (GPT-6-Astra via codex, effort high, clear only on legit >= 0.8)
Stage 2 designed on dev only (stage-1 out-of-fold flags on the v12 training side: cleared 9/18 false alarms, 0/40
exploits); prompt never tuned; frozen as models/stage2_v1.json (prompt sha ab53fb6d...). Then run once on the stage-1
flags of the sealed sets (stage-1 results on those sets were already known; stage 2 had not seen them).
- Sealed v4: exploits 65/66 = 98.5% (0 wrongly cleared); false alarms 13 -> 4 of 2,266 = 0.18% [0.07-0.45];
  precision 83.3% -> 94.2%. Remaining: MEV bots 2, Safe full-balance payout 1, Uniswap v4 flash route 1.
- Per-category holdouts: exploits 125 -> 121 of 130 = 93.1% (4 wrongly cleared); false alarms 5/1,374 (0 cleared);
  precision 96.0%.
- Combined: 186/196 exploits = 94.9%, 9/3,640 false alarms = 0.25%, precision 95.4%.
- Stage-2 failure mode: the 4 wrongly cleared exploits are redemption-abuse attacks (ActivePool urgent redemption x2,
  Juicebox REV loans, tCDP): the model accepted the redemption mechanics without checking that the payout was fair for
  the claim surrendered. Next: a fairness/entitlement number on the card, and a stage-2 rule that a redemption cannot
  be cleared when it pays out far more than the claim's value; to be designed on dev and tested on a new sealed set.
