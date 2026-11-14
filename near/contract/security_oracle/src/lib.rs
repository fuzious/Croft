//! On-chain security oracle for NEAR accounts.
//!
//! Attesters (oracle operator keys) publish a verdict per account: allow, warn or block, with a risk
//! score, the code hash they scored and an expiry. Anyone can report an account with evidence by
//! paying for the report's storage; an attester confirms (the account becomes blocked) or dismisses
//! it. A blocked account always reads as `block`, whatever verdict was attested.
use near_sdk::json_types::U64;
use near_sdk::store::{IterableSet, LookupMap, Vector};
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault,
    Promise,
};

const MAX_SCORE_BPS: u16 = 10_000;
const MAX_URL_LEN: usize = 512;
const MAX_CODE_HASH_LEN: usize = 64;
const MAX_REPORTS_PAGE: u32 = 50;
/// Longest lifetime of an attested verdict, so a leaked attester key cannot publish a lasting `allow`.
const MAX_VERDICT_TTL_NS: u64 = 7 * 24 * 3_600 * 1_000_000_000;

#[near(serializers = [borsh, json])]
#[serde(rename_all = "lowercase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictKind {
    #[serde(alias = "Allow")]
    Allow,
    #[serde(alias = "Warn")]
    Warn,
    #[serde(alias = "Block")]
    Block,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub code_hash: String,
    pub verdict: VerdictKind,
    pub score_bps: u16,
    pub reasons_hash: String,
    pub attested_at_ns: U64,
    pub expires_at_ns: U64,
    pub attester: AccountId,
}

#[near(serializers = [borsh])]
struct StoredVerdict {
    verdict: Verdict,
    attester_generation: u64,
}

#[near(serializers = [borsh, json])]
#[serde(rename_all = "lowercase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportStatus {
    Pending,
    Confirmed,
    Dismissed,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub id: U64,
    pub account_id: AccountId,
    pub reporter: AccountId,
    pub evidence_url: String,
    pub evidence_sha256: String,
    pub deposit: NearToken,
    pub status: ReportStatus,
    pub created_at_ns: U64,
    pub resolved_by: Option<AccountId>,
}

/// Why an account is blocked: the confirmed report, who confirmed it and when.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub report_id: U64,
    pub evidence_sha256: String,
    pub confirmed_by: AccountId,
    pub confirmed_at_ns: U64,
}

#[near(event_json(standard = "security_oracle"))]
pub enum Event {
    #[event_version("1.0.0")]
    VerdictSubmitted {
        account_id: AccountId,
        verdict: VerdictKind,
        score_bps: u16,
        attester: AccountId,
    },
    #[event_version("1.0.0")]
    ReportFiled {
        report_id: U64,
        account_id: AccountId,
        reporter: AccountId,
    },
    #[event_version("1.0.0")]
    ReportConfirmed {
        report_id: U64,
        account_id: AccountId,
        attester: AccountId,
    },
    #[event_version("1.0.0")]
    ReportDismissed {
        report_id: U64,
        account_id: AccountId,
        attester: AccountId,
    },
    #[event_version("1.0.0")]
    Unblocked {
        account_id: AccountId,
        owner: AccountId,
    },
    #[event_version("1.0.0")]
    AttesterAdded { attester: AccountId },
    #[event_version("1.0.0")]
    AttesterRemoved { attester: AccountId },
}

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Attesters,
    Verdicts,
    Reports,
    ReportsByAccount,
    Blocked,
    AttesterGenerations,
}

#[near(
    contract_state,
    contract_metadata(
        link = "https://github.com/fuzious/security_oracle",
        standard(standard = "nep297", version = "1.0.0"),
    )
)]
#[derive(PanicOnDefault)]
pub struct SecurityOracle {
    owner_id: AccountId,
    attesters: IterableSet<AccountId>,
    verdicts: LookupMap<AccountId, StoredVerdict>,
    reports: Vector<Report>,
    reports_by_account: LookupMap<AccountId, Vec<u64>>,
    blocked: LookupMap<AccountId, Block>,
    attester_generations: LookupMap<AccountId, u64>,
}

#[near]
impl SecurityOracle {
    #[init]
    pub fn new(owner_id: AccountId, attesters: Vec<AccountId>) -> Self {
        let mut set = IterableSet::new(StorageKey::Attesters);
        for a in attesters {
            set.insert(a);
        }
        Self {
            owner_id,
            attesters: set,
            verdicts: LookupMap::new(StorageKey::Verdicts),
            reports: Vector::new(StorageKey::Reports),
            reports_by_account: LookupMap::new(StorageKey::ReportsByAccount),
            blocked: LookupMap::new(StorageKey::Blocked),
            attester_generations: LookupMap::new(StorageKey::AttesterGenerations),
        }
    }

    // ---- attester methods (no attached deposit: operators use a function-call key) ----

    pub fn submit_verdict(
        &mut self,
        account_id: AccountId,
        code_hash: String,
        verdict: VerdictKind,
        score_bps: u16,
        reasons_hash: String,
        expires_at_ns: U64,
    ) {
        let attester = self.assert_attester();
        require!(score_bps <= MAX_SCORE_BPS, "score_bps must be <= 10000");
        require!(code_hash.len() <= MAX_CODE_HASH_LEN, "code_hash too long");
        require!(
            is_sha256_hex(&reasons_hash),
            "reasons_hash must be 64 hex chars"
        );
        let now = env::block_timestamp();
        require!(expires_at_ns.0 > now, "expires_at_ns must be in the future");
        require!(
            expires_at_ns.0 <= now.saturating_add(MAX_VERDICT_TTL_NS),
            "expiry too far"
        );
        self.verdicts.insert(
            account_id.clone(),
            StoredVerdict {
                attester_generation: self.attester_generation(&attester),
                verdict: Verdict {
                    code_hash,
                    verdict,
                    score_bps,
                    reasons_hash,
                    attested_at_ns: U64(now),
                    expires_at_ns,
                    attester: attester.clone(),
                },
            },
        );
        Event::VerdictSubmitted {
            account_id,
            verdict,
            score_bps,
            attester,
        }
        .emit();
    }

    pub fn confirm_report(&mut self, report_id: U64) {
        let attester = self.assert_attester();
        let report = self.resolve(report_id, ReportStatus::Confirmed, &attester);
        self.blocked.insert(
            report.account_id.clone(),
            Block {
                report_id,
                evidence_sha256: report.evidence_sha256,
                confirmed_by: attester.clone(),
                confirmed_at_ns: U64(env::block_timestamp()),
            },
        );
        Event::ReportConfirmed {
            report_id,
            account_id: report.account_id,
            attester,
        }
        .emit();
    }

    pub fn dismiss_report(&mut self, report_id: U64) {
        let attester = self.assert_attester();
        let report = self.resolve(report_id, ReportStatus::Dismissed, &attester);
        Event::ReportDismissed {
            report_id,
            account_id: report.account_id,
            attester,
        }
        .emit();
    }

    // ---- public methods ----

    /// File a report against `account_id`. The caller pays for the report's storage; the excess
    /// deposit is refunded. The storage deposit is kept by the contract (it pays for the record).
    #[payable]
    pub fn report(
        &mut self,
        account_id: AccountId,
        evidence_url: String,
        evidence_sha256: String,
    ) -> U64 {
        require!(
            !evidence_url.is_empty() && evidence_url.len() <= MAX_URL_LEN,
            "evidence_url must be 1..=512 bytes"
        );
        require!(
            is_sha256_hex(&evidence_sha256),
            "evidence_sha256 must be 64 hex chars"
        );
        let reporter = env::predecessor_account_id();
        let attached = env::attached_deposit();
        let before = env::storage_usage();

        let id = self.reports.len() as u64;
        self.reports.push(Report {
            id: U64(id),
            account_id: account_id.clone(),
            reporter: reporter.clone(),
            evidence_url,
            evidence_sha256,
            deposit: NearToken::from_yoctonear(0),
            status: ReportStatus::Pending,
            created_at_ns: U64(env::block_timestamp()),
            resolved_by: None,
        });
        let mut ids = self
            .reports_by_account
            .get(&account_id)
            .cloned()
            .unwrap_or_default();
        ids.push(id);
        self.reports_by_account.insert(account_id.clone(), ids);
        self.reports.flush();
        self.reports_by_account.flush();

        let used = env::storage_usage()
            .checked_sub(before)
            .unwrap_or_else(|| env::panic_str("storage accounting"));
        let cost = env::storage_byte_cost()
            .checked_mul(used as u128)
            .unwrap_or_else(|| env::panic_str("storage cost overflow"));
        require!(
            attached >= cost,
            format!(
                "attach at least {} yoctoNEAR for storage",
                cost.as_yoctonear()
            )
        );
        self.reports.get_mut(id as u32).unwrap().deposit = cost;

        let refund = attached.saturating_sub(cost);
        if !refund.is_zero() {
            Promise::new(reporter.clone()).transfer(refund).detach();
        }
        Event::ReportFiled {
            report_id: U64(id),
            account_id,
            reporter,
        }
        .emit();
        U64(id)
    }

    // ---- owner methods (full-access key: one yoctoNEAR) ----

    #[payable]
    pub fn add_attester(&mut self, attester: AccountId) {
        self.assert_owner();
        self.attesters.insert(attester.clone());
        Event::AttesterAdded { attester }.emit();
    }

    #[payable]
    pub fn remove_attester(&mut self, attester: AccountId) {
        self.assert_owner();
        if self.attesters.remove(&attester) {
            // Re-adding a recovered operator must not revive verdicts signed by its old key.
            let generation = self
                .attester_generation(&attester)
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str("attester generation overflow"));
            self.attester_generations
                .insert(attester.clone(), generation);
        }
        Event::AttesterRemoved { attester }.emit();
    }

    /// Lift a block (e.g. a confirmation later found wrong). The report stays confirmed in history.
    #[payable]
    pub fn unblock(&mut self, account_id: AccountId) {
        let owner = self.assert_owner();
        require!(
            self.blocked.remove(&account_id).is_some(),
            "account is not blocked"
        );
        Event::Unblocked { account_id, owner }.emit();
    }

    #[payable]
    pub fn set_owner(&mut self, owner_id: AccountId) {
        self.assert_owner();
        self.owner_id = owner_id;
    }

    // ---- views ----

    /// The attested verdict, overridden to `block` (score 10000, never expiring) when the account
    /// is blocked by a confirmed report. A verdict whose attester has since been removed is not
    /// served, including after re-adding that attester; a block stands whoever confirmed it.
    pub fn get_verdict(&self, account_id: AccountId) -> Option<Verdict> {
        let attested = self
            .verdicts
            .get(&account_id)
            .filter(|v| {
                self.attesters.contains(&v.verdict.attester)
                    && v.attester_generation == self.attester_generation(&v.verdict.attester)
            })
            .map(|v| v.verdict.clone());
        match self.blocked.get(&account_id) {
            None => attested,
            Some(b) => Some(Verdict {
                code_hash: attested.map(|v| v.code_hash).unwrap_or_default(),
                verdict: VerdictKind::Block,
                score_bps: MAX_SCORE_BPS,
                reasons_hash: b.evidence_sha256.clone(),
                attested_at_ns: b.confirmed_at_ns,
                expires_at_ns: U64(u64::MAX),
                attester: b.confirmed_by.clone(),
            }),
        }
    }

    pub fn is_blocked(&self, account_id: AccountId) -> bool {
        self.blocked.contains_key(&account_id)
    }

    pub fn get_block(&self, account_id: AccountId) -> Option<Block> {
        self.blocked.get(&account_id).cloned()
    }

    pub fn get_report(&self, report_id: U64) -> Option<Report> {
        u32::try_from(report_id.0)
            .ok()
            .and_then(|i| self.reports.get(i))
            .cloned()
    }

    /// Reports filed against `account_id`, oldest first, paginated (at most 50 per call).
    pub fn get_reports(
        &self,
        account_id: AccountId,
        from_index: Option<u32>,
        limit: Option<u32>,
    ) -> Vec<Report> {
        let Some(ids) = self.reports_by_account.get(&account_id) else {
            return vec![];
        };
        let limit = limit.unwrap_or(MAX_REPORTS_PAGE).min(MAX_REPORTS_PAGE) as usize;
        ids.iter()
            .skip(from_index.unwrap_or(0) as usize)
            .take(limit)
            .filter_map(|&id| self.reports.get(id as u32).cloned())
            .collect()
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn get_attesters(&self) -> Vec<AccountId> {
        self.attesters.iter().cloned().collect()
    }

    pub fn is_attester(&self, account_id: AccountId) -> bool {
        self.attesters.contains(&account_id)
    }
}

impl SecurityOracle {
    fn attester_generation(&self, attester: &AccountId) -> u64 {
        self.attester_generations
            .get(attester)
            .copied()
            .unwrap_or(0)
    }

    fn assert_attester(&self) -> AccountId {
        let caller = env::predecessor_account_id();
        require!(
            self.attesters.contains(&caller),
            "only an attester can call this method"
        );
        caller
    }

    fn assert_owner(&self) -> AccountId {
        assert_one_yocto();
        let caller = env::predecessor_account_id();
        require!(
            caller == self.owner_id,
            "only the owner can call this method"
        );
        caller
    }

    fn resolve(&mut self, report_id: U64, status: ReportStatus, attester: &AccountId) -> Report {
        let idx = u32::try_from(report_id.0).unwrap_or_else(|_| env::panic_str("unknown report"));
        let report = self
            .reports
            .get_mut(idx)
            .unwrap_or_else(|| env::panic_str("unknown report"));
        require!(
            report.status == ReportStatus::Pending,
            "report is already resolved"
        );
        report.status = status;
        report.resolved_by = Some(attester.clone());
        report.clone()
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
