# Human oracle demo

Run the existing service from the repository root:

```sh
uv run uvicorn near.service.app:app --port 8000
```

Open **http://localhost:8000/human/** or choose **Human oracle** in the transaction inspector.

- Scoring a transaction or scanning an account automatically queues `suspicious` and `malicious_pattern` assessments. Transaction evidence returned through `/v1/check` also enters the queue.
- Search by hash/account, filter priority and status, inspect the original evidence, and confirm or dismiss a finding with a required note. Reviewed cases can be reopened.
- **Load demo cases** adds four real historical findings from the checked-in FastNEAR recording, scored offline. These are labelled historical demos and stored separately from live findings; loading them again does not reset decisions.
- Cases and decisions persist in `data/human_reviews.sqlite3` (gitignored). Override with `ORACLE_REVIEW_DB` if needed. Repeated scoring keeps the original evidence snapshot and review decision.
- No authentication, as requested for this demo. Review decisions are local annotations and do not update the blocklist, sign transactions, or change on-chain policy. Use this unauthenticated surface only as a local demo.

The queue refreshes every 15 seconds. It collects inspections and scans performed through this service; it is not a continuous mainnet monitor. The demo stores the latest note and decision, not a multi-reviewer audit trail.

API: `GET /v1/reviews`, `PATCH /v1/reviews/{id}` with `{status, note}`, and `POST /v1/reviews/demo`.
