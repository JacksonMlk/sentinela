# Architecture & Technical Decisions

This document explains the **why** behind Sentinela's main design choices. For the high-level diagram and feature list, see the [README](../README.md).

---

## Multi-tenancy via STS AssumeRole

**Decision:** every client is represented by an IAM Role ARN on their own AWS account. Sentinela's operator account assumes that role via `sts:AssumeRole` to collect data.

**Why:**
- **No long-lived credentials stored.** We never see, store, or rotate access keys. Customers can revoke access by detaching the role's trust policy.
- **Audit trail belongs to the customer.** Every API call shows up in *their* CloudTrail under an assumed-role session — they can see exactly what we did.
- **Read-only by design.** The role is attached `ReadOnlyAccess` + `SecurityAudit`. There is no path to mutate state from the analyzer.
- **Multi-account orgs are first-class.** A single client can register multiple ARNs (see *Account modes* below) and we'll analyze each in the same run.

**Alternative considered:** API gateway keys / signed webhooks. Rejected because it requires running infra on the customer side and complicates the trust story.

---

## Account modes: `organization` vs `standalone`

**Decision:** the [`Client`](../app/models.py) model has an `account_mode` field with two values:

| Mode | What it means |
|------|---------------|
| `organization` | One ARN. Used when the role lives in the management account of an AWS Organization, and we walk member accounts from there. |
| `standalone` | A list of `{arn, regions}` entries. Used when there is no Organization, or when a customer wants to onboard a subset of accounts explicitly. |

**Why:** real customers split roughly in half. Forcing everyone into the Organization model excluded smaller customers; forcing everyone into the multi-ARN list lost the elegance of "one role to rule them all" for the larger ones. Two modes, one analyzer.

---

## Synchronous analysis with thread-based jobs

**Decision:** analyses run in a Python `threading.Thread` spawned by the request handler (see [`app/routers/admin.py`](../app/routers/admin.py)). A `threading.Event` is used for cancellation. Status is persisted to `analysis_reports.status`.

**Why:**
- Analyses take 5–15 minutes and the boto3 SDK is **I/O-bound** (lots of waiting on AWS API responses). The GIL is not the bottleneck — network round-trips are.
- Adding Celery / Redis / RQ would triple the infra footprint for what is, in practice, a single-replica deployment. Cost of complexity > cost of a thread.
- Cancellation via `threading.Event` is checked at well-defined boundaries between AWS data sources, so jobs stop cleanly without leaking sessions.

**Trade-off accepted:** if the process dies mid-analysis, the job is lost. Status flips to `failed` on the next request that touches it. For a beta tool used by an operator who can re-trigger, this is acceptable. For SaaS scale, swap in Celery.

---

## Same SQLAlchemy schema for SQLite (dev) and PostgreSQL (prod)

**Decision:** `DATABASE_URL` selects the driver. Models use only types that work in both (`Integer`, `String`, `Text`, `JSON`, `DateTime`).

**Why:**
- Local dev needs zero setup — `sqlite:///./sentinela.db` and you're running.
- Prod needs concurrent writers and durability — Postgres.
- `JSON` columns work in both (SQLite stores as `TEXT`, Postgres as native `jsonb`).
- No port between environments means no "works in dev, breaks in prod" surprises.

---

## Manual `ALTER TABLE` migrations (interim)

**Decision:** [`app/main.py`](../app/main.py) runs an idempotent `ALTER TABLE … ADD COLUMN` block on startup for every column added after the initial schema. It diffs the live schema against a hard-coded list.

**Why this exists:**
- Sentinela went from solo project to "running for clients" without ever sitting still long enough to introduce Alembic.
- The schema changes are exclusively **additive** — new nullable columns — which is the one shape `ALTER TABLE … ADD COLUMN` handles safely in both SQLite and Postgres.
- It survives `Base.metadata.create_all()` because `create_all` is no-op for existing tables.

**Why it's tech debt:** any destructive or renaming migration breaks this approach. Alembic is the right answer and is on the [Future ideas](../README.md#future-ideas) list.

---

## Jinja2 + vanilla JS instead of a SPA

**Decision:** server-rendered HTML with Jinja2 templates, vanilla JS for interactivity, Chart.js for charts. No React/Vue/Svelte. No build pipeline.

**Why:**
- The data is **read-mostly** and **per-page**. There's no global app state that justifies a client-side store.
- A FinOps report is a thing you scroll through and copy commands from. It's a document, not an app.
- Page-load performance is dominated by the Anthropic API call latency upstream, not by client-side hydration.
- One language (Python) end-to-end keeps the contributor surface tiny.

**Trade-off accepted:** the UX is not as snappy as a SPA. Filter/sort interactions cause a server round-trip. That's fine for a tool used by ops, not customers, in long sessions.

---

## Two analysis layers: `aws_analyzer` (data) + `claude_analyzer` (insight)

**Decision:** [`aws_analyzer.py`](../app/aws_analyzer.py) only **collects** — it makes no judgments. [`claude_analyzer.py`](../app/claude_analyzer.py) only **analyzes** — it never talks to AWS. The raw data is persisted to `analysis_reports.raw_data` alongside the structured analysis output.

**Why:**
- **Replayability.** A bug in the analyzer prompts? Re-run Claude against stored raw data without burning new Cost Explorer queries. Save hours of debugging.
- **Auditability.** A customer asks "why did you flag this?" — we can show them the exact JSON that went into the prompt.
- **Determinism boundaries.** Data collection is deterministic; AI analysis is not. Keeping them in separate modules makes that boundary explicit.
- **Provider swap is cheap.** If we want to try a different model, only `claude_analyzer.py` changes.

---

## What we ask Claude to do (and what we don't)

**Claude does:**
- Score the account on FinOps maturity and security posture across well-defined dimensions
- Generate prioritized Quick Wins with USD savings estimates and `aws cli` commands
- Generate the **combined matrix** that cross-references cost and risk — this is the single hardest part to do by hand and the highest-value output
- Write natural-language summaries grounded in the raw data

**Claude does NOT:**
- Compute the actual cost numbers — those come straight from Cost Explorer
- Decide what resources exist — those come straight from boto3
- Execute anything — see the [v2 featured direction](../README.md#future-ideas) for where we want this to evolve

**Why this split:** LLMs are unreliable at arithmetic and great at synthesis. Numbers come from AWS; meaning comes from Claude.

---

## Authentication: three layers

**Decision:** three distinct auth mechanisms for three distinct audiences.

| Audience | Mechanism | Where |
|----------|-----------|-------|
| Admin operator (dev) | Shared `ADMIN_SECRET_TOKEN` via login form | [`app/main.py`](../app/main.py) middleware |
| Admin operator (prod) | Cognito OIDC (optional) | `COGNITO_*` env vars |
| End customer | Per-client URL token (`access_token` field) | [`app/routers/client.py`](../app/routers/client.py) |

**Why:**
- The admin and the customer are fundamentally different roles — the admin can edit everything, the customer can only read their own report. They should not share an auth mechanism.
- A per-client URL token is the lowest-friction option for the customer (no signup, no password reset flow) and is acceptable because the data is already filtered to that customer.
- Cognito is opt-in because not every deployment wants AWS-bound identity.

---

## Docker: multi-stage build

**Decision:** Python wheel build in stage 1, slim runtime in stage 2. `git`/`curl` removed from the final image. See [`Dockerfile`](../Dockerfile).

**Why:**
- The WeasyPrint dependency chain (libffi, cairo, pango) is big. Without multi-stage, the final image was ~600 MB. With it, it's ~520 MB. Not huge savings, but every base-image pull on EKS is faster.
- Removing `git` and `curl` from the runtime is a small but free attack-surface reduction.

---

## Why not Steampipe / Prowler-as-a-library

**Considered and rejected:**

- **Steampipe** is a great query layer, but it adds a SQL engine to the stack and requires bundling/installing plugin binaries. The boto3 calls Sentinela makes are direct enough that the abstraction wasn't earning its complexity.
- **Prowler** is integrated, but only as an **optional async scan** ([`app/prowler_runner.py`](../app/prowler_runner.py)) — not as the primary security collector. Prowler runs take 30–60 min and we needed sub-15-min turnaround for the main analysis flow.

Both are excellent tools; they just solve a slightly different problem than what Sentinela targets.

---

## Open questions / known sharp edges

These aren't decisions yet — they're places where the current answer is "good enough for beta, will need revisiting":

- **No retry logic on Anthropic API failures.** A 429 currently fails the whole job. Should be exponential backoff with a budget.
- **Cost Explorer throttling under heavy use.** AWS throttles aggressively; we don't yet have a token-bucket smoother.
- **No background-job persistence.** If the process restarts mid-analysis, the job is gone. See [Synchronous analysis](#synchronous-analysis-with-thread-based-jobs) trade-off.
- **Prompts are hard-coded.** No prompt registry, no versioning. Fine for one author, brittle for a team.
