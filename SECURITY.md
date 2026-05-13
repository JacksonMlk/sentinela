# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in Sentinela, **please do not open a public issue**. Public disclosure before a fix is available puts users at risk.

Instead, contact the maintainer directly:

- **Email:** jackson.ssantos21@gmail.com
- **Subject line:** `[Sentinela Security] <short summary>`

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof-of-concept
- The version / commit SHA you tested against
- Your contact details if you'd like credit in the fix announcement

## What to expect

- **Acknowledgement** within 72 hours (best effort — this is a side project)
- **Initial assessment** within 7 days describing whether the report is accepted and the planned response
- **Fix and disclosure** coordinated with you. We aim to publish the fix and an advisory within 30 days of acknowledgement for confirmed issues. Complex issues may take longer; we'll keep you informed.

## Scope

In scope:

- The Sentinela application code in this repository
- The default Docker image build
- The default Kubernetes manifests under `k8s/`

Out of scope:

- Vulnerabilities in upstream dependencies (please report those upstream — we'll bump the version once a patched release exists)
- Vulnerabilities in customer-side IAM configuration (we provide guidance in [SETUP.md](SETUP.md); audit your own roles)
- Social engineering, physical attacks, or denial-of-service via volumetric traffic
- Issues that require a compromised admin account to exploit (the admin is fully trusted)

## Hardening recommendations for operators

Sentinela is a beta tool. If you deploy it to production, at minimum:

- Rotate `ADMIN_SECRET_TOKEN` to a long random value (or use Cognito OIDC instead)
- Set `https_only=True` on the session middleware in [`app/main.py`](app/main.py)
- Run behind an Ingress with TLS termination
- Grant the operator IAM role only `sts:AssumeRole` for the specific customer role ARNs you've onboarded — never `*`
- Restrict the customer-side role to `ReadOnlyAccess` + `SecurityAudit`. Sentinela does not need (and should not have) any write permissions
- Run the container as non-root (the slim base image already does)
- Back up the database — `analysis_reports.raw_data` contains a redacted but still sensitive snapshot of customer AWS state
