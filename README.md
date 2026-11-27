# PipeGuard demo: BasraShop

A small demo repository for the PipeGuard course project (static audit of the GitHub Actions to
AWS trust chain). **Every value here is a placeholder**: AWS account `111122223333` is the example
account of the AWS documentation; there is no real AWS account, role or bucket behind it.

- `.github/workflows/deploy.yml` deploys the site with OIDC from `main`. Its job has
  `if: ${{ false }}`: it never runs, so this repository never sends a token to AWS.
- `infra/main.tf` is the deploy role's trust policy. It checks only `aud` (no `sub`), so **any
  repository on GitHub** could assume the role: PipeGuard reports CRITICAL.
- `.github/workflows/pipeguard.yml` runs `python -m pipeguard gate` on every pull request and
  fails the check on CRITICAL / HIGH findings. Make it a required check (ruleset or branch
  protection) so that GitHub blocks the merge.
- `tools/pipeguard/` is a copy of the PipeGuard package (made by `scripts/build_demo.py`).

Run locally (Python 3.11+): `PYTHONPATH=tools/pipeguard python -m pipeguard gate . --repo OWNER/REPO`.
