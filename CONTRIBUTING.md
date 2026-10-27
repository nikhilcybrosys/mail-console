# Contributing

Thanks for helping. This project is licensed under the Apache License 2.0 (see `LICENSE`).

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](DCO) instead of a contributor licence agreement.
Add a sign-off to every commit; it certifies that you have the right to submit the change:

    git commit -s -m "Fix suppression search for mixed-case addresses"

This appends `Signed-off-by: Your Name <you@example.com>`. Pull requests with unsigned commits cannot be merged.

## Set up

    python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
    # a throwaway PostgreSQL 16 on port 54329 (see config/test_settings.py), then
    .venv/bin/python -m pytest

There is no Node toolchain: the UI is server-rendered Django + HTMX with plain CSS and a few small JavaScript
files. Please keep it that way.

## Continuous integration
Every pull request runs the tests on PostgreSQL 16, Django deployment checks, a migrations check, tests of the AWS policy files (no console role can send mail),
a dependency vulnerability and licence audit, a Docker build with a smoke test of the demo, and a DCO
check. Run `docker compose up --build` to try the demo locally (see the README).

## What a good change looks like
- **Tests:** logic needs a test. `tests/test_ui_contract.py` fails the build on inline `style=` or `on*=`
  attributes, inline scripts, raw hex colours outside `static/css/tokens.css`, unsafe JavaScript sinks, and
  colour pairs below WCAG AA. Use design tokens, not colours.
- **Security first:** this tool renders untrusted email and can change SES settings. Never mark untrusted text
  safe, never log message bodies or recipient lists, keep the console roles unable to send mail, and keep writes behind the
  approval flow. Report vulnerabilities privately (see `SECURITY.md`), not in public issues.
- **Strings:** wrap user-visible template text in `{% trans %}` or `{% blocktrans %}`.
- **No new runtime dependencies** without a reason in the pull request, and check their licence is compatible with Apache-2.0.
- **No external requests:** fonts, icons and scripts are vendored under `static/`; nothing loads from a CDN.

## Branding
The name, logo and accent colour are configurable in *Settings > Appearance* or with the `MC_BRAND_*` settings, so forks
can rebrand without editing templates.
