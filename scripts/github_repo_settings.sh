#!/usr/bin/env bash
# Apply the recommended GitHub security settings to a repository. Needs admin rights and the `gh` CLI, logged in as the
# repository owner (check with: gh api user --jq .login).
#
#   scripts/github_repo_settings.sh OWNER/REPO --dry-run   # print what would be done
#   scripts/github_repo_settings.sh OWNER/REPO             # do it
#
# Private vulnerability reporting, branch protection, rulesets and secret scanning are only available on PUBLIC
# repositories (or private ones on a paid GitHub plan). Anything GitHub refuses is reported and skipped, not fatal.
set -uo pipefail

REPO="${1:?usage: scripts/github_repo_settings.sh OWNER/REPO [--dry-run]}"
DRY="${2:-}"

# The CI job names that must pass before anything is merged (see .github/workflows/ci.yml).
CHECKS='["Tests (PostgreSQL 16)", "Terraform (fmt and validate)", "Dependencies (vulnerabilities and licences)", "Docker image and demo", "Sign-off (DCO)"]'

apply() { # apply "description" -- gh api args...
  local what="$1"; shift 2
  if [ "$DRY" = "--dry-run" ]; then echo "would: $what"; return 0; fi
  if out=$(gh api "$@" 2>&1 >/dev/null); then echo "ok:      $what"; else echo "skipped: $what -> $(echo "$out" | head -1 | cut -c1-140)"; fi
}

apply "private vulnerability reporting (SECURITY.md points to it)" -- -X PUT "repos/$REPO/private-vulnerability-reporting"
apply "Dependabot alerts"                                       -- -X PUT "repos/$REPO/vulnerability-alerts"
apply "Dependabot security updates"                             -- -X PUT "repos/$REPO/automated-security-fixes"
apply "secret scanning and push protection" -- -X PATCH "repos/$REPO" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

BODY=$(cat <<JSON
{
  "required_status_checks": {"strict": true, "contexts": $CHECKS},
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
)
if [ "$DRY" = "--dry-run" ]; then
  echo "would: protect main (required checks, up to date before merge, no force-push, no deletion, conversations resolved)"
else
  if out=$(echo "$BODY" | gh api -X PUT "repos/$REPO/branches/main/protection" --input - 2>&1 >/dev/null); then
    echo "ok:      protect main"
  else
    echo "skipped: protect main -> $(echo "$out" | head -1 | cut -c1-140)"
  fi
fi
echo "Note: enforce_admins is off, so the repository owner can still push directly in an emergency. Turn it on for a stricter setup."
