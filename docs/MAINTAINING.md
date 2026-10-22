# Maintaining the repository

## Going public
1. Check the working tree and history one more time for anything private (`git grep -i <name> $(git rev-list --all)`).
2. Make the repository public (Settings, then General, then Danger zone).
3. Apply the recommended security settings straight away:

       scripts/github_repo_settings.sh OWNER/REPO --dry-run
       scripts/github_repo_settings.sh OWNER/REPO

   This enables private vulnerability reporting (which `SECURITY.md` points to), Dependabot alerts and security updates,
   secret scanning with push protection, and protects `main`: the CI jobs must pass and branches must be up to date,
   with no force-pushes or deletions. GitHub only offers most of these on public repositories (or paid plans).
4. Once `main` is protected, changes go through pull requests. Every commit needs a `Signed-off-by` line (`git commit -s`).

## Dependencies
Dependabot opens weekly pull requests. Django major versions are ignored on purpose (the project follows the 5.2 LTS
line); change `.github/dependabot.yml` when you decide to upgrade. Regenerate `requirements.lock` after upgrades.
