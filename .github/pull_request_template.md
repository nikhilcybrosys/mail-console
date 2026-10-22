## What and why

## Checklist
- [ ] Every commit is signed off (`git commit -s`), see CONTRIBUTING.md
- [ ] Tests added or updated, and `pytest` passes
- [ ] New user-visible strings use `{% trans %}`; no inline `style=`, `on*=` or scripts; colours come from tokens
- [ ] No message content, recipient lists or secrets in logs, errors or test fixtures
- [ ] Console roles still cannot send mail, and risky writes still go through approvals
