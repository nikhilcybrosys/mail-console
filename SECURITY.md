# Security policy

Mail Console renders untrusted email and can change Amazon SES settings, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately in either way:

1. Use GitHub's **"Report a vulnerability"** button on the repository's *Security* tab (private vulnerability reporting), or
2. email **nikhil.ravi10@gmail.com** with the subject `Mail Console security`.

Include what you found, how to reproduce it, the affected version or commit, and the impact you expect. A short proof of
concept is ideal. Do not include real customer data or message contents.

You can expect an acknowledgement within **5 business days**. This is a small project, so fix times depend on severity;
I will keep you updated and agree a disclosure date with you. The default is coordinated disclosure within **90 days**,
sooner for fixes that are quick, and credit if you want it.

## Supported versions

Only the latest release and the `main` branch receive security fixes while the project is pre-1.0.

## Scope

In scope: the console application (`apps/`, `config/`, `templates/`, `static/`), the mail renderer on its separate origin,
the approval and audit mechanisms, sign-in and passkey handling, the Docker image, and the IAM policies and setup steps in `aws/`.

Particularly interesting to me:
- anything that makes untrusted email content execute script, load remote resources or escape the sandboxed viewer;
- bypassing role checks, domain scoping, the passkey step-up or the four-eyes approval flow;
- anything that lets a console role send mail (other than through the opt-in Compose send role, within the limits documented in `aws/README.md` section 8) or make an unapproved SES change;
- tampering with, or hiding entries in, the audit log;
- authentication bypass, account takeover or session weaknesses in the sign-in flow;
- SQL injection, SSRF, path traversal, or secrets exposed in logs, errors or the image.

Out of scope: vulnerabilities in Amazon Web Services, your identity provider or third-party dependencies themselves
(report those upstream, though I welcome a heads-up if this project uses one in a vulnerable way), denial of service from
unrealistic traffic volumes, findings that need an already fully-compromised administrator or host, and the
`MC_DEBUG` / `MC_DEV_LOGIN` demo mode, which is deliberately insecure and refuses to run unless enabled explicitly.

## Good-faith research

If you act in good faith, avoid privacy violations and data destruction, only test against your own deployment, and give
me reasonable time to fix, I will not pursue action against you.

## Hardening you should apply when deploying

- Set `MC_OIDC_ALLOWED_DOMAIN` (the app refuses to start without a domain policy) and provision users explicitly.
- Serve the mail renderer from a **separate registrable domain** with no cookies (`MC_MAILVIEW_HOST`).
- Never set `MC_DEBUG` or `MC_DEV_LOGIN` outside a throwaway local demo.
- Use the read-only app role and the two narrow write roles from `aws/`; never grant `ses:Send*` to anything the console uses.
- Keep `MC_AWS_WRITE_ROLE_EXTERNAL_ID` secret (the write roles require it) and run the console as its own unprivileged user.
- Run the console on its **own host**, shared with no other service, and require IMDSv2 (see `aws/README.md`, "Where to run it").
- Keep the audit bucket in Object Lock mode and review `login.identity_mismatch` audit events.
