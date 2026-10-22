"""Expected-vs-actual DNS checks for SES identities (DKIM, MAIL FROM, SPF, DMARC)."""
import re

from .models import DnsCheckResult


def default_resolve(name, rtype):
    import dns.exception
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime, r.timeout = 5.0, 3.0
    try:
        ans = r.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    out = []
    for rd in ans:
        if rtype == "TXT":
            out.append(b"".join(rd.strings).decode("utf-8", "replace"))
        elif rtype == "MX":
            out.append(f"{rd.preference} {str(rd.exchange).rstrip('.')}")
        else:
            out.append(str(rd.target if rtype == "CNAME" else rd).rstrip("."))
    return out


def _result(domain, kind, ok, expected, actual, detail=""):
    return DnsCheckResult.objects.create(domain=domain, record_kind=kind, ok=ok, expected=expected, actual=actual, detail=detail[:500])


def check_dkim(domain, tokens, resolve=default_resolve):
    out = []
    for t in tokens:
        exp = f"{t}.dkim.amazonses.com"
        actual = resolve(f"{t}._domainkey.{domain}", "CNAME")
        out.append(_result(domain, "dkim", exp in actual, [exp], actual, "" if exp in actual else f"CNAME {t}._domainkey.{domain} missing or wrong"))
    return out


def check_spf(domain, resolve=default_resolve):
    txt = [t for t in resolve(domain, "TXT") if t.lower().startswith("v=spf1")]
    if not txt:
        return _result(domain, "spf", False, ["v=spf1 ... include:amazonses.com ~all"], [], "No SPF record. Receivers may treat mail as unauthenticated.")
    if len(txt) > 1:
        return _result(domain, "spf", False, ["exactly one SPF record"], txt, "Multiple SPF records are invalid (permerror).")
    rec = txt[0].lower()
    problems = []
    if "+all" in rec or re.search(r"\s\?all\b", rec):
        problems.append("SPF ends in +all/?all (allows anyone)")
    if not re.search(r"[~-]all\b", rec):
        problems.append("SPF has no ~all/-all terminator")
    lookups = len(re.findall(r"\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)", rec))
    if lookups > 10:
        problems.append(f"about {lookups} DNS-lookup terms (limit is 10)")
    return _result(domain, "spf", not problems, ["single SPF record ending ~all or -all"], txt, "; ".join(problems))


def check_dmarc(domain, resolve=default_resolve):
    txt = [t for t in resolve(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    if not txt:
        return _result(domain, "dmarc", False, ["v=DMARC1; p=quarantine|reject; rua=mailto:..."], [], "No DMARC record.")
    tags = dict(p.strip().split("=", 1) for p in txt[0].split(";") if "=" in p)
    policy, rua = tags.get("p", "").lower(), tags.get("rua", "")
    problems = []
    if policy == "none":
        problems.append("p=none is monitoring only (no enforcement)")
    elif policy not in ("quarantine", "reject"):
        problems.append(f"unknown policy {policy!r}")
    if not rua:
        problems.append("no rua= aggregate report address (you receive no DMARC reports)")
    return _result(domain, "dmarc", not problems, ["p=quarantine|reject with rua"], txt, "; ".join(problems))


def check_mail_from(domain, mail_from_domain, region, resolve=default_resolve):
    if not mail_from_domain:
        return []
    exp_mx = f"10 feedback-smtp.{region}.amazonses.com"
    mx = resolve(mail_from_domain, "MX")
    out = [_result(domain, "mail_from_mx", exp_mx in mx, [exp_mx], mx, "" if exp_mx in mx else "MAIL FROM MX missing or wrong")]
    spf = [t for t in resolve(mail_from_domain, "TXT") if t.lower().startswith("v=spf1")]
    ok = any("include:amazonses.com" in t.lower() for t in spf)
    out.append(_result(domain, "mail_from_spf", ok, ["v=spf1 include:amazonses.com ~all"], spf, "" if ok else "MAIL FROM SPF must include amazonses.com"))
    return out


def check_identity(snapshot, resolve=default_resolve):
    """Run every relevant check for a DOMAIN identity snapshot."""
    if snapshot.identity_type != "DOMAIN" and "@" in snapshot.identity:
        return []
    d = snapshot.identity
    res = []
    if snapshot.dkim_signing_origin != "EXTERNAL":  # BYODKIM uses a TXT selector we cannot derive
        res += check_dkim(d, snapshot.dkim_tokens, resolve)
    res.append(check_spf(d, resolve))
    res.append(check_dmarc(d, resolve))
    res += check_mail_from(d, snapshot.mail_from_domain, snapshot.region, resolve)
    return res
