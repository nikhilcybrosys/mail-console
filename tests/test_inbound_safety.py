import pytest

from apps.inbound.mime import parse_mime, thread_key
from apps.inbound.redact import redact_text
from apps.inbound.sanitize import sanitize_html

XSS = [
    "<script>alert(1)</script>hello",
    '<img src=x onerror="alert(1)">',
    '<svg onload=alert(1)><circle/></svg>',
    '<a href="javascript:alert(1)">click</a>',
    '<iframe src="https://evil.example/"></iframe>',
    '<object data="x"></object><embed src="x">',
    '<form action="https://evil.example"><input name=p></form>',
    '<meta http-equiv="refresh" content="0;url=https://evil.example">',
    '<base href="https://evil.example/">',
    '<link rel="stylesheet" href="https://evil.example/x.css">',
    '<style>body{background:url(https://evil.example/t.gif)}</style>x',
    '<div style="background:url(https://evil.example/t.gif)">x</div>',
    '<p onclick="steal()">x</p>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>',
    '<a href="vbscript:msgbox(1)">x</a>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
]
FORBIDDEN = ["<script", "onerror", "onload", "onclick", "javascript:", "<iframe", "<img", "<svg", "<form", "<meta", "<base", "<link", "<style", "<object", "<embed", "style=", "data:text", "vbscript:", "src="]


@pytest.mark.parametrize("payload", XSS)
def test_sanitizer_neutralises_xss_corpus(payload):
    out = sanitize_html(payload).lower()
    for bad in FORBIDDEN:
        assert bad not in out, f"{bad!r} survived in {out!r} for {payload!r}"


def test_links_are_inert_text_with_redacted_tokens():
    out = sanitize_html('<a href="https://app.example.com/reset/Abcdef0123456789ABCDEFxyz?token=SECRET123&x=1">Reset</a>')
    assert "<a " not in out and "href=" not in out
    assert "SECRET123" not in out and "Abcdef0123456789ABCDEFxyz" not in out and "[redacted]" in out


def test_redaction_rules():
    t = "Your verification code is 123456. Visit https://x.io/verify/AAAAAAAAAAAAAAAAAAAA?sig=zzz&ok=1 Bearer abcdefghijklmnopqrstuvwxyz AKIAABCDEFGHIJKLMNOP"
    out = redact_text(t)
    for secret in ("123456", "AAAAAAAAAAAAAAAAAAAA", "zzz", "abcdefghijklmnopqrstuvwxyz", "AKIAABCDEFGHIJKLMNOP"):
        assert secret not in out
    assert "ok=1" in out  # non-secret params stay readable


def test_bad_category_regex_is_ignored_not_raised():
    assert redact_text("hello", ["("]) == "hello"


RAW = (b"From: Bob <bob@customer.com>\r\nTo: support@inbound.example.com\r\nSubject: Re: invoice\r\n"
       b"Message-ID: <m3@customer.com>\r\nIn-Reply-To: <m2@example.com>\r\nReferences: <m1@example.com> <m2@example.com>\r\n"
       b"X-SES-Spam-Verdict: PASS\r\nX-SES-Virus-Verdict: PASS\r\nAuthentication-Results: amazonses.com; spf=pass; dkim=pass; dmarc=fail\r\n"
       b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
       b"--B\r\nContent-Type: text/html\r\n\r\n<p>Hi <script>x()</script><img src=https://t.example/p.gif></p>\r\n"
       b"--B\r\nContent-Type: application/pdf; name=inv.pdf\r\nContent-Disposition: attachment; filename=inv.pdf\r\n"
       b"Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--B--\r\n")


def test_parse_mime_threading_verdicts_attachments():
    p = parse_mime(RAW)
    assert p.from_addr == "bob@customer.com" and p.subject == "Re: invoice"
    assert thread_key(p) == "<m1@example.com>"
    assert p.verdicts["spam"] == "PASS" and p.verdicts["dmarc"] == "FAIL" and p.verdicts["spf"] == "PASS"
    assert p.attachments == [{"index": 0, "filename": "inv.pdf", "content_type": "application/pdf", "size": 9}]
    assert "<script" not in p.html_clean and "<img" not in p.html_clean
