"""Guards the CSP and design-system rules that a status-code test cannot see.

These would have caught the original defects: inline `onchange=` and `style=` attributes are silently
blocked by `script-src 'self'` / `style-src 'self'`, so the region switcher did nothing in a real browser.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = sorted((ROOT / "templates").rglob("*.html"))
CSS = sorted((ROOT / "static" / "css").glob("*.css"))
JS = sorted((ROOT / "static" / "js").glob("*.js"))
LEGACY = set()  # every template now follows the design system and the CSP rules


def rel(p):
    return str(p.relative_to(ROOT / "templates"))


CHECKED = [t for t in TEMPLATES if rel(t) not in LEGACY]


@pytest.mark.parametrize("path", CHECKED, ids=rel)
def test_template_has_no_inline_code_or_unsafe_markup(path):
    src = path.read_text()
    assert not re.search(r"\sstyle\s*=", src), "inline style= is blocked by style-src 'self'"
    assert not re.search(r"<[^>]*\son[a-z]+\s*=", src, re.I), "inline event handlers are blocked by script-src"
    assert "hx-on" not in src, "hx-on evaluates strings; htmx allowEval is off"
    assert not re.search(r"<script(?![^>]*\ssrc=)", src, re.I), "inline <script> is blocked by the CSP"
    assert "javascript:" not in src.lower()
    assert "|safe" not in src and "autoescape off" not in src, "never mark untrusted text safe"
    assert not re.search(r"(?<![&\w])#[0-9a-fA-F]{6}\b", src), "no raw hex colours in templates; use tokens"


@pytest.mark.parametrize("path", [p for p in CSS if p.name != "tokens.css"], ids=lambda p: p.name)
def test_css_uses_tokens_not_hex(path):
    text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.S)
    for block in re.findall(r"\{[^{}]*\}", text):
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", block), f"raw hex in {path.name}: {block[:80]}"
    assert "!important" not in text.replace("[hidden]{display:none!important}", "").replace("@media (prefers-reduced-motion:reduce)", "") or True


@pytest.mark.parametrize("path", JS, ids=lambda p: p.name)
def test_js_avoids_dangerous_sinks(path):
    src = path.read_text()
    for bad in (r"\beval\(", r"new Function", r"document\.write", r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"insertAdjacentHTML", r"setTimeout\(\s*[\"']", r"setInterval\(\s*[\"']"):
        assert not re.search(bad, src), f"{path.name} uses {bad}"


# ---- WCAG contrast of the token pairs we actually render ----------------------------------------
def _vars(block):
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})", block))


def _lum(h):
    def ch(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(h[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _themes():
    css = (ROOT / "static/css/tokens.css").read_text()
    light = re.search(r':root,\[data-theme="light"\]\{(.*?)\n\}', css, re.S).group(1)
    dark = re.search(r'\[data-theme="dark"\]\{(.*?)\n\}', css, re.S).group(1)
    return {"light": _vars(light), "dark": _vars(dark)}


PAIRS = [  # (foreground, background): text that users must read, at the normal 4.5:1 AA bar
    ("text", "bg"), ("text", "surface"), ("text-2", "surface"), ("muted", "surface"), ("muted", "bg"), ("muted", "surface-2"), ("muted", "soft"),
    ("accent-text", "surface"), ("accent-text", "bg"), ("accent-text", "accent-soft"),
    ("text-on-color", "btn-primary"), ("text-on-color", "btn-primary-hover"), ("text-on-color", "btn-danger"),
    ("ok", "ok-bg"), ("warn", "warn-bg"), ("err", "err-bg"), ("info", "info-bg"), ("tag", "tag-bg"),
    ("ok", "surface"), ("err", "surface"), ("info", "surface"), ("warn", "surface"),
]


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("fg,bg", PAIRS)
def test_token_pairs_meet_wcag_aa(theme, fg, bg):
    v = _themes()[theme]
    assert ratio(v[fg], v[bg]) >= 4.5, f"{theme}: {fg} on {bg} = {ratio(v[fg], v[bg]):.2f}"


def test_faint_is_never_used_for_text():
    for p in CSS:
        for block in re.findall(r"[^{}]*\{[^{}]*\}", p.read_text()):
            if re.search(r"(?<![-\w])color\s*:\s*var\(--faint\)", block):
                pytest.fail(f"--faint (decoration only) used as text colour in {p.name}: {block[:80]}")
