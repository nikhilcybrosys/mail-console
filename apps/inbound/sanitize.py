"""Turn untrusted email HTML into inert, display-only HTML.

Layers (the renderer adds the others): this sanitizer, a separate cookie-less origin, a sandboxed
iframe with no allow-scripts, and a CSP of `default-src 'none'`.

- allow-list of formatting tags only; no img/svg/form/iframe/object/style/script/link/meta/base
- no attributes at all except a few safe table ones; hrefs are rendered as visible text, not links
- remote images are dropped (kills tracking pixels); there is no proxy in v1
"""
import re

import nh3

from .redact import redact_text

ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li",
    "ol", "p", "pre", "small", "span", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul",
}
ALLOWED_ATTRS = {"a": {"href"}, "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"}}
_A_TAG = re.compile(r'<a href="([^"]*)"[^>]*>(.*?)</a>', re.S | re.I)


def sanitize_html(html, extra_rules=()):
    clean = nh3.clean(
        html or "", tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, url_schemes={"http", "https", "mailto"},
        link_rel=None, strip_comments=True, clean_content_tags={"script", "style", "template"},
    )

    def _link(m):
        href = redact_text(m.group(1), extra_rules)
        return f'<span class="lnk" title="{href}">{m.group(2)} [{href}]</span>'

    clean = _A_TAG.sub(_link, clean)
    return redact_text(clean, extra_rules)
