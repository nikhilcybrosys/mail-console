"""Appearance settings: reading the current look, and checking everything an admin submits before it is saved.

Uploaded images are checked by their content, never by file name or the browser's claim, and an image that is not clearly
safe is REFUSED, never edited. A logo or favicon is PNG or SVG (a favicon may also be ICO). An SVG is accepted only when
every element and attribute is on a short allow-list: no scripts, no links, no external references, no DOCTYPE.
"""
import hashlib
import re
import struct
import zlib
from xml.parsers import expat

from django.conf import settings
from django.templatetags.static import static
from django.urls import reverse

from .models import BrandImage, Branding

MAX_IMAGE = 512 * 1024
MAX_PIXELS = 1024
MAX_NAME, MAX_LOGIN_TEXT, MAX_FOOTER = 40, 160, 200
SVG_NS = "http://www.w3.org/2000/svg"
PNG, ICO, SVG = "image/png", "image/x-icon", "image/svg+xml"
_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]")
_HEX = re.compile(r"#[0-9a-fA-F]{6}")


# ------------------------------------------------------------------ reading
def current(request=None):
    """What the templates need, with defaults from the environment. Cached on the request; never writes."""
    if request is not None and hasattr(request, "_brand"):
        return request._brand
    row = Branding.objects.first()
    sha = dict(BrandImage.objects.values_list("kind", "sha256"))

    def url(kind, route, fallback):
        return f"{reverse(route)}?v={sha[kind][:12]}" if kind in sha else fallback

    default_logo, default_dark = static(settings.BRAND_LOGO), static(settings.BRAND_LOGO_DARK)
    logo = url(BrandImage.LOGO, "brand_logo", default_logo)
    out = {
        "name": (row.name if row and row.name else settings.BRAND_NAME),
        "accent": (row.accent if row and row.accent else settings.BRAND_ACCENT),
        "login_text": row.login_text if row else "",
        "footer_text": row.footer_text if row else "",
        "default_theme": row.default_theme if row else "system",
        "default_density": row.default_density if row else "compact",
        "logo": logo,
        # With only one logo uploaded it is used in both themes, rather than mixing it with the default white mark.
        "logo_dark": url(BrandImage.LOGO_DARK, "brand_logo_dark", logo if BrandImage.LOGO in sha else default_dark),
        "favicon": url(BrandImage.FAVICON, "brand_favicon", static("brand/favicon.svg")),
        "version": row.updated_at.strftime("%Y%m%d%H%M%S") if row else "0",
        "customised": bool(row or sha),
    }
    if request is not None:
        request._brand = out
    return out


# ------------------------------------------------------------------ colour
DEFAULT_ACCENT = "#CF4430"
DEFAULT_LOGIN_TEXT = "See what happened to every email, and fix problems without opening the AWS console."


def _lum(hex_color):
    def chan(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast_with_white(hex_color):
    return 1.05 / (_lum(hex_color) + 0.05)


def _darken(hex_color, factor=0.88):
    return "#" + "".join(f"{int(int(hex_color[i:i + 2], 16) * factor):02X}" for i in (1, 3, 5))


def _mix(hex_color, other, share):
    """`share` (0 to 1) of `other` blended into `hex_color`."""
    return "#" + "".join(f"{round(int(hex_color[i:i + 2], 16) * (1 - share) + int(other[i:i + 2], 16) * share):02X}" for i in (1, 3, 5))


def usable_accent(value):
    """The accent if it is #RRGGBB and keeps white text at 4.5:1, else ''."""
    return value if value and _HEX.fullmatch(value) and contrast_with_white(value) >= 4.5 else ""


def accent_tones(accent):
    """Every colour the theme derives from one accent, for both themes."""
    return {
        "accent": accent, "hover": _darken(accent),
        "light_text": _darken(accent, 0.8), "light_soft": _mix(accent, "#FFFFFF", 0.9),
        "dark_text": _mix(accent, "#FFFFFF", 0.55), "dark_soft": _mix(accent, "#151517", 0.82), "dark_ring": _mix(accent, "#151517", 0.7),
    }


# ------------------------------------------------------------------ text, choices
def _plain(value, label, limit, required=False):
    value = (value or "").strip()
    if _CONTROL.search(value):
        return value, [f"{label} cannot contain line breaks or control characters."]
    if len(value) > limit:
        return value[:limit], [f"{label} can be at most {limit} characters."]
    if required and not value:
        return value, [f"{label} cannot be empty."]
    return value, []


def check_accent(value):
    """'' (use the default) or #RRGGBB that keeps white button text at WCAG AA (4.5:1). Returns (normalised, errors)."""
    value = (value or "").strip()
    if not value:
        return "", []
    if not _HEX.fullmatch(value):
        return value[:7], ["The accent colour must look like #1F4FBF."]
    value = value.upper()
    if contrast_with_white(value) < 4.5:
        return value, ["That colour is too light for white button text. Choose a darker one."]
    return value, []


def check_text_fields(post):
    """-> (values, errors) for the name, sign-in line, footer, accent, theme and density."""
    errors, values = [], {}
    values["name"], e = _plain(post.get("name"), "The name", MAX_NAME)
    errors += e
    values["login_text"], e = _plain(post.get("login_text"), "The sign-in line", MAX_LOGIN_TEXT)
    errors += e
    values["footer_text"], e = _plain(post.get("footer_text"), "The footer", MAX_FOOTER)
    errors += e
    values["accent"], e = check_accent(post.get("accent"))
    errors += e
    theme, density = post.get("default_theme") or "system", post.get("default_density") or "compact"
    if theme not in dict(Branding.THEMES):
        errors.append("Choose light, dark or match the device for the default theme.")
        theme = "system"
    if density not in dict(Branding.DENSITIES):
        errors.append("Choose compact or comfortable for the default density.")
        density = "compact"
    values["default_theme"], values["default_density"] = theme, density
    return values, errors


# ------------------------------------------------------------------ images
class ImageRefused(Exception):
    """The reason, in plain words, shown to the person."""


def inspect_image(raw, kind):
    """-> content type. Raises ImageRefused. `kind` is a BrandImage kind (only the favicon may be an ICO)."""
    if not raw:
        raise ImageRefused("The file is empty.")
    if len(raw) > MAX_IMAGE:
        raise ImageRefused(f"The file is larger than {MAX_IMAGE // 1024} KB.")
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        _check_png(raw)
        return PNG
    if raw[:4] == b"\x00\x00\x01\x00":
        if kind != BrandImage.FAVICON:
            raise ImageRefused("A logo must be a PNG or SVG. An ICO file can only be used as the favicon.")
        _check_ico(raw)
        return ICO
    _check_svg(raw)
    return SVG


def _check_png(raw):
    if len(raw) < 45 or raw[12:16] != b"IHDR" or struct.unpack(">I", raw[8:12])[0] != 13:
        raise ImageRefused("That PNG file is damaged.")
    if zlib.crc32(raw[12:29]) != struct.unpack(">I", raw[29:33])[0] or not raw.endswith(b"IEND\xaeB`\x82"):
        raise ImageRefused("That PNG file is damaged.")
    w, h = struct.unpack(">II", raw[16:24])
    if not (0 < w <= MAX_PIXELS and 0 < h <= MAX_PIXELS):
        raise ImageRefused(f"The image must be at most {MAX_PIXELS} by {MAX_PIXELS} pixels.")


def _check_ico(raw):
    count = struct.unpack("<H", raw[4:6])[0]
    if not 1 <= count <= 16 or len(raw) < 6 + 16 * count:
        raise ImageRefused("That ICO file is damaged.")
    for i in range(count):
        size, offset = struct.unpack("<II", raw[6 + 16 * i + 8:6 + 16 * i + 16])
        if size == 0 or offset < 6 + 16 * count or offset + size > len(raw):
            raise ImageRefused("That ICO file is damaged.")


SVG_ELEMENTS = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "defs", "linearGradient", "radialGradient", "stop", "title"}
SVG_ATTRIBUTES = {
    "id", "class", "style", "d", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx", "fy", "width", "height", "points",
    "viewBox", "preserveAspectRatio", "version", "transform", "fill", "fill-opacity", "fill-rule", "clip-rule", "stroke", "stroke-width",
    "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-dasharray", "stroke-dashoffset", "opacity",
    "offset", "stop-color", "stop-opacity", "gradientUnits", "gradientTransform", "spreadMethod", "role", "aria-label", "aria-hidden",
}
_STYLE_OK = re.compile(r"[A-Za-z0-9 \t:;#.,%()\-]*")
_URL_REF = re.compile(r"url\(#[A-Za-z0-9_-]+\)")
_SVG_WHY = "That SVG uses something that is not allowed (scripts, links, text, images, filters or editor extras). Export a plain SVG with shapes and paths only."


def _check_svg(raw):
    stop = ImageRefused(_SVG_WHY)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImageRefused("That file is not a PNG, ICO or SVG image.") from None
    if not text.lstrip().startswith(("<", "<?xml")):
        raise ImageRefused("That file is not a PNG, ICO or SVG image.")
    state = {"depth": 0, "count": 0, "root": False, "title": 0}
    p = expat.ParserCreate(namespace_separator=" ")

    def refuse(*_a):
        raise stop

    def start(name, attrs):
        state["depth"] += 1
        state["count"] += 1
        uri, _, local = name.rpartition(" ")
        if state["depth"] > 20 or state["count"] > 2000 or uri != SVG_NS or local not in SVG_ELEMENTS:
            raise stop
        if not state["root"]:
            if local != "svg":
                raise stop
            state["root"] = True
        elif local == "svg":
            raise stop
        if local == "title":
            state["title"] += 1
        for key, value in attrs.items():
            if key not in SVG_ATTRIBUTES or len(value) > 50_000:
                raise stop
            low = value.lower()
            if key == "style" and (not _STYLE_OK.fullmatch(value) or any(w in low for w in ("url", "image", "expression", "import"))):
                raise stop
            if "url(" in low and not _URL_REF.fullmatch(value.strip()):
                raise stop
            if "javascript" in low or "<" in value:
                raise stop

    def end(name):
        state["depth"] -= 1
        if name.rpartition(" ")[2] == "title":
            state["title"] -= 1

    def text_data(data):
        if data.strip() and not (state["title"] and len(data) <= 200):
            raise stop

    def namespace(prefix, uri):
        if uri != SVG_NS:
            raise stop

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, text_data
    p.StartDoctypeDeclHandler = p.EntityDeclHandler = p.ProcessingInstructionHandler = p.ExternalEntityRefHandler = refuse
    p.StartNamespaceDeclHandler = namespace
    try:
        p.Parse(raw, True)
    except ImageRefused:
        raise
    except expat.ExpatError:
        raise ImageRefused("That SVG file could not be read. It may be damaged.") from None
    if not state["root"]:
        raise stop


def digest(raw):
    return hashlib.sha256(raw).hexdigest()
