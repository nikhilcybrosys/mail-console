# Third-party notices

Everything below is vendored under `static/` and served from this app. Nothing is loaded from a CDN at runtime.

| Component | Version | License | Path |
|---|---|---|---|
| Geist and Geist Mono fonts | as shipped by Vercel | SIL Open Font License 1.1 | `static/fonts/` (`OFL.txt`) |
| uPlot | 1.6.31 | MIT | `static/vendor/uplot/` |
| htmx | 2.0.4 | BSD Zero Clause | `static/vendor/htmx/` |
| Lucide icons (subset sprite) | 1.61.0 | ISC | `static/icons/` (`LICENSE`) |

SHA-256 prefixes of the pinned vendor files (re-check on upgrade):
`uPlot.iife.min.js` and `htmx.min.js` are recorded in `static/vendor/CHECKSUMS.txt`.

## Python dependencies (installed from PyPI, not vendored)

| Package | Version at time of writing | Licence |
|---|---|---|
| Django | 5.2.x | BSD-3-Clause |
| psycopg (and psycopg-binary) | 3.3.x | LGPL-3.0-only (used unmodified as a dependency; the binary wheel bundles libpq under the PostgreSQL licence) |
| boto3 | 1.43.x | Apache-2.0 |
| nh3 | 0.3.x | MIT |
| dnspython | 2.9.x | ISC |
| Authlib | 1.9.x | BSD-3-Clause |
| python-fido2 | 2.2.x | BSD-2-Clause / Apache-2.0 / MPL-2.0 (multi-licensed) |
| WhiteNoise | 6.12.x | MIT |
| Gunicorn | 26.2.x | MIT |
| requests | 2.34.x | Apache-2.0 |
| defusedxml | 0.7.x | Python Software Foundation License |

Development only: pytest, pytest-django, moto (Apache-2.0), httpx (BSD-3-Clause). Re-check licences when upgrading
a dependency.

## Brand assets

`static/brand/mark.svg` and `mark-white.svg` are an original placeholder mark released under the same licence as
the code (Apache-2.0). Replace the name, logo and accent colour with your own in *Settings > Appearance*, or with `MC_BRAND_NAME`,
`MC_BRAND_LOGO`, `MC_BRAND_LOGO_DARK` and `MC_BRAND_ACCENT` (see `config/settings.py`).
