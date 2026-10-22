"""Parse DMARC aggregate (rua) reports safely: defusedxml, size caps on decompression."""
import gzip
import io
import zipfile
from datetime import datetime, timezone

from defusedxml import ElementTree as ET

MAX_XML = 10 * 1024 * 1024  # decompressed cap (decompression-bomb guard)


class DmarcError(ValueError):
    pass


def _read_capped(stream):
    data = stream.read(MAX_XML + 1)
    if len(data) > MAX_XML:
        raise DmarcError("report too large after decompression")
    return data


def unpack(raw, filename=""):
    """Return XML bytes from raw/.gz/.zip attachment bytes."""
    if raw[:2] == b"\x1f\x8b":
        return _read_capped(gzip.GzipFile(fileobj=io.BytesIO(raw)))
    if raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = [n for n in z.namelist() if n.lower().endswith(".xml")]
            if len(names) != 1:
                raise DmarcError("zip must contain exactly one xml file")
            if z.getinfo(names[0]).file_size > MAX_XML:
                raise DmarcError("report too large after decompression")
            with z.open(names[0]) as fh:
                return _read_capped(fh)
    if len(raw) > MAX_XML:
        raise DmarcError("report too large")
    return raw


def _t(node, path, default=""):
    el = node.find(path) if node is not None else None
    return (el.text or "").strip() if el is not None and el.text else default


def _dt(ts):
    return datetime.fromtimestamp(int(ts), tz=timezone.utc)


def parse(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as exc:  # defusedxml raises on entity bombs / DTDs too
        raise DmarcError(f"unparseable report: {type(exc).__name__}") from exc
    if root.tag != "feedback":
        raise DmarcError("not a DMARC aggregate report")
    meta, pol = root.find("report_metadata"), root.find("policy_published")
    rows, ok, bad = [], 0, 0
    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        count = int(_t(row, "count", "0") or 0)
        dkim, spf = _t(pe, "dkim"), _t(pe, "spf")
        aligned = dkim == "pass" or spf == "pass"  # DMARC passes if either aligned mechanism passes
        ok, bad = (ok + count, bad) if aligned else (ok, bad + count)
        rows.append({"source_ip": _t(row, "source_ip"), "count": count, "disposition": _t(pe, "disposition"),
                     "dkim": dkim, "spf": spf, "header_from": _t(rec, "identifiers/header_from")})
    try:
        begin, end = _dt(_t(meta, "date_range/begin")), _dt(_t(meta, "date_range/end"))
    except ValueError as exc:
        raise DmarcError("bad date range") from exc
    return {"org_name": _t(meta, "org_name"), "report_id": _t(meta, "report_id"), "domain": _t(pol, "domain").lower(),
            "policy": _t(pol, "p"), "begin": begin, "end": end, "rows": rows, "pass_count": ok, "fail_count": bad}
