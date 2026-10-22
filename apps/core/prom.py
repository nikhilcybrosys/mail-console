"""A small Prometheus text-format (0.0.4) writer, so the console needs no extra dependency for /metrics.

Only what the console uses: gauges and counters with labels. Names and label names are validated (a bad one is a
programming error and raises), label values are escaped, and non-finite numbers use the spellings Prometheus expects.
"""
import math
import re

_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class Family:
    def __init__(self, name, help_text, kind="gauge"):
        if not _NAME.match(name):
            raise ValueError(f"bad metric name {name!r}")
        if kind not in ("gauge", "counter"):
            raise ValueError(f"unsupported metric type {kind!r}")
        self.name, self.help, self.kind, self.samples = name, help_text, kind, []

    def add(self, value, **labels):
        for k in labels:
            if not _LABEL.match(k) or k.startswith("__"):
                raise ValueError(f"bad label name {k!r}")
        self.samples.append((labels, value))
        return self


def _label_value(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _help(text):
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def number(v):
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "+Inf" if v > 0 else "-Inf"
        return repr(v)
    return str(int(v))


def render(families):
    """The exposition document. A family with no samples is left out entirely (an empty # TYPE line is noise)."""
    out = []
    for fam in families:
        if not fam.samples:
            continue
        out.append(f"# HELP {fam.name} {_help(fam.help)}")
        out.append(f"# TYPE {fam.name} {fam.kind}")
        for labels, value in fam.samples:
            lbl = ",".join(f'{k}="{_label_value(v)}"' for k, v in sorted(labels.items()))
            out.append(f"{fam.name}{{{lbl}}} {number(value)}" if lbl else f"{fam.name} {number(value)}")
    return "\n".join(out) + "\n"
