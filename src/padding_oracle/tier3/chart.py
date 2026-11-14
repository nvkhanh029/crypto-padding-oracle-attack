"""Minimal dependency-free PDF line chart for the Tier 3 experiments."""

from __future__ import annotations

import math
from pathlib import Path


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _text(x: float, y: float, size: float, text: str) -> str:
    return (
        f"BT /F1 {size:.1f} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm "
        f"({_escape(text)}) Tj ET"
    )


def _log_tick_label(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:g}M"
    if value >= 1_000:
        return f"{value / 1_000:g}k"
    return f"{value:g}"


def _build_pdf(series: list[dict], title: str, xlabel: str, ylabel: str) -> bytes:
    page_w, page_h = 500.0, 340.0
    left, bottom = 62.0, 52.0
    width, height = 400.0, 235.0

    xs = [point[0] for item in series for point in item["points"]]
    if not xs:
        raise ValueError("a chart needs at least one point")
    x_min, x_max = min(xs), max(xs)
    if x_min <= 0:
        raise ValueError("the x axis is logarithmic; all points must be positive")
    if x_min == x_max:
        x_min *= 0.9
        x_max *= 1.1
    log_min = math.log10(x_min * 0.9)
    log_max = math.log10(x_max * 1.1)
    if log_max <= log_min:
        log_max = log_min + 1.0

    def x_pos(value: float) -> float:
        return left + (math.log10(value) - log_min) / (log_max - log_min) * width

    def y_pos(value: float) -> float:
        return bottom + value * height

    commands: list[str] = []
    commands.append("0.85 w")
    commands.append(f"0 g {left:.2f} {bottom:.2f} {width:.2f} {height:.2f} re S")
    commands.append("0.8 g")

    # Horizontal grid lines and percentage labels.
    for i in range(6):
        value = i / 5.0
        y = y_pos(value)
        commands.append(f"{left:.2f} {y:.2f} m {left + width:.2f} {y:.2f} l S")
        commands.append(_text(left - 12.0, y - 3.0, 8.0, f"{value * 100:.0f}%"))
    commands.append(f"0 g {left:.2f} {bottom:.2f} m {left + width:.2f} {bottom:.2f} l S")

    # Log ticks at powers of ten.
    first = math.floor(log_min)
    last = math.ceil(log_max)
    for exponent in range(first, last + 1):
        value = 10.0 ** exponent
        if not (10.0 ** log_min <= value <= 10.0 ** log_max):
            continue
        x = x_pos(value)
        commands.append(f"{x:.2f} {bottom:.2f} m {x:.2f} {bottom - 4:.2f} l S")
        commands.append(_text(x - 8.0, bottom - 16.0, 8.0, _log_tick_label(value)))

    commands.append(_text(left, bottom - 32.0, 8.0, xlabel))
    commands.append(_text(left, bottom + height + 24.0, 9.0, title))
    commands.append(_text(left, bottom + height + 12.0, 8.0, ylabel))

    dash_styles = [None, (4.0, 2.0), (1.0, 2.0), (6.0, 2.0, 1.0, 2.0)]
    marker_sizes = [3.0, 3.0, 3.0, 3.0]
    legend_y = bottom + height - 14.0

    for index, item in enumerate(series):
        points = sorted(item["points"], key=lambda point: point[0])
        if not points:
            continue
        dash = dash_styles[index % len(dash_styles)]
        if dash is None:
            commands.append("[] 0 d")
        else:
            commands.append("[" + " ".join(f"{v:.1f}" for v in dash) + "] 0 d")
        commands.append("0.9 w 0 g")
        path = " ".join(
            f"{x_pos(point[0]):.2f} {y_pos(point[1]):.2f} "
            f"{'m' if position == 0 else 'l'}"
            for position, point in enumerate(points)
        )
        if len(points) >= 2:
            commands.append(path + " S")
        size = marker_sizes[index % len(marker_sizes)]
        for point in points:
            x, y = x_pos(point[0]), y_pos(point[1])
            commands.append(
                f"{x - size / 2:.2f} {y - size / 2:.2f} {size:.2f} {size:.2f} re f"
            )

        # Legend sample and label.
        lx = left + width - 145.0
        ly = legend_y - index * 13.0
        commands.append("0.9 w 0 g")
        if dash is not None:
            commands.append("[" + " ".join(f"{v:.1f}" for v in dash) + "] 0 d")
        commands.append(f"{lx:.2f} {ly:.2f} m {lx + 22:.2f} {ly:.2f} l S")
        commands.append("[] 0 d")
        commands.append(f"{lx + 27:.2f} {ly - 3.0:.2f} 8.0 8.0 re f")
        commands.append(_text(lx + 38.0, ly - 3.0, 8.0, item["label"]))

    commands.append("[] 0 d")
    stream = "\n".join(commands).encode("latin-1")

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
        + f"{page_w:.0f} {page_h:.0f}".encode("ascii")
        + b"] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    objects.append(
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream
        + b"\nendstream"
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(body)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


def write_line_chart_pdf(
    path: Path,
    series: list[dict],
    title: str,
    xlabel: str,
    ylabel: str = "Word success rate",
) -> None:
    """Write one log-x line chart as a dependency-free PDF.

    `series` is a list of {"label": str, "points": [(x, y), ...]}.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_build_pdf(series, title, xlabel, ylabel))
