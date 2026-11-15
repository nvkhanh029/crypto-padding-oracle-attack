"""Matplotlib line chart for the Tier 3 experiments."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


_STYLES = {
    "Trigram prior": {"marker": "o", "linestyle": "-"},
    "NCC uniform": {"marker": "s", "linestyle": "--"},
    "Sequential Halving": {"marker": "^", "linestyle": "-."},
}
_FALLBACK_MARKERS = ["o", "s", "^", "D", "v"]
_FALLBACK_LINESTYLES = ["-", "--", "-.", ":"]


def write_line_chart_pdf(
    path: Path,
    series: list[dict],
    title: str,
    xlabel: str,
    ylabel: str = "Word success rate",
) -> None:
    """Write one log-x line chart as PDF.

    `series` is a list of {"label": str, "points": [(x, y), ...]} where x is
    the measured mean queries per word and y is the success rate.
    """
    cleaned = []
    for item in series:
        points = sorted(item["points"], key=lambda point: point[0])
        if points:
            cleaned.append({"label": item["label"], "points": points})
    if not cleaned:
        raise ValueError("a chart needs at least one point")
    for item in cleaned:
        for x, _y in item["points"]:
            if x <= 0:
                raise ValueError("the x axis is logarithmic; all points must be positive")

    figure, axis = plt.subplots(figsize=(6.5, 3.5))
    for index, item in enumerate(cleaned):
        style = _STYLES.get(item["label"])
        if style is None:
            style = {
                "marker": _FALLBACK_MARKERS[index % len(_FALLBACK_MARKERS)],
                "linestyle": _FALLBACK_LINESTYLES[index % len(_FALLBACK_LINESTYLES)],
            }
        xs = [point[0] for point in item["points"]]
        ys = [point[1] for point in item["points"]]
        axis.plot(
            xs,
            ys,
            label=item["label"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            markersize=5,
            linewidth=1.5,
        )

    axis.set_xscale("log")
    axis.set_xlabel(xlabel, fontsize=9)
    axis.set_ylabel(ylabel, fontsize=9)
    axis.set_title(title, fontsize=10)
    axis.tick_params(labelsize=9)
    axis.set_ylim(-0.05, 1.05)
    axis.grid(True, which="both", alpha=0.3)
    axis.legend(fontsize=9, loc="best")

    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, format="pdf")
    plt.close(figure)
