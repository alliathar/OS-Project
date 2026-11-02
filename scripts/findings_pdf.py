#!/usr/bin/env python3
"""
findings_pdf.py -- build results/findings.pdf, an interim findings report with
charts, entirely from what the other scripts generated under results/:

    attack_matrix.csv, perf.csv, memory.csv, environment.txt, logs/*.log

Every number and every quoted allocator message in the PDF is read from those
files. The hand-written parts are the explanations around them, and an
explanation that only holds for a particular result is printed only when the
data shows that result -- so re-running the experiments can't leave a stale
claim behind.

Also writes the figures it embeds to results/figures/.

Run it through ./scripts/make_pdf.sh, which uses the venv from setup.sh
(reportlab is not in Ubuntu's system Python).
"""

import os
import re
import signal
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402  (shared CSV loading)

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Patch  # noqa: E402
from matplotlib.ticker import FuncFormatter, MultipleLocator  # noqa: E402

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_RIGHT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.lib.utils import ImageReader  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (CondPageBreak, Image, KeepTogether,  # noqa: E402
                                Paragraph, Preformatted, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

RESULTS = report.RESULTS
LOGS = os.path.join(RESULTS, "logs")
FIGS = os.path.join(RESULTS, "figures")
OUT = os.path.join(RESULTS, "findings.pdf")

# ---- look -------------------------------------------------------------------
# Each allocator keeps one color in every chart (validated categorical slots
# 1-3, safe for colorblind readers in any pairing). Outcomes use the reserved
# status colors and always carry a text label too.
ALLOCATORS = ["glibc", "scudo", "hardened"]
LABEL = {"glibc": "glibc malloc", "scudo": "Scudo", "hardened": "hardened_malloc"}
COLOR = {"glibc": "#2a78d6", "scudo": "#eb6834", "hardened": "#1baf7a"}
STATUS = {"stopped": "#0ca30c", "succeeded": "#d03b3b", "inconclusive": "#898781"}
VERB = {"stopped": "Stopped", "succeeded": "Missed", "inconclusive": "Inconclusive"}
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#ffffff"
FIG_W = 6.7  # inches; the text frame on A4 with 2 cm margins

# ---- what the programs are (descriptions, not results) ----------------------
DEFENSES = {
    "glibc": "The Linux default and the baseline here. Some integrity checks "
             "inside free(), such as tcache double-free detection and "
             "safe-linking.",
    "scudo": "LLVM's hardened allocator, the default on Android. Checksummed "
             "chunk headers, randomized placement, and an optional quarantine "
             "that delays reuse of freed memory.",
    "hardened": "GrapheneOS's allocator. Metadata kept apart from user data, "
                "guard regions, a canary at the end of each slot, zero-on-free, "
                "and randomized slot reuse.",
}
ATTACKS = {
    "double_free": ("Double free", "Frees the same block twice."),
    "invalid_free": ("Invalid free",
                     "Calls free() on a stack address that malloc never returned."),
    "heap_overflow": ("Heap overflow",
                      "Writes far past the end of a block, then frees it."),
    "metadata_overwrite": ("Metadata overwrite",
                           "Overflows block a toward a second block b, where an "
                           "allocator with inline metadata keeps b's header, then "
                           "frees b and a."),
    "uninitialized_read": ("Uninitialized read",
                           "Writes a secret into a block, frees it, allocates the "
                           "same size again and looks for the secret."),
    "use_after_free": ("Use after free",
                       "Reads and writes a block through its pointer after "
                       "freeing it."),
}
META_A_SIZE = 32  # malloc(32) for block a in src/attacks/metadata_overwrite.c

ADDR = re.compile(r"0x[0-9a-fA-F]+")


# ---- small helpers ----------------------------------------------------------
def join_and(items):
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def code(s):
    return f'<font name="Mono">{escape(s)}</font>'


def ops(v):
    return f"{v / 1e6:.1f}M"


def sig_name(num):
    try:
        return signal.Signals(int(num)).name
    except (ValueError, TypeError):
        return f"signal {num}"


def read_log(attack, alloc, run):
    path = os.path.join(LOGS, f"{attack}.{alloc}.{run}.log")
    if not os.path.exists(path):
        return []
    with open(path, errors="replace") as f:
        return [ln.rstrip("\n") for ln in f]


def allocator_message(lines):
    """First line the allocator itself printed (not our markers), addresses masked."""
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith(("[", "ATTACK SUCCEEDED", "timeout:")):
            return ADDR.sub("0x…", s)
    return ""


def last_step(lines):
    steps = [ln[len("[step] "):] for ln in lines if ln.startswith("[step] ")]
    return ADDR.sub("0x…", steps[-1]) if steps else ""


def load_environment():
    env = {}
    path = os.path.join(RESULTS, "environment.txt")
    if os.path.exists(path):
        with open(path) as f:
            for ln in f:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    env[k.strip()] = v.strip()
    return env


# ---- data -------------------------------------------------------------------
def load_cells():
    rows = report.load_csv("attack_matrix.csv")
    if not rows:
        sys.exit("results/attack_matrix.csv missing -- run ./scripts/run_all.sh first")
    cells = defaultdict(list)
    for r in rows:
        cells[(r["attack"], r["allocator"])].append(r)
    allocs = [a for a in ALLOCATORS if any(k[1] == a for k in cells)]
    attacks = sorted({k[0] for k in cells})
    return rows, cells, allocs, attacks


def summarize_cell(rows):
    outcomes = Counter(r["outcome"] for r in rows)
    verdict = outcomes.most_common(1)[0][0]
    signals = Counter(r["signal"] for r in rows if r["signal"])
    exit_codes = Counter(r["exit_code"] for r in rows if r["exit_code"] not in ("", "0"))
    messages, steps = Counter(), Counter()
    for r in rows:
        lines = read_log(r["attack"], r["allocator"], r["run"])
        msg = allocator_message(lines)
        if msg:
            messages[msg] += 1
        if r["outcome"] == "stopped":
            steps[last_step(lines)] += 1
    return {
        "verdict": verdict,
        "k": outcomes[verdict],
        "n": len(rows),
        "unanimous": len(outcomes) == 1,
        "signal": sig_name(signals.most_common(1)[0][0]) if signals else "",
        "exit_code": exit_codes.most_common(1)[0][0] if exit_codes else "",
        "message": messages.most_common(1)[0][0] if messages else "",
        "step": steps.most_common(1)[0][0] if steps else "",
    }


def log_texts(cells, attack, alloc):
    return ["\n".join(read_log(attack, alloc, r["run"])) for r in cells.get((attack, alloc), [])]


def metadata_facts(cells, allocs):
    """Where block b landed relative to a, and whether the overflow could reach it."""
    out = {}
    for alloc in allocs:
        deltas, overflow = [], 0
        for text in log_texts(cells, "metadata_overwrite", alloc):
            m = re.search(r"delta (-?\d+) bytes", text)
            o = re.search(r"overflowing chunk a by (\d+) bytes", text)
            if m:
                deltas.append(int(m.group(1)))
            if o:
                overflow = int(o.group(1))
        reach = META_A_SIZE + overflow
        out[alloc] = {"deltas": deltas, "reach": reach, "overflow": overflow,
                      "in_reach": sum(1 for d in deltas if 0 < d <= reach)}
    return out


def overflow_sizes(cells, allocs):
    for alloc in allocs:
        for text in log_texts(cells, "heap_overflow", alloc):
            a = re.search(r"allocated (\d+) bytes", text)
            w = re.search(r"writing (\d+) bytes", text)
            if a and w:
                return int(a.group(1)), int(w.group(1))
    return None


def uninit_facts(cells, allocs):
    out = {}
    for alloc in allocs:
        same = total = 0
        for text in log_texts(cells, "uninitialized_read", alloc):
            a = re.search(r"first block at (0x[0-9a-fA-F]+)", text)
            b = re.search(r"re-allocated \d+ bytes at (0x[0-9a-fA-F]+)", text)
            if a and b:
                total += 1
                same += a.group(1) == b.group(1)
        leaked = sum(1 for r in cells.get(("uninitialized_read", alloc), [])
                     if r["outcome"] == "succeeded")
        out[alloc] = {"same": same, "total": total, "leaked": leaked}
    return out


def uaf_facts(cells, allocs):
    out = {}
    for alloc in allocs:
        before, after, wrote_ok = set(), [], 0
        for text in log_texts(cells, "use_after_free", alloc):
            b = re.search(r"before free: data\[2\] = (-?\d+)", text)
            a = re.search(r"^\[step\] read back: (-?\d+)$", text, re.M)
            if b:
                before.add(int(b.group(1)))
            if a:
                after.append(int(a.group(1)))
            if re.search(r"wrote 999, read back: 999", text):
                wrote_ok += 1
        orig = next(iter(before)) if len(before) == 1 else None
        if after and orig is not None and all(v == orig for v in after):
            kind = "unchanged"
        elif after and all(v == 0 for v in after):
            kind = "zeroed"
        elif after:
            kind = "overwritten"
        else:
            kind = "unknown"
        out[alloc] = {"orig": orig, "after": after, "kind": kind, "wrote_ok": wrote_ok}
    return out


def perf_stats():
    rows = report.load_csv("perf.csv") or []
    agg, iters = defaultdict(list), set()
    for r in rows:
        try:
            agg[(r["allocator"], r["threads"])].append(float(r["ops_per_sec"]))
            iters.add(r["iters"])
        except (ValueError, KeyError):
            pass
    return agg, iters


def memory_stats():
    rows = report.load_csv("memory.csv") or []
    agg, meta = defaultdict(list), {}
    for r in rows:
        try:
            agg[r["allocator"]].append(float(r["peak_rss_kib"]))
            meta = {"blocks": int(r["blocks"]), "bytes": int(r["block_bytes"]),
                    "req_kib": float(r["requested_kib"])}
        except (ValueError, KeyError):
            pass
    return agg, meta


# ---- figures ----------------------------------------------------------------
def setup_matplotlib():
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9,
        "text.color": INK, "axes.labelcolor": INK2,
        "xtick.color": INK2, "ytick.color": INK2,
        "axes.edgecolor": AXIS, "axes.linewidth": 0.8,
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    })


def quiet_axes(ax, grid="y"):
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(length=0)
    if grid:
        ax.grid(axis=grid, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def top_legend(ax, handles=None):
    ax.legend(handles=handles, loc="lower left", bbox_to_anchor=(0, 1.02), ncol=3,
              frameon=False, fontsize=8.5, handlelength=1.0, handleheight=1.0,
              borderaxespad=0, columnspacing=1.6)


# A surface-colored backing so gridlines never cut through a text label.
LABEL_BOX = dict(facecolor=SURFACE, edgecolor="none", pad=1.2)


def save(fig, name):
    os.makedirs(FIGS, exist_ok=True)
    path = os.path.join(FIGS, name)
    fig.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)
    return path


def fig_matrix(order, summ, allocs):
    n_rows, n_cols = len(order), len(allocs)
    left, right, top, bottom = 0.24, 0.995, 0.86, 0.13
    fig_h = 0.5 * n_rows + 0.9
    fig = plt.figure(figsize=(FIG_W, fig_h))
    ax = fig.add_axes([left, bottom, right - left, top - bottom])
    ax.set_xlim(0, n_cols)
    ax.set_ylim(n_rows, 0)
    ax.axis("off")

    # Rounded corners in data units: correct for the cell aspect so they are circular.
    ax_w, ax_h = FIG_W * (right - left), fig_h * (top - bottom)
    x_per_in, y_per_in = n_cols / ax_w, n_rows / ax_h
    gap_in, radius_in = 0.025, 0.04
    gx, gy = gap_in * x_per_in / 2, gap_in * y_per_in / 2

    seen = set()
    for i, attack in enumerate(order):
        ax.text(-0.04, i + 0.5, attack, ha="right", va="center", fontsize=9,
                family="DejaVu Sans Mono", color=INK)
        for j, alloc in enumerate(allocs):
            s = summ.get((attack, alloc))
            if not s:
                continue
            seen.add(s["verdict"])
            ax.add_patch(FancyBboxPatch(
                (j + gx, i + gy), 1 - 2 * gx, 1 - 2 * gy,
                boxstyle=f"round,pad=0,rounding_size={radius_in * x_per_in}",
                mutation_aspect=y_per_in / x_per_in,
                facecolor=STATUS[s["verdict"]], edgecolor="none"))
            ax.text(j + 0.5, i + 0.5, f"{VERB[s['verdict']]}  {s['k']}/{s['n']}",
                    ha="center", va="center", fontsize=9, fontweight="bold",
                    color="#ffffff")
    for j, alloc in enumerate(allocs):
        ax.text(j + 0.5, -0.15, LABEL[alloc], ha="center", va="bottom",
                fontsize=9.5, fontweight="bold", color=INK)

    legend_text = {"stopped": "Stopped: the allocator aborted the program",
                   "succeeded": "Missed: the bug ran to completion",
                   "inconclusive": "Inconclusive: timed out or allocator not loaded"}
    handles = [Patch(facecolor=STATUS[v], label=legend_text[v])
               for v in ("stopped", "succeeded", "inconclusive") if v in seen]
    fig.legend(handles=handles, loc="lower left", bbox_to_anchor=(left, 0.0),
               ncol=len(handles), frameon=False, fontsize=8.5, handlelength=1.0,
               handleheight=1.0, columnspacing=1.6)
    return save(fig, "fig_attack_matrix.png")


def fig_throughput(agg, allocs):
    threads = sorted({t for (_a, t) in agg}, key=int)
    fig, ax = plt.subplots(figsize=(FIG_W, 2.9))
    width, step = 0.08, 0.15  # step leaves room for each bar's value label
    ymax = max(statistics.mean(v) + (statistics.stdev(v) if len(v) > 1 else 0)
               for v in agg.values())
    for j, alloc in enumerate(allocs):
        xs, means, sds = [], [], []
        for i, t in enumerate(threads):
            vals = agg.get((alloc, t))
            if not vals:
                continue
            xs.append(i + (j - (len(allocs) - 1) / 2) * step)
            means.append(statistics.mean(vals))
            sds.append(statistics.stdev(vals) if len(vals) > 1 else 0.0)
        ax.bar(xs, means, width, color=COLOR[alloc], label=LABEL[alloc], zorder=2)
        ax.errorbar(xs, means, yerr=sds, fmt="none", ecolor=INK2, elinewidth=0.9,
                    capsize=2.5, zorder=3)
        for x, m, sd in zip(xs, means, sds):
            ax.text(x, m + sd + ymax * 0.02, ops(m), ha="center", va="bottom",
                    fontsize=8, color=INK)
    ax.set_xticks(range(len(threads)))
    ax.set_xticklabels([f"{t} thread" + ("" if t == "1" else "s") for t in threads])
    ax.set_xlim(-0.45, len(threads) - 0.55)
    ax.set_ylim(0, ymax * 1.15)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v / 1e6:.0f}M"))
    ax.set_ylabel("malloc + free operations per second")
    quiet_axes(ax, "y")
    top_legend(ax)
    return save(fig, "fig_throughput.png")


def fig_memory(agg, meta, allocs):
    req_mib = meta["req_kib"] / 1024
    present = [a for a in allocs if a in agg]
    means = {a: statistics.mean(agg[a]) / 1024 for a in present}
    fig, ax = plt.subplots(figsize=(FIG_W, 0.42 * len(present) + 0.9))
    xmax = max(means.values())
    for y, alloc in enumerate(present):
        ax.barh(y, means[alloc], height=0.42, color=COLOR[alloc], zorder=2)
        ax.text(means[alloc] + xmax * 0.012, y,
                f"{means[alloc]:.1f} MiB  ({means[alloc] / req_mib:.2f}× requested)",
                va="center", fontsize=8, color=INK, bbox=LABEL_BOX, zorder=4)
    ax.axvline(req_mib, color=INK2, linewidth=1, zorder=3)
    ax.text(req_mib + xmax * 0.01, -0.55, f"requested: {req_mib:.1f} MiB", ha="left",
            va="center", fontsize=8, color=INK2, bbox=LABEL_BOX, zorder=4)
    ax.set_yticks(range(len(present)))
    ax.set_yticklabels([LABEL[a] for a in present])
    ax.set_ylim(len(present) - 0.5, -0.75)
    ax.set_xlim(0, xmax * 1.42)
    ax.set_xlabel("peak resident memory (MiB)")
    quiet_axes(ax, "x")
    ax.spines["left"].set_visible(False)
    return save(fig, "fig_memory.png")


def fig_tradeoff(points, n_attacks):
    """points: alloc -> (single-thread ops/s, attacks stopped)."""
    fig, ax = plt.subplots(figsize=(FIG_W, 2.8))
    xmax = max(x for x, _ in points.values())
    for alloc, (x, y) in points.items():
        ax.scatter([x], [y], s=75, color=COLOR[alloc], edgecolors=SURFACE,
                   linewidths=2, zorder=3, label=LABEL[alloc])
        flip = x > xmax * 0.7  # keep labels near the right edge inside the plot
        ax.annotate(f"{LABEL[alloc]}: {y} of {n_attacks} stopped, {ops(x)} ops/s",
                    (x, y), xytext=(-9 if flip else 9, 0), textcoords="offset points",
                    ha="right" if flip else "left", va="center", fontsize=8.5,
                    color=INK, bbox=LABEL_BOX, zorder=4)
    ax.set_xlim(0, xmax * 1.12)
    ax.set_ylim(-0.4, n_attacks + 0.4)
    ax.yaxis.set_major_locator(MultipleLocator(1))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v / 1e6:.0f}M"))
    ax.set_xlabel("single-thread throughput (malloc + free per second; further right is faster)")
    ax.set_ylabel(f"attacks stopped (of {n_attacks})")
    quiet_axes(ax, "both")
    top_legend(ax)
    return save(fig, "fig_tradeoff.png")


# ---- PDF building blocks ----------------------------------------------------
def register_fonts():
    fp = font_manager.FontProperties
    faces = {
        "Sans": fp(family="DejaVu Sans"),
        "Sans-Bold": fp(family="DejaVu Sans", weight="bold"),
        "Sans-Italic": fp(family="DejaVu Sans", style="italic"),
        "Mono": fp(family="DejaVu Sans Mono"),
    }
    for name, prop in faces.items():
        pdfmetrics.registerFont(TTFont(name, font_manager.findfont(prop)))
    pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold",
                                  italic="Sans-Italic", boldItalic="Sans-Bold")


def make_styles():
    ink, ink2 = colors.HexColor(INK), colors.HexColor(INK2)
    body = ParagraphStyle("body", fontName="Sans", fontSize=9.5, leading=13.8,
                          textColor=ink, spaceAfter=6)
    s = {
        "title": ParagraphStyle("title", parent=body, fontName="Sans-Bold",
                                fontSize=19, leading=23, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", parent=body, fontSize=11.5,
                                   leading=15, textColor=ink2, spaceAfter=8),
        "meta": ParagraphStyle("meta", parent=body, fontSize=8.5, leading=12,
                               textColor=ink2, spaceAfter=12),
        "h1": ParagraphStyle("h1", parent=body, fontName="Sans-Bold", fontSize=13.5,
                             leading=17, spaceBefore=12, spaceAfter=6, keepWithNext=1),
        "h2": ParagraphStyle("h2", parent=body, fontName="Sans-Bold", fontSize=10.5,
                             leading=14, spaceBefore=8, spaceAfter=4, keepWithNext=1),
        "lead": ParagraphStyle("lead", parent=body, keepWithNext=1),
        "body": body,
        "bullet": ParagraphStyle("bullet", parent=body, leftIndent=12,
                                 bulletIndent=2, spaceAfter=3),
        "callout": ParagraphStyle("callout", parent=body, backColor=colors.HexColor("#f3f2ee"),
                                  borderPadding=(8, 10, 8, 10), leftIndent=10,
                                  rightIndent=10, spaceBefore=6, spaceAfter=14),
        "caption": ParagraphStyle("caption", parent=body, fontSize=8.2, leading=11,
                                  textColor=ink2, spaceBefore=3, spaceAfter=10),
        "cell": ParagraphStyle("cell", parent=body, fontSize=8, leading=10.5, spaceAfter=0),
        "cellb": ParagraphStyle("cellb", parent=body, fontName="Sans-Bold", fontSize=8,
                                leading=10.5, spaceAfter=0),
        "mono": ParagraphStyle("mono", parent=body, fontName="Mono", fontSize=8,
                               leading=11, backColor=colors.HexColor("#f3f2ee"),
                               borderPadding=(6, 8, 6, 8), leftIndent=8, rightIndent=8,
                               spaceBefore=4, spaceAfter=10),
    }
    s["cellr"] = ParagraphStyle("cellr", parent=s["cell"], alignment=TA_RIGHT)
    s["cellbr"] = ParagraphStyle("cellbr", parent=s["cellb"], alignment=TA_RIGHT)
    return s


class Doc:
    """Collects flowables and numbers figures/tables in order of appearance."""

    def __init__(self, styles):
        self.s = styles
        self.story = []
        self.pending = []  # headings waiting to be glued to the block after them
        self.figs = 0
        self.tabs = 0
        self.frame_w = A4[0] - 4 * cm

    def add(self, *flowables, keep=False):
        """Append flowables. Pending headings join them, and the group is kept on
        one page when it holds a heading or keep=True. Groups are never nested:
        reportlab mis-measures a KeepTogether inside another one and breaks pages
        early."""
        group = self.pending + list(flowables)
        heading = bool(self.pending)
        self.pending = []
        if keep or heading:
            self.story.append(KeepTogether(group))
        else:
            self.story.extend(group)

    def add_long(self, *flowables):
        """Like add(), for blocks too tall to keep whole: headings stay with the
        start of the block by requiring some free space before it."""
        if self.pending:
            self.story.append(CondPageBreak(5 * cm))
            self.story.extend(self.pending)
            self.pending = []
        self.story.extend(flowables)

    def p(self, text, style="body"):
        para = Paragraph(text, self.s[style])
        if style in ("h1", "h2", "lead"):
            self.pending.append(para)
        else:
            self.add(para)

    def bullets(self, items):
        for it in items:
            self.add(Paragraph(it, self.s["bullet"], bulletText="•"))
        self.add(Spacer(1, 4))

    def h1(self, text):
        self.p(text, "h1")

    def h2(self, text):
        self.p(text, "h2")

    def figure(self, path, caption):
        self.figs += 1
        iw, ih = ImageReader(path).getSize()
        img = Image(path, width=self.frame_w, height=self.frame_w * ih / iw)
        cap = Paragraph(f"<b>Figure {self.figs}.</b> {caption}", self.s["caption"])
        self.add(img, cap, keep=True)

    def table(self, header, rows, widths, caption=None, right=()):
        s = self.s
        data = [[Paragraph(h, s["cellbr"] if i in right else s["cellb"])
                 for i, h in enumerate(header)]]
        for row in rows:
            data.append([Paragraph(str(c), s["cellr"] if i in right else s["cell"])
                         for i, c in enumerate(row)])
        t = Table(data, colWidths=[w * self.frame_w for w in widths], repeatRows=1,
                  hAlign="LEFT")
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.HexColor(AXIS)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(GRID)),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        block = [t]
        if caption:
            self.tabs += 1
            block.append(Paragraph(f"<b>Table {self.tabs}.</b> {caption}", s["caption"]))
        else:
            block.append(Spacer(1, 10))
        # Short tables stay in one piece; long ones may split across pages
        # (the header row repeats) rather than leave half a page empty.
        if len(rows) <= 8:
            self.add(*block, keep=True)
        else:
            self.add_long(*block)


def chip(verdict, k, n):
    return f'<font color="{STATUS[verdict]}">■</font> {VERB[verdict]} {k}/{n}'


# ---- the report -------------------------------------------------------------
def build():
    setup_matplotlib()
    register_fonts()
    styles = make_styles()
    d = Doc(styles)

    rows, cells, allocs, attacks = load_cells()
    env = load_environment()
    summ = {key: summarize_cell(r) for key, r in cells.items()}
    n_attacks = len(attacks)
    runs_per_cell = max(len(r) for r in cells.values())
    stopped = {a: [x for x in attacks if summ.get((x, a), {}).get("verdict") == "stopped"]
               for a in allocs}
    # Most-stopped attacks first, so the matrix reads from "everyone catches it"
    # down to "nobody does".
    order = sorted(attacks, key=lambda x: (-sum(summ.get((x, a), {}).get("verdict") == "stopped"
                                                for a in allocs), x))
    perf, perf_iters = perf_stats()
    mem, mem_meta = memory_stats()
    meta = metadata_facts(cells, allocs)
    uninit = uninit_facts(cells, allocs)
    uaf = uaf_facts(cells, allocs)

    def single_thread(a):
        v = perf.get((a, "1"))
        return statistics.mean(v) if v else None

    # figures first (they are files the PDF embeds)
    f_matrix = fig_matrix(order, summ, allocs)
    f_tradeoff = None
    if all(single_thread(a) for a in allocs):
        f_tradeoff = fig_tradeoff({a: (single_thread(a), len(stopped[a])) for a in allocs},
                                  n_attacks)
    f_perf = fig_throughput(perf, allocs) if perf else None
    f_mem = fig_memory(mem, mem_meta, allocs) if mem else None

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_date = env.get("date_utc", "unknown date")[:10]

    # -- title ---------------------------------------------------------------
    d.p("Heap Allocator Security: Interim Findings", "title")
    d.p("How glibc malloc, Scudo and hardened_malloc handled six heap bugs, "
        "and what their protection costs", "subtitle")
    d.p(f"Muhammad Ali Athar (10569), Aleena Abbasi, Shaheer Qureshi · "
        f"Operating Systems final project, Habib "
        f"University, Fall 2026<br/>Interim report: baseline results only; the bypass "
        f"variants are still to come. Experiments run {run_date} on "
        f"{escape(env.get('os', 'Linux'))}; this PDF was generated {generated} from the "
        f"files in {code('results/')}.", "meta")
    d.p("<b>Research question.</b> When common heap bugs like double free and "
        "use-after-free are used to attack the standard malloc and two "
        "security-enhanced versions of it, which attacks does each one stop, which "
        "still get through, and what does the extra safety cost?", "callout")

    # -- at a glance ---------------------------------------------------------
    d.h1("Results at a glance")
    base1 = single_thread("glibc")
    glance = []
    for a in allocs:
        cols = [f"<b>{LABEL[a]}</b>", f"{len(stopped[a])} of {n_attacks}"]
        for t in ("1", "4"):
            v = perf.get((a, t))
            b = perf.get(("glibc", t))
            if v and b:
                m, mb = statistics.mean(v), statistics.mean(b)
                rel = "baseline" if a == "glibc" else f"{mb / m:.1f}× slower"
                cols.append(f"{ops(m)} ({rel})")
            else:
                cols.append("n/a")
        if a in mem and mem_meta:
            pk = statistics.mean(mem[a])
            cols.append(f"{pk / 1024:.1f} MiB ({pk / mem_meta['req_kib']:.2f}× requested)")
        else:
            cols.append("n/a")
        glance.append(cols)
    d.table(["Allocator", "Attacks stopped", "Speed, 1 thread (ops/s)",
             "Speed, 4 threads (ops/s)", "Peak memory"], glance,
            [0.19, 0.13, 0.22, 0.22, 0.24],
            caption="Summary of every measurement in this report. Speed is "
                    "malloc + free operations per second.")
    if f_tradeoff:
        d.figure(f_tradeoff, "Protection against cost: attacks stopped by each "
                             "allocator against its single-thread speed. Further up "
                             "is safer; further right is faster.")

    groups = defaultdict(list)
    for x in order:
        groups[tuple(a for a in allocs if x in stopped[a])].append(code(x))
    lines = []
    for key in sorted(groups, key=lambda k: -len(k)):
        names = join_and(groups[key])
        if len(key) == len(allocs):
            lines.append(f"Stopped by all {len(allocs)} allocators: {names}.")
        elif not key:
            lines.append(f"Stopped by none of them: {names}.")
        else:
            lines.append(f"Stopped only by {join_and(LABEL[k] for k in key)}: {names}.")
    if base1 and len(allocs) > 1:
        slower = [f"{LABEL[a]} {base1 / single_thread(a):.1f}×" for a in allocs
                  if a != "glibc" and single_thread(a)]
        lines.append("Single-threaded, the hardened allocators were slower than glibc: "
                     f"{join_and(slower)}.")
    if any(m["in_reach"] == 0 for m in meta.values()):
        lines.append("Read the counts together with Section 3. In some cells, memory "
                     "layout decided the outcome, or a different defense fired than the "
                     "bug's name suggests.")
    d.p("<b>In short</b>", "lead")
    d.bullets(lines)

    # -- 1. method -----------------------------------------------------------
    d.h1("1. How the experiment works")
    d.h2("1.1 Allocators compared")
    llvm = re.search(r"llvm-(\d+)", env.get("scudo_so", ""))
    build_used = {
        "glibc": escape(env.get("glibc", "system glibc")),
        "scudo": f"LLVM {llvm.group(1)} compiler-rt (standalone Scudo)" if llvm
                 else escape(env.get("scudo_so", "not configured")),
        "hardened": f"GrapheneOS hardened_malloc, commit "
                    f"{escape(env.get('hardened_commit', 'unknown'))}, default build",
    }
    d.table(["Allocator", "Build used", "Documented defenses"],
            [[f"<b>{LABEL[a]}</b>", build_used[a], DEFENSES[a]] for a in allocs],
            [0.19, 0.29, 0.52],
            caption="Defenses as documented by each project. This experiment measures "
                    "which of them actually fire against the programs in Table 3.")
    d.h2("1.2 Attack programs")
    d.table(["Program", "Bug", "What it does"],
            [[code(x), ATTACKS.get(x, (x, ""))[0], ATTACKS.get(x, ("", ""))[1]]
             for x in order],
            [0.25, 0.18, 0.57],
            caption=f"One bug per program, in {code('src/attacks/')}. Each prints "
                    f"{code('ATTACK SUCCEEDED')} only if it reaches the end without "
                    f"being stopped.")
    d.h2("1.3 Procedure")
    d.p("Each attack is a small C program, compiled once with gcc at -O0 and without "
        "_FORTIFY_SOURCE, so the compiler neither removes the bug nor intercepts it. "
        "The same binary then runs under each allocator, loaded with "
        f"{code('LD_PRELOAD')}. glibc is the baseline and needs no preload.")
    loaded = Counter(r.get("loaded") for r in rows)
    check = (f"All {len(rows)} runs passed this check."
             if loaded.get("yes", 0) == len(rows)
             else f"{len(rows) - loaded.get('yes', 0)} of {len(rows)} runs failed it "
                  f"and are counted as inconclusive.")
    d.p("Before each attack/allocator pair runs, a helper program reads "
        f"{code('/proc/self/maps')} to confirm the intended allocator library is "
        f"actually loaded, so no result can come from glibc by accident. {check}")
    d.p(f"Each pair ran {runs_per_cell} times with a "
        f"{escape(env.get('timeout_s', '?'))}-second timeout. A run counts as "
        "<b>stopped</b> if the allocator killed the program (for example with "
        f"SIGABRT) or it exited with an error before printing {code('ATTACK SUCCEEDED')}, "
        "and as <b>missed</b> if it printed that marker and exited normally. "
        f"{code('uninitialized_read')} decides its own outcome: it exits with an error "
        "when it cannot find the secret.")
    d.h2("1.4 Machine")
    env_rows = [[k, escape(env[key])] for k, key in
                (("Operating system", "os"), ("Kernel", "kernel"), ("CPU", "cpu"),
                 ("Logical CPUs", "cpus"), ("C library", "glibc"),
                 ("Compiler", "compiler"), ("Experiment date (UTC)", "date_utc"))
                if key in env]
    if env_rows:
        d.table(["", ""], env_rows, [0.25, 0.75])

    # -- 2. outcomes ---------------------------------------------------------
    d.h1("2. Which attacks each allocator stopped")
    d.figure(f_matrix, f"Outcome of each attack under each allocator, "
                       f"{runs_per_cell} runs per cell. The count is how many runs had "
                       f"the outcome shown.")
    unanimous = all(s["unanimous"] for s in summ.values())
    if unanimous:
        d.p(f"Every run of a given pair gave the same outcome, so the result did not "
            f"depend on Scudo's or hardened_malloc's randomization in any of the "
            f"{runs_per_cell} runs.")
    ev = []
    for x in order:
        for a in allocs:
            s = summ.get((x, a))
            if not s:
                continue
            if s["verdict"] == "stopped":
                where = escape(s["step"])
                if s["message"]:
                    msg = code(s["message"])
                    if s["signal"]:
                        msg += f" ({s['signal']})"
                elif s["exit_code"]:
                    msg = f"none: the program itself exited with code {s['exit_code']}"
                else:
                    msg = f"none ({s['signal']})" if s["signal"] else "none"
            else:
                where, msg = "—", "none: the program ran to completion"
            ev.append([code(x), LABEL[a], chip(s["verdict"], s["k"], s["n"]), where, msg])
    d.table(["Attack", "Allocator", "Outcome", "Last step before the abort",
             "Allocator's message"], ev, [0.21, 0.17, 0.14, 0.22, 0.26],
            caption=f"Messages are each allocator's own error output from the run logs "
                    f"in {code('results/logs/')}, with addresses replaced by 0x…. The "
                    f"last step shows where in the program the allocator stepped in.")

    # -- 3. mechanisms -------------------------------------------------------
    d.h1("3. What actually happened")
    d.p("The matrix shows whether each program was stopped. The logs also show "
        "how. In some cases the mechanism differs from what the bug's name suggests, "
        "and that changes what the result means.")

    both = [x for x in ("double_free", "invalid_free") if x in attacks]
    if both and all(summ.get((x, a), {}).get("verdict") == "stopped"
                    for x in both for a in allocs):
        d.h2("3.1 Double free and invalid free")
        d.p(f"Every allocator caught both bugs inside {code('free()')}, each through "
            "its own check (Table 4). These are the easiest bugs to check for. The "
            "pointer handed to free() is the evidence, and the allocator can inspect "
            "its own record of that block before trusting it.")

    if "heap_overflow" in attacks:
        d.h2("3.2 Heap overflow")
        sizes = overflow_sizes(cells, allocs)
        if sizes:
            req, wr = sizes
            d.p(f"The program allocates {req} bytes, writes {wr} ({wr - req} past the "
                f"end) and then frees the block.")
        items, header_only = [], []
        for a in allocs:
            s = summ.get(("heap_overflow", a))
            if not s:
                continue
            if s["verdict"] == "stopped" and "canary" in s["message"]:
                items.append(f"<b>{LABEL[a]}</b> stopped it in {code('free()')}. The "
                             f"overflow had overwritten the canary at the end of the "
                             f"block's slot ({code(s['message'])}).")
            elif s["verdict"] == "succeeded" and a in ("glibc", "scudo"):
                header_only.append(a)
            else:
                items.append(f"<b>{LABEL[a]}</b>: {VERB[s['verdict']].lower()} "
                             f"({s['k']}/{s['n']} runs).")
        if header_only:
            who = join_and(f"<b>{LABEL[a]}</b>" for a in header_only)
            items.insert(0, f"{who} let it run to completion. "
                            f"{'Both check' if len(header_only) > 1 else 'It checks'} "
                            f"the block's own header in {code('free()')}. That header "
                            f"sits <i>before</i> the buffer, not after it, so the "
                            f"overwritten bytes went unnoticed.")
        d.bullets(items)

    if "metadata_overwrite" in attacks:
        d.h2("3.3 Metadata overwrite: memory layout decided the result")
        some = next(iter(meta.values()))
        d.p(f"Block a is {META_A_SIZE} bytes and the program writes {some['overflow']} "
            f"bytes past its end, so the overflow covers the {some['reach']} bytes "
            f"starting at a. It can only damage b's header if b starts inside that "
            f"range. Where b actually landed was logged in every run:")
        mrows = []
        for a in allocs:
            m, s = meta[a], summ.get(("metadata_overwrite", a))
            if not s:
                continue
            ds = ", ".join(str(v) for v in m["deltas"])
            msg = code(s["message"]) if s["message"] else "none"
            mrows.append([LABEL[a], ds, f"{m['in_reach']} of {len(m['deltas'])}",
                          chip(s["verdict"], s["k"], s["n"]), msg])
        d.table(["Allocator", "Distance from a to b, per run (bytes)",
                 "Runs where b was in reach", "Outcome", "Allocator's message"],
                mrows, [0.18, 0.24, 0.14, 0.15, 0.29],
                caption="A negative distance means b was placed before a in memory.")
        paras = []
        for a in allocs:
            m, s = meta[a], summ.get(("metadata_overwrite", a))
            if not s or not m["deltas"]:
                continue
            if m["in_reach"] == len(m["deltas"]) and s["verdict"] == "stopped":
                dist = join_and(sorted({str(v) for v in m["deltas"]}))
                t = (f"Under <b>{LABEL[a]}</b>, b sat {dist} bytes after a in every run, "
                     f"so the overflow rewrote b's header and {code('free(b)')} rejected "
                     f"it ({code(s['message'])}).")
                if a == "glibc" and "munmap_chunk" in s["message"]:
                    t += (" The overflow byte is 'B' (0x42), which sets the IS_MMAPPED "
                          "flag (0x2) in b's size field, so glibc treated b as a "
                          "separately mapped chunk and its sanity check failed. This is "
                          "the one case where the program tested what its name says.")
                paras.append(t)
        far = [a for a in allocs if meta[a]["deltas"] and meta[a]["in_reach"] == 0]
        if far:
            all_d = [v for a in far for v in meta[a]["deltas"]]
            near = min(all_d, key=abs)
            t = (f"Under {join_and('<b>' + LABEL[a] + '</b>' for a in far)}, b was never "
                 f"in reach. It landed between {abs(near)} and {max(abs(v) for v in all_d)} "
                 f"bytes away, sometimes before a. For these allocators, this program did "
                 f"not test metadata protection at all:")
            paras.append(t)
            sub = []
            for a in far:
                s = summ[("metadata_overwrite", a)]
                if s["verdict"] == "succeeded":
                    sub.append(f"<b>{LABEL[a]}</b> let it finish. The bytes it overwrote "
                               f"belonged to neighbouring blocks that the program never "
                               f"frees, so no check ever looked at them. This is our "
                               f"explanation; it has not been verified separately.")
                elif s["verdict"] == "stopped" and "canary" in s["message"]:
                    sub.append(f"<b>{LABEL[a]}</b> stopped it at {code(s['step'])}, not at "
                               f"free(b). The cause was a's own end-of-slot canary "
                               f"({code(s['message'])}), the same mechanism as in the "
                               f"heap overflow test. Its separated metadata never came "
                               f"into play.")
            for t in paras:
                d.p(t)
            d.bullets(sub)
            d.p("A fairer version of this test would place b right after a on purpose, "
                "for example by allocating many same-size blocks and overflowing into "
                "one that is then freed. Section 6 lists it.")
        else:
            for t in paras:
                d.p(t)

    if "uninitialized_read" in attacks:
        d.h2("3.4 Uninitialized read")
        d.table(["Allocator", "Same block handed back", "Secret recovered", "Outcome"],
                [[LABEL[a], f"{uninit[a]['same']} of {uninit[a]['total']}",
                  f"{uninit[a]['leaked']} of {summ[('uninitialized_read', a)]['n']}",
                  chip(summ[("uninitialized_read", a)]["verdict"],
                       summ[("uninitialized_read", a)]["k"],
                       summ[("uninitialized_read", a)]["n"])]
                 for a in allocs if ("uninitialized_read", a) in summ],
                [0.25, 0.25, 0.25, 0.25])
        reused = [a for a in allocs if uninit[a]["total"]
                  and uninit[a]["same"] == uninit[a]["total"]
                  and uninit[a]["leaked"] == uninit[a]["total"]]
        moved = [a for a in allocs if uninit[a]["total"] and uninit[a]["same"] == 0
                 and uninit[a]["leaked"] == 0]
        if reused:
            t = (f"{join_and('<b>' + LABEL[a] + '</b>' for a in reused)} handed back the "
                 f"block that had just been freed, with the secret still in it.")
            if "scudo" in reused:
                t += (" Scudo can delay reuse with a quarantine, but the quarantine is off "
                      "by default, and this experiment uses default settings.")
            d.p(t)
        for a in moved:
            t = (f"<b>{LABEL[a]}</b> handed back a different block in every run, so the "
                 f"secret never appeared. This demonstrates its randomized slot reuse. "
                 f"It does not by itself demonstrate zero-on-free, because the old block "
                 f"was never read again.")
            if uaf.get(a, {}).get("kind") == "zeroed":
                t += " Section 3.5 has direct evidence of that."
            d.p(t)

    if "use_after_free" in attacks:
        d.h2("3.5 Use after free")
        meaning = {"unchanged": "freed memory left as it was",
                   "zeroed": "freed memory wiped (zero-on-free)",
                   "overwritten": "overwritten by the allocator's own bookkeeping "
                                  "(a different value each run)",
                   "unknown": "not recorded"}
        urows = []
        for a in allocs:
            u = uaf[a]
            vals = sorted(set(u["after"]))
            shown = ", ".join(str(v) for v in vals[:5]) + (", …" if len(vals) > 5 else "")
            urows.append([LABEL[a], str(u["orig"]), shown, meaning[u["kind"]]])
        d.table(["Allocator", "Value before free", "Value read after free",
                 "What that shows"], urows, [0.17, 0.15, 0.30, 0.38])
        if all(summ.get(("use_after_free", a), {}).get("verdict") == "succeeded"
               for a in allocs):
            d.p("No allocator detected the stale write: every run read back the value it "
                "had written (999) and finished normally. The read after free still shows "
                "how each allocator treats freed memory:")
        items = []
        for a in allocs:
            k = uaf[a]["kind"]
            if k == "overwritten" and a == "glibc":
                items.append("<b>glibc</b> had replaced the value with its own data. That "
                             "fits glibc's tcache, which stores a per-process random key "
                             "at bytes 8 to 15 of a freed chunk. The value read sits at "
                             "byte 8.")
            elif k == "unchanged":
                items.append(f"<b>{LABEL[a]}</b> left the old value in place, so a "
                             f"dangling pointer can still read the old contents.")
            elif k == "zeroed":
                t = f"<b>{LABEL[a]}</b> returned 0. It had wiped the block on free."
                if a == "hardened" and summ.get(("use_after_free", a), {}).get("verdict") == "succeeded":
                    t += (" It does check for writes to freed memory, but only when the "
                          "slot is handed out again (it verifies the slot is still zero). "
                          "This program exits before that happens.")
                items.append(t)
        d.bullets(items)

    # -- 4. cost -------------------------------------------------------------
    if perf or mem:
        d.h1("4. What the safety costs")
    if perf:
        d.h2("4.1 Speed")
        n_perf = max(len(v) for v in perf.values())
        it = next(iter(perf_iters)) if len(perf_iters) == 1 else "?"
        d.p(f"Each thread runs {int(it):,} cycles of malloc and free over 128 live "
            f"blocks of sizes from 16 bytes to 4 KiB ({code('src/bench/throughput.c')}). "
            f"Each configuration ran {n_perf} times.")
        d.figure(f_perf, f"Mean throughput of {n_perf} runs; whiskers show one "
                         f"standard deviation.")
        prow = []
        for a in allocs:
            for t in sorted({t for (_a, t) in perf}, key=int):
                v = perf.get((a, t))
                if not v:
                    continue
                m = statistics.mean(v)
                sd = statistics.stdev(v) if len(v) > 1 else 0.0
                b = perf.get(("glibc", t))
                rel = "baseline" if a == "glibc" or not b else f"{statistics.mean(b) / m:.1f}×"
                prow.append([LABEL[a], t, f"{m:,.0f}", f"{sd:,.0f}", rel])
        d.table(["Allocator", "Threads", "Mean ops/s", "Std dev", "Slower than glibc by"],
                prow, [0.22, 0.12, 0.24, 0.2, 0.22], right=(1, 2, 3, 4),
                caption="Slowdown compares each allocator with glibc at the same thread "
                        "count.")
    if mem and mem_meta:
        d.h2("4.2 Memory")
        n_mem = max(len(v) for v in mem.values())
        d.p(f"The program keeps {mem_meta['blocks']:,} blocks of {mem_meta['bytes']} bytes "
            f"alive at once ({mem_meta['req_kib'] / 1024:.1f} MiB requested) and reports "
            f"its peak resident memory. Each allocator ran {n_mem} times.")
        d.figure(f_mem, "Mean peak resident memory for the same allocations. The line "
                        "marks how much memory the program asked for.")
        d.p("Peak memory includes the program's own code and libraries, so these ratios "
            "slightly overstate the allocator's own overhead.")

    # -- 5/6. limits and next steps ------------------------------------------
    d.h1("5. Limitations")
    lim = [f"{runs_per_cell} runs per pair, on one machine (WSL2)."
           + (" Attack outcomes were identical across runs, but timing varies (see the "
              "standard deviations)." if unanimous else "")]
    lim += ["Each bug is tested by a single program. A result describes that program, "
            "not the whole bug class; Section 3.3 shows memory layout alone deciding "
            "an outcome.",
            "All allocators run with their default settings. Optional defenses such as "
            "Scudo's quarantine were not enabled.",
            "The attacks have not yet been checked with a reference detector "
            "(AddressSanitizer or Valgrind) to confirm that each program triggers "
            "exactly the bug it is meant to.",
            "The speed test is a synthetic microbenchmark, not a real application."]
    d.bullets(lim)
    d.h1("6. Next steps")
    d.bullets([
        "<b>Bypass variants</b>, the project's main contribution. These are versions "
        "of each attack designed around one specific defense: for example, an "
        "out-of-bounds write placed to skip the slot canary, or heap spraying so a "
        "freed block is reused despite delayed reuse.",
        "A metadata overwrite test that places the target block right after the "
        "overflowing one, so Scudo's header checksums and hardened_malloc's separated "
        "metadata are actually exercised.",
        "Repeat with Scudo's quarantine enabled, to measure what delayed reuse stops "
        "and what it costs.",
        "A use-after-free variant that allocates again after the stale write, to "
        "trigger hardened_malloc's write-after-free check.",
        "Confirm every attack with AddressSanitizer or Valgrind.",
    ])

    d.h1("Appendix: reproducing these results")
    d.p("From a clean checkout, on Linux or WSL2, following the README:")
    d.add(Preformatted(
        "./scripts/setup.sh      # allocators + report venv\n"
        "make                    # attacks and benchmarks\n"
        "./scripts/run_all.sh    # -> results/attack_matrix.csv, logs, environment.txt\n"
        "./scripts/measure.sh    # -> results/perf.csv, results/memory.csv\n"
        "./scripts/make_pdf.sh   # -> results/findings.pdf (this document)",
        styles["mono"]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Sans", 7.5)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.drawString(doc.leftMargin, 1.2 * cm,
                          f"Heap allocator security: interim findings · generated "
                          f"{generated} from results/ · do not edit by hand")
        canvas.drawRightString(A4[0] - doc.rightMargin, 1.2 * cm, str(doc.page))
        canvas.restoreState()

    pdf = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title="Heap Allocator Security: Interim Findings",
                            author="Muhammad Ali Athar, Aleena Abbasi, Shaheer Qureshi")
    pdf.build(d.story, onFirstPage=footer, onLaterPages=footer)
    print(f"wrote {OUT}")
    print(f"wrote figures to {FIGS}/")


if __name__ == "__main__":
    build()
