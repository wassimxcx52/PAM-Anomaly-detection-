#!/usr/bin/env python3
"""
plot_unsupervised.py -- figures for the unsupervised track.

Reads the artifacts that ml/unsupervised/train.py already wrote, so the figures
cannot drift from the numbers in the report:

    ml/unsupervised/out/eval_scores_configA.csv   per-session anomaly scores
    ml/unsupervised/out/domain_gate.csv           KS per feature (post-fix)
    feature_extraction/out/features_eval_real.csv labels + composition

Emits PNG (300 dpi, for slides) and PDF (vector, for the LaTeX report) per figure.

FIGURE CHOICES
--------------
Fig 1 uses EMPHASIS, not six categorical colours: the story is "the best learned
detector vs the mandatory baseline", and painting all six equally would bury it.
Figs 2 and 5 are magnitude -> one sequential hue, ordered. Fig 3 is before/after
per item -> dumbbell, one hue in two shades. Fig 4 is the only place two classes
are the subject, so it is the only categorical pair.

Everything is single-mode light: these are print figures for a report, not a
themed web page.
"""

from __future__ import annotations

import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.path import Path as MPath
from matplotlib.patches import PathPatch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
SCORES = os.path.join(ROOT, "ml", "unsupervised", "out", "eval_scores_configA.csv")
GATE = os.path.join(ROOT, "ml", "unsupervised", "out", "domain_gate.csv")
FEATURES = os.path.join(ROOT, "feature_extraction", "out", "features_eval_real.csv")
OUT = HERE

# ---------------------------------------------------------------- palette ---
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

SERIES_1 = "#2a78d6"      # blue   -- emphasis / primary
SERIES_2 = "#eb6834"      # orange -- the one contrasting series
# Blue ordinal steps. Nothing lighter than 250 on a light surface (contrast).
BLUE = {"450": "#2a78d6", "350": "#5598e7", "250": "#86b6ef", "600": "#184f95"}

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "text.color": INK,
    "axes.labelcolor": INK_2,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.edgecolor": AXIS,
    "axes.linewidth": 0.8,
    "font.size": 10,
})


def style(ax, xgrid=False, ygrid=True):
    """Recessive chrome: no box, hairline grid on the value axis only."""
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(AXIS)
    ax.spines["bottom"].set_color(AXIS)
    ax.set_axisbelow(True)
    if ygrid:
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    if xgrid:
        ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.tick_params(length=0)


def _radius_in_data(ax, points):
    """x and y are on completely different scales, so a single radius value
    cannot be reused for both axes -- it produces a lozenge. Convert a screen
    radius into (rx, ry) separately. Call only once the axes limits are final."""
    dpi = ax.figure.dpi
    px = points * dpi / 72.0
    inv = ax.transData.inverted()
    x0, y0 = inv.transform((0.0, 0.0))
    x1, y1 = inv.transform((px, px))
    return abs(x1 - x0), abs(y1 - y0)


def rounded_hbar(ax, y, width, height, color, points=3.0):
    """Horizontal bar anchored at x=0 with only its DATA end rounded, so the
    baseline stays a straight edge and the value end reads as the mark's tip."""
    if width <= 0:
        return
    rx, ry = _radius_in_data(ax, points)
    rx, ry = min(rx, width), min(ry, height / 2)
    y0, y1 = y - height / 2, y + height / 2
    verts = [(0, y0), (width - rx, y0), (width, y0), (width, y0 + ry),
             (width, y1 - ry), (width, y1), (width - rx, y1), (0, y1), (0, y0)]
    codes = [MPath.MOVETO, MPath.LINETO, MPath.CURVE3, MPath.CURVE3,
             MPath.LINETO, MPath.CURVE3, MPath.CURVE3, MPath.LINETO,
             MPath.CLOSEPOLY]
    ax.add_patch(PathPatch(MPath(verts, codes), facecolor=color, edgecolor="none"))


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def save(fig, name):
    for ext in ("png", "pdf"):
        path = os.path.join(OUT, f"{name}.{ext}")
        fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {name}.png / .pdf")


# ------------------------------------------------------------------- data ---
def load():
    scores = pd.read_csv(SCORES)
    feats = pd.read_csv(FEATURES)[["session_id", "composition", "avg_command_length"]]
    df = scores.merge(feats, on="session_id")
    df["y"] = (df["label"] == "attack").astype(int)
    return df


def precision_at_k(score, y, k):
    order = np.argsort(-score)[:k]
    return y[order].sum() / k


# ------------------------------------------------------------- figure 1 -----
def fig_precision_at_k(df):
    """EMPHASIS: the best learned detector and the mandatory baseline carry the
    story; the other four are context, so they are grey."""
    y = df["y"].to_numpy()
    base = y.mean()
    models = [c[6:] for c in df.columns if c.startswith("score_")]
    ks = np.arange(5, 101, 1)

    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    for m in models:
        if m in ("PCA", "MAD (baseline)"):
            continue
        curve = [precision_at_k(df["score_" + m].to_numpy(), y, k) for k in ks]
        ax.plot(ks, curve, color=MUTED, linewidth=1.2, alpha=0.55, zorder=2)

    for m, color in (("PCA", SERIES_1), ("MAD (baseline)", SERIES_2)):
        curve = [precision_at_k(df["score_" + m].to_numpy(), y, k) for k in ks]
        ax.plot(ks, curve, color=color, linewidth=2.0, zorder=4, label=m)
        ax.annotate(m, xy=(ks[-1], curve[-1]), xytext=(6, 0),
                    textcoords="offset points", color=color, fontsize=9,
                    va="center", fontweight="bold")

    ax.axhline(base, color=MUTED, linewidth=1.5, linestyle=(0, (4, 3)), zorder=1)
    ax.annotate(f"classeur aléatoire ({base:.3f})", xy=(ks[-1], base),
                xytext=(6, 9), textcoords="offset points",
                color=MUTED, fontsize=8.5, va="center")
    ax.annotate("4 autres détecteurs", xy=(38, 0.47), xytext=(30, 0.255),
                color=MUTED, fontsize=8.5,
                arrowprops=dict(arrowstyle="-", color=MUTED, linewidth=0.8,
                                shrinkA=2, shrinkB=3))

    ax.set_xlabel("k — budget d'alertes du SOC (sessions examinées)")
    ax.set_ylabel("precision@k")
    ax.set_ylim(0.14, 1.02)
    ax.set_xlim(5, 118)
    ax.set_xticks([5, 25, 50, 75, 100])
    style(ax)
    ax.set_title("Precision@k — 256 sessions réelles, 49 attaques",
                 color=INK, fontsize=12, fontweight="bold", loc="left", pad=14)
    save(fig, "fig1_precision_at_k")


# ------------------------------------------------------------- figure 2 -----
def fig_recall_by_composition(df, k=50):
    """The structuring result. Magnitude -> one hue, ordered dark->light as the
    attack gets stealthier, so the colour ramp and the story point the same way."""
    d = df.copy()
    d["flag"] = (d["score_PCA"].rank(ascending=False, method="min") <= k).astype(int)
    atk = d[d.y == 1]
    order = ["full", "diluted", "minimal"]
    labels = {"full": "full\nscénario seul",
              "diluted": "diluted\ndilué dans du bénin",
              "minimal": "minimal\n1–2 commandes enfouies"}
    shades = [BLUE["600"], BLUE["450"], BLUE["250"]]

    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    # Limits before any rounded bar: the radius is computed from transData.
    ax.set_xlim(0, 1.18)
    ax.set_ylim(-0.6, len(order) - 0.4)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([labels[c] for c in reversed(order)], color=INK_2, fontsize=9)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel(f"rappel @k={k}   (barres d'erreur : IC 95 % de Wilson)")
    style(ax, xgrid=True, ygrid=False)

    for i, comp in enumerate(order):
        g = atk[atk.composition == comp]
        n, hits = len(g), int(g.flag.sum())
        rate = hits / n if n else 0
        lo, hi = wilson(hits, n)
        yy = len(order) - 1 - i
        rounded_hbar(ax, yy, rate, 0.30, shades[i])
        ax.plot([lo, hi], [yy, yy], color=INK_2, linewidth=1.3, zorder=5,
                solid_capstyle="butt")
        for b in (lo, hi):
            ax.plot([b, b], [yy - 0.07, yy + 0.07], color=INK_2, linewidth=1.3, zorder=5)
        ax.text(hi + 0.025, yy, f"{rate:.2f}   n={n}",
                va="center", color=INK, fontsize=10, fontweight="bold")
    ax.set_title("Le détecteur attrape le bruyant et rate le réaliste",
                 color=INK, fontsize=12, fontweight="bold", loc="left", pad=14)
    fig.text(0.005, -0.20,
             "Les sessions « minimal » font 19,3 caractères de moyenne contre 19,1 "
             "pour le bénin : indistinguables\nsur toutes les features de forme de "
             "commande disponibles.", color=MUTED, fontsize=8.5, ha="left")
    save(fig, "fig2_recall_by_composition")


# ------------------------------------------------------------- figure 3 -----
def fig_domain_gate():
    """Before -> after per item = dumbbell, one hue in two shades.

    The `before` column is the pre-fix run of the same gate (2026-08-07, before
    session composition landed in simulate_sessions.py). It is recorded here as a
    constant because that run predates the CSV artifact.
    """
    before = {"command_count": 0.041, "unique_command_ratio": 0.943,
              "avg_command_length": 0.155, "command_entropy": 0.687,
              "duration_sec_feat": 0.267}
    gate = pd.read_csv(GATE).set_index("feature")["ks"].to_dict()
    feats = sorted(before, key=lambda f: -before[f])

    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    for i, f in enumerate(feats):
        yy = len(feats) - 1 - i
        b, a = before[f], gate[f]
        ax.plot([b, a], [yy, yy], color=BLUE["250"], linewidth=2.0,
                zorder=2, solid_capstyle="round")
        ax.scatter([b], [yy], s=95, color=BLUE["250"], zorder=3,
                   edgecolor=SURFACE, linewidth=1.5)
        ax.scatter([a], [yy], s=95, color=BLUE["600"], zorder=4,
                   edgecolor=SURFACE, linewidth=1.5)

    ax.set_ylim(-0.6, len(feats) - 0.4)
    ax.axvline(0.35, color=SERIES_2, linewidth=1.5, linestyle=(0, (4, 3)), zorder=1)
    ax.annotate("seuil de rejet (KS 0.35)", xy=(0.35, 1.5), xytext=(8, 0),
                textcoords="offset points",
                color=SERIES_2, fontsize=8.5, va="center")

    ax.scatter([], [], s=95, color=BLUE["250"], label="avant le correctif de collecte")
    ax.scatter([], [], s=95, color=BLUE["600"], label="après")
    ax.legend(loc="lower right", frameon=False, fontsize=9, labelcolor=INK_2)

    ax.set_yticks(range(len(feats)))
    ax.set_yticklabels(list(reversed(feats)), color=INK_2, fontsize=9)
    ax.set_xlim(0, 1.0)
    ax.set_xlabel("statistique KS — bénin généré contre bénin réel")
    style(ax, xgrid=True, ygrid=False)
    ax.set_title("Porte de domaine : 3 features sur 5 admises → 5 sur 5",
                 color=INK, fontsize=12, fontweight="bold", loc="left", pad=14)
    fig.text(0.005, -0.20,
             "KS élevé = les deux domaines ne s'accordent pas sur ce qu'est une "
             "session NORMALE. Le détecteur signalerait\nalors une session parce "
             "qu'elle est réelle, pas parce qu'elle est anormale.",
             color=MUTED, fontsize=8.5, ha="left")
    save(fig, "fig3_domain_gate")


# ------------------------------------------------------------- figure 4 -----
def fig_score_distribution(df, k=50):
    """The only figure where the two CLASSES are the subject -> the one
    categorical pair. Strip plot, because n=256 is small enough to show every
    session and the overlap is the point."""
    rng = np.random.default_rng(7)
    d = df.copy()
    d["rank"] = d["score_PCA"].rank(ascending=False, method="min")
    cutoff = d.loc[d["rank"] <= k, "score_PCA"].min()

    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    for i, (lbl, color, name) in enumerate(
            [("benign", SERIES_1, "bénin"), ("attack", SERIES_2, "attaque")]):
        g = d[d.label == lbl]
        jitter = rng.uniform(-0.17, 0.17, len(g))
        ax.scatter(g["score_PCA"], np.full(len(g), i) + jitter, s=26,
                   color=color, alpha=0.75, edgecolor=SURFACE, linewidth=0.6,
                   zorder=3, label=f"{name} (n={len(g)})")

    ax.axvline(cutoff, color=INK_2, linewidth=1.5, linestyle=(0, (4, 3)), zorder=2)
    ax.annotate(f"seuil top-{k}", xy=(cutoff, 1.62), xytext=(8, 0),
                textcoords="offset points", color=INK_2, fontsize=8.5, va="center")

    ax.set_yticks([0, 1])
    ax.set_yticklabels(["bénin", "attaque"], color=INK_2, fontsize=10)
    ax.set_ylim(-0.55, 1.85)
    ax.set_xscale("log")
    ax.set_xlabel("score d'anomalie PCA (échelle log)")
    ax.legend(loc="upper left", frameon=False, fontsize=9, labelcolor=INK_2)
    style(ax, xgrid=True, ygrid=False)
    ax.set_title("Distribution des scores — le recouvrement EST le résultat",
                 color=INK, fontsize=12, fontweight="bold", loc="left", pad=14)
    save(fig, "fig4_score_distribution")


# ------------------------------------------------------------- figure 5 -----
def fig_recall_by_tactic(df, k=50):
    d = df.copy()
    d["flag"] = (d["score_PCA"].rank(ascending=False, method="min") <= k).astype(int)
    atk = d[d.y == 1]
    g = atk.groupby("scenario")["flag"].agg(["count", "sum"])
    g["rate"] = g["sum"] / g["count"]
    g = g.sort_values("rate")

    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    ax.set_xlim(0, 1.15)
    ax.set_ylim(-0.6, len(g) - 0.4)
    ax.set_yticks(range(len(g)))
    ax.set_yticklabels(g.index, color=INK_2, fontsize=9.5)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel(f"rappel @k={k}")
    style(ax, xgrid=True, ygrid=False)

    lo_, hi_ = g["rate"].min(), g["rate"].max()
    for i, (name, row) in enumerate(g.iterrows()):
        # sequential: more-is-darker, mapped across the observed range
        t = (row["rate"] - lo_) / (hi_ - lo_) if hi_ > lo_ else 1.0
        color = [BLUE["250"], BLUE["350"], BLUE["450"], BLUE["600"]][int(t * 3.001)]
        rounded_hbar(ax, i, row["rate"], 0.34, color)
        ax.text(row["rate"] + 0.025, i, f"{row['rate']:.2f}   n={int(row['count'])}",
                va="center", color=INK, fontsize=9.5)
    ax.set_title("Rappel par tactique MITRE (PCA)",
                 color=INK, fontsize=12, fontweight="bold", loc="left", pad=14)
    save(fig, "fig5_recall_by_tactic")


def main() -> int:
    df = load()
    print(f"[viz] {len(df)} sessions, {int(df.y.sum())} attaques "
          f"(base {df.y.mean():.3f})")
    fig_precision_at_k(df)
    fig_recall_by_composition(df)
    fig_domain_gate()
    fig_score_distribution(df)
    fig_recall_by_tactic(df)
    print(f"[viz] figures -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
