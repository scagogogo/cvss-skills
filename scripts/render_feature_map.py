#!/usr/bin/env python3
"""Render a feature tree mind map for CVSS Skills project."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

# Color palette - dark theme with vibrant accents
C = {
    'bg': '#0d1117',
    'root': '#1f6feb',
    'root_dark': '#1158c7',
    'integration': '#8957e5',
    'sdk': '#1f6feb',
    'cli': '#f78166',
    'advanced': '#3fb950',
    'parsing': '#da3633',
    'scoring': '#d29922',
    'validation': '#3fb950',
    'comparison': '#58a6ff',
    'serial': '#bc8cff',
    'line': '#30363d',
    'text': '#f0f6fc',
    'text_sub': '#8b949e',
    'badge_bg': '#21262d',
    'leaf': '#30363d',
}

def rounded_box(ax, x, y, w, h, text, bg, text_color='#f0f6fc', fontsize=10,
                bold=False, radius=0.06, alpha=1.0, border_color=None, border_width=0):
    """Draw a rounded box with centered text."""
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle=f"round,pad={radius}",
        facecolor=bg, edgecolor=border_color or 'none',
        linewidth=border_width, alpha=alpha, zorder=3
    )
    ax.add_patch(box)
    ax.text(x, y, text, ha='center', va='center', fontsize=fontsize,
            color=text_color, fontweight='bold' if bold else 'normal', zorder=4,
            fontfamily='sans-serif')

def connect(ax, x1, y1, x2, y2, color='#30363d', lw=1.5, style='-'):
    """Draw a stepped connection."""
    mid_x = (x1 + x2) / 2
    ax.plot([x1, mid_x, mid_x, x2], [y1, y1, y2, y2],
            color=color, lw=lw, alpha=0.7, zorder=1,
            solid_capstyle='round', linestyle=style)

# ============ Setup ============
fig, ax = plt.subplots(1, 1, figsize=(24, 14))
fig.patch.set_facecolor(C['bg'])
ax.set_facecolor(C['bg'])
ax.set_xlim(-0.5, 23.5)
ax.set_ylim(-0.5, 13.5)
ax.axis('off')

# ============ Title ============
ax.text(11.5, 12.8, 'CVSS Skills', ha='center', va='center',
        fontsize=26, color=C['text'], fontweight='bold', fontfamily='sans-serif')
ax.text(11.5, 12.2, 'Professional CVSS v3.0 / v3.1 Toolkit  —  Feature Map',
        ha='center', va='center', fontsize=13, color=C['text_sub'], fontfamily='sans-serif')

# ============ Root ============
rounded_box(ax, 11.5, 11.0, 5, 0.9, 'CVSS Skills', C['root'], fontsize=20, bold=True,
            border_color='#58a6ff', border_width=2)

# ============ Level 1: 4 categories ============
cats = [
    (3.0, 9.0, 'Integration', C['integration']),
    (9.0, 9.0, 'Go SDK', C['sdk']),
    (15.0, 9.0, 'CLI (30+)', C['cli']),
    (21.0, 9.0, 'Advanced', C['advanced']),
]
for cx, cy, label, color in cats:
    rounded_box(ax, cx, cy, 3.4, 0.75, label, color, fontsize=14, bold=True)
    connect(ax, 11.5, 10.55, cx, 9.38, color=color, lw=2.5)

# ============ INTEGRATION subtree ============
int_subs = [
    (1.5, 7.4, 'Claude Code Skills', '#6e40c9'),
    (3.0, 7.4, 'Go SDK', '#6e40c9'),
    (4.5, 7.4, 'CLI', '#6e40c9'),
    (2.25, 6.2, 'MCP Server', '#6e40c9'),
]
for x, y, label, color in int_subs:
    rounded_box(ax, x, y, 1.9, 0.5, label, color, fontsize=8)
    connect(ax, 3.0, 8.62, x, y + 0.25, color='#6e40c9', lw=1.2)

# Skills detail
int_skills = [
    (0.5, 5.2, '9 Skills'),
    (0.5, 4.4, '/cvss-parse'),
    (0.5, 3.7, '/cvss-score'),
    (0.5, 3.0, '/cvss-validate'),
    (2.0, 5.2, '/cvss-construct'),
    (2.0, 4.4, '/cvss-compare'),
    (2.0, 3.7, '/cvss-metrics'),
    (2.0, 3.0, '/cvss-serialize'),
    (3.5, 5.2, '/cvss-advanced'),
    (3.5, 4.4, '/cvss-install'),
]
for x, y, label in int_skills:
    rounded_box(ax, x, y, 1.5, 0.38, label, C['leaf'], fontsize=6.5, alpha=0.8)
    connect(ax, 1.5, 6.95, x, y + 0.19, color='#6e40c9', lw=0.8, style='-')

# ============ Go SDK subtree ============
sdk_subs = [
    (7.0, 7.4, 'Parsing', C['parsing']),
    (9.0, 7.4, 'Scoring', C['scoring']),
    (11.0, 7.4, 'Validation', C['validation']),
]
for x, y, label, color in sdk_subs:
    rounded_box(ax, x, y, 1.8, 0.55, label, color, fontsize=10, bold=True)
    connect(ax, 9.0, 8.62, x, y + 0.28, color=color, lw=1.5)

# Parsing leaves
parsing_leaves = [
    (6.0, 5.8, 'ParseString'),
    (6.0, 5.0, 'ParseAndScore'),
    (6.0, 4.2, 'Relaxed Parse'),
    (7.8, 5.8, 'Builder API'),
    (7.8, 5.0, 'FromMap'),
    (7.8, 4.2, 'Presets'),
]
for x, y, label in parsing_leaves:
    rounded_box(ax, x, y, 1.5, 0.4, label, '#8b2828', fontsize=7)
    connect(ax, 7.0, 7.12, x, y + 0.2, color='#da3633', lw=0.8)

# Scoring leaves
scoring_leaves = [
    (9.0, 5.8, 'Base Score'),
    (9.0, 5.0, 'Temporal Score'),
    (9.0, 4.2, 'Env Score'),
    (10.2, 5.4, 'Severity'),
    (10.2, 4.6, 'Breakdown'),
]
for x, y, label in scoring_leaves:
    rounded_box(ax, x, y, 1.5, 0.4, label, '#7a5a10', fontsize=7)
    connect(ax, 9.0, 7.12, x, y + 0.2, color='#d29922', lw=0.8)

# Validation leaves
val_leaves = [
    (11.0, 5.8, 'Validate()'),
    (11.0, 5.0, 'ValidationErrors'),
    (11.0, 4.2, 'MissingMetrics'),
    (11.0, 3.5, 'IsComplete'),
    (12.2, 5.0, 'Check()'),
    (12.2, 4.2, 'Equal()'),
]
for x, y, label in val_leaves:
    rounded_box(ax, x, y, 1.5, 0.4, label, '#1a5c20', fontsize=7)
    connect(ax, 11.0, 7.12, x, y + 0.2, color='#3fb950', lw=0.8)

# ============ CLI subtree ============
cli_subs = [
    (13.5, 7.4, 'Core', '#b35a3a'),
    (15.0, 7.4, 'Compare', '#b35a3a'),
    (16.5, 7.4, 'Output', '#b35a3a'),
]
for x, y, label, color in cli_subs:
    rounded_box(ax, x, y, 1.6, 0.55, label, color, fontsize=10, bold=True)
    connect(ax, 15.0, 8.62, x, y + 0.28, color='#f78166', lw=1.5)

# Core leaves
core_leaves = [
    (13.0, 5.8, 'score'),
    (13.0, 5.0, 'parse'),
    (13.0, 4.2, 'validate'),
    (13.0, 3.5, 'build'),
    (14.0, 5.8, 'describe'),
    (14.0, 5.0, 'preset'),
    (14.0, 4.2, 'random'),
    (14.0, 3.5, 'severity'),
]
for x, y, label in core_leaves:
    rounded_box(ax, x, y, 1.2, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 13.5, 7.12, x, y + 0.19, color='#f78166', lw=0.8)

# Compare leaves
compare_leaves = [
    (15.0, 5.8, 'diff'),
    (15.0, 5.0, 'merge'),
    (15.0, 4.2, 'distance'),
    (15.0, 3.5, 'equal'),
]
for x, y, label in compare_leaves:
    rounded_box(ax, x, y, 1.2, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 15.0, 7.12, x, y + 0.19, color='#f78166', lw=0.8)

# Output leaves
output_leaves = [
    (16.0, 5.8, 'json'),
    (16.0, 5.0, 'csv'),
    (16.0, 4.2, 'batch'),
    (17.0, 5.4, 'sort'),
    (17.0, 4.6, 'canonicalize'),
    (17.0, 3.9, 'convert'),
]
for x, y, label in output_leaves:
    rounded_box(ax, x, y, 1.3, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 16.5, 7.12, x, y + 0.19, color='#f78166', lw=0.8)

# ============ ADVANCED subtree ============
adv_subs = [
    (19.5, 7.4, 'Distance', '#2a8a4a'),
    (21.0, 7.4, 'Analysis', '#2a8a4a'),
    (22.5, 7.4, 'Utilities', '#2a8a4a'),
]
for x, y, label, color in adv_subs:
    rounded_box(ax, x, y, 1.6, 0.55, label, color, fontsize=10, bold=True)
    connect(ax, 21.0, 8.62, x, y + 0.28, color=C['advanced'], lw=1.5)

# Distance leaves
dist_leaves = [
    (19.0, 5.8, 'Euclidean'),
    (19.0, 5.0, 'Manhattan'),
    (19.0, 4.2, 'Hamming'),
    (20.0, 5.4, 'Jaccard'),
    (20.0, 4.6, 'Env-Aware'),
]
for x, y, label in dist_leaves:
    rounded_box(ax, x, y, 1.3, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 19.5, 7.12, x, y + 0.19, color=C['advanced'], lw=0.8)

# Analysis leaves
analysis_leaves = [
    (21.0, 5.8, 'Sensitivity'),
    (21.0, 5.0, 'Score Range'),
    (21.0, 4.2, 'Impact'),
    (21.0, 3.5, 'Version\nAware'),
]
for x, y, label in analysis_leaves:
    rounded_box(ax, x, y, 1.3, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 21.0, 7.12, x, y + 0.19, color=C['advanced'], lw=0.8)

# Utilities leaves
util_leaves = [
    (22.5, 5.8, 'Clone'),
    (22.5, 5.0, 'Serialize'),
    (22.5, 4.2, 'Mock Data'),
    (22.5, 3.5, 'Severity\nHelpers'),
]
for x, y, label in util_leaves:
    rounded_box(ax, x, y, 1.3, 0.38, label, C['leaf'], fontsize=7)
    connect(ax, 22.5, 7.12, x, y + 0.19, color=C['advanced'], lw=0.8)

# ============ Bottom stats bar ============
ax.axhline(y=2.2, xmin=0.03, xmax=0.97, color=C['line'], alpha=0.5, lw=1)

stats = [
    (3, '500+', 'Unit Tests'),
    (8, '30+', 'CLI Commands'),
    (13, '4', 'Integration Methods'),
    (18, '2', 'CVSS Versions'),
    (22, '9', 'Claude Skills'),
]
for x, num, label in stats:
    rounded_box(ax, x, 1.3, 2.8, 0.9, '', C['badge_bg'], alpha=0.8,
                border_color=C['line'], border_width=1)
    ax.text(x, 1.55, num, ha='center', va='center',
            fontsize=18, color=C['text'], fontweight='bold', fontfamily='sans-serif', zorder=5)
    ax.text(x, 1.05, label, ha='center', va='center',
            fontsize=8, color=C['text_sub'], fontfamily='sans-serif', zorder=5)

plt.tight_layout(pad=0.5)
output_path = '/home/cc11001100/github/scagogogo/cvss-skills/docs/images/feature-map.png'
fig.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor(), edgecolor='none')
plt.close()
print(f'Feature map saved to {output_path}')
