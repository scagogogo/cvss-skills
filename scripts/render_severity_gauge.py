#!/usr/bin/env python3
"""Render a CVSS severity gauge and score scale visualization."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Arc, Wedge
import numpy as np

# Color palette
C = {
    'bg': '#0d1117',
    'text': '#f0f6fc',
    'text_sub': '#8b949e',
    'line': '#30363d',
    'none': '#8b949e',
    'low': '#3fb950',
    'medium': '#d29922',
    'high': '#f78166',
    'critical': '#da3633',
}

fig, axes = plt.subplots(1, 2, figsize=(20, 7))
fig.patch.set_facecolor(C['bg'])

# ============ Left: Severity Scale Bar ============
ax1 = axes[0]
ax1.set_facecolor(C['bg'])
ax1.set_xlim(-0.5, 10.5)
ax1.set_ylim(-1, 5)
ax1.axis('off')

ax1.text(5, 4.3, 'CVSS Severity Scale', ha='center', va='center',
         fontsize=18, color=C['text'], fontweight='bold', fontfamily='sans-serif')

# Severity bands
bands = [
    (0, 0.1, 'None', C['none'], '0.0'),
    (0.1, 3.9, 'Low', C['low'], '0.1 - 3.9'),
    (3.9, 6.9, 'Medium', C['medium'], '4.0 - 6.9'),
    (6.9, 8.9, 'High', C['high'], '7.0 - 8.9'),
    (8.9, 10.0, 'Critical', C['critical'], '9.0 - 10.0'),
]

bar_y = 2.5
bar_h = 1.2
for lo, hi, name, color, range_str in bands:
    x_lo = lo
    w = hi - lo
    rect = FancyBboxPatch(
        (x_lo, bar_y), w, bar_h,
        boxstyle="round,pad=0.02",
        facecolor=color, edgecolor='none', alpha=0.9, zorder=3
    )
    ax1.add_patch(rect)
    mid_x = (lo + hi) / 2
    ax1.text(mid_x, bar_y + bar_h / 2 + 0.1, name, ha='center', va='center',
             fontsize=11, color='#ffffff', fontweight='bold', fontfamily='sans-serif', zorder=4)
    ax1.text(mid_x, bar_y + bar_h / 2 - 0.25, range_str, ha='center', va='center',
             fontsize=8, color='#ffffff', alpha=0.8, fontfamily='sans-serif', zorder=4)

# Score markers below
for score in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
    ax1.plot([score, score], [bar_y - 0.15, bar_y], color=C['text_sub'], lw=0.8, alpha=0.5)
    ax1.text(score, bar_y - 0.35, str(score), ha='center', va='center',
             fontsize=8, color=C['text_sub'], fontfamily='sans-serif')

# Example vectors
examples = [
    (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', C['critical']),
    (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N', C['high']),
    (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L', C['medium']),
    (2.3, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', C['low']),
]
ex_y = 0.8
for score, vector, color in examples:
    # Arrow from score to bar
    ax1.annotate('', xy=(score, bar_y + bar_h + 0.05), xytext=(score, ex_y + 0.35),
                 arrowprops=dict(arrowstyle='->', color=color, lw=1.5, alpha=0.7))
    ax1.text(score, ex_y, f'{score} — {vector[:30]}...',
             ha='center', va='center', fontsize=6.5, color=C['text_sub'],
             fontfamily='monospace', zorder=4,
             bbox=dict(boxstyle='round,pad=0.2', facecolor=C['bg'], edgecolor=color, alpha=0.8, lw=0.8))

# ============ Right: Semi-circle Gauge ============
ax2 = axes[1]
ax2.set_facecolor(C['bg'])
ax2.set_xlim(-1.3, 1.3)
ax2.set_ylim(-0.5, 1.5)
ax2.axis('off')
ax2.set_aspect('equal')

ax2.text(0, 1.35, 'CVSS Score Gauge', ha='center', va='center',
         fontsize=18, color=C['text'], fontweight='bold', fontfamily='sans-serif')

# Draw gauge arcs
gauge_r = 1.0
gauge_w = 0.15
segments = [
    (180, 180 - 1.8, C['none']),    # None: 0-0.1
    (178.2, 180 - 70.2, C['low']),  # Low: 0.1-3.9
    (109.8, 180 - 126, C['medium']), # Medium: 4.0-6.9
    (54, 180 - 162, C['high']),     # High: 7.0-8.9
    (18, 0, C['critical']),         # Critical: 9.0-10.0
]
# Redraw with clean segments
theta_segments = [
    (180, 178.2, C['none']),
    (178.2, 109.8, C['low']),
    (109.8, 54, C['medium']),
    (54, 18, C['critical']),
    (18, 0, C['critical']),
]
for start_deg, end_deg, color in theta_segments:
    wedge = Wedge((0, 0), gauge_r, end_deg, start_deg, width=gauge_w,
                  facecolor=color, edgecolor='none', alpha=0.9, zorder=3)
    ax2.add_patch(wedge)

# Outer thin ring
outer_ring = Wedge((0, 0), gauge_r + 0.02, 0, 180, width=0.02,
                   facecolor=C['text_sub'], edgecolor='none', alpha=0.3, zorder=2)
ax2.add_patch(outer_ring)

# Score labels around the gauge
for score, label in [(0, '0'), (2, '2'), (4, '4'), (6, '6'), (8, '8'), (10, '10')]:
    angle = np.radians(180 - score * 18)
    x = (gauge_r + 0.25) * np.cos(angle)
    y = (gauge_r + 0.25) * np.sin(angle)
    ax2.text(x, y, label, ha='center', va='center',
             fontsize=9, color=C['text_sub'], fontfamily='sans-serif')

# Severity labels
severity_labels = [
    (0.05, 'None', C['none']),
    (0.2, 'Low', C['low']),
    (0.54, 'Medium', C['medium']),
    (0.79, 'High', C['high']),
    (0.95, 'Critical', C['critical']),
]
for frac, name, color in severity_labels:
    angle = np.radians(180 - frac * 180)
    x = (gauge_r - gauge_w - 0.18) * np.cos(angle)
    y = (gauge_r - gauge_w - 0.18) * np.sin(angle)
    ax2.text(x, y, name, ha='center', va='center',
             fontsize=7, color=color, fontweight='bold', fontfamily='sans-serif',
             rotation=90 - frac * 180, alpha=0.8)

# Center text - example score
center_score = 9.8
ax2.text(0, 0.45, f'{center_score}', ha='center', va='center',
         fontsize=36, color=C['critical'], fontweight='bold', fontfamily='sans-serif', zorder=5)
ax2.text(0, 0.15, 'Critical', ha='center', va='center',
         fontsize=14, color=C['critical'], fontfamily='sans-serif', zorder=5)

# Needle
needle_angle = np.radians(180 - center_score * 18)
nx = (gauge_r - gauge_w/2 - 0.05) * np.cos(needle_angle)
ny = (gauge_r - gauge_w/2 - 0.05) * np.sin(needle_angle)
ax2.plot([0, nx], [0, ny], color=C['text'], lw=2.5, zorder=6)
ax2.plot(0, 0, 'o', color=C['text'], markersize=5, zorder=7)

plt.tight_layout(pad=1.0)
output_path = '/home/cc11001100/github/scagogogo/cvss-skills/docs/images/severity-gauge.png'
fig.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor(), edgecolor='none')
plt.close()
print(f'Severity gauge saved to {output_path}')
