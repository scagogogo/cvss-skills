#!/usr/bin/env python3
"""Render CVSS vector structure diagram showing Base/Temporal/Environmental layers."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

C = {
    'bg': '#0d1117',
    'text': '#f0f6fc',
    'text_sub': '#8b949e',
    'line': '#30363d',
    'base': '#1f6feb',
    'base_light': '#1a4fa0',
    'temporal': '#d29922',
    'temporal_light': '#8a6510',
    'env': '#8957e5',
    'env_light': '#5a3a9a',
    'header': '#21262d',
}

def rounded_box(ax, x, y, w, h, text, bg, text_color='#f0f6fc', fontsize=9,
                bold=False, alpha=1.0, border_color=None, border_width=0):
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle="round,pad=0.03",
        facecolor=bg, edgecolor=border_color or 'none',
        linewidth=border_width, alpha=alpha, zorder=3
    )
    ax.add_patch(box)
    ax.text(x, y, text, ha='center', va='center', fontsize=fontsize,
            color=text_color, fontweight='bold' if bold else 'normal', zorder=4,
            fontfamily='sans-serif')

fig, ax = plt.subplots(1, 1, figsize=(18, 10))
fig.patch.set_facecolor(C['bg'])
ax.set_facecolor(C['bg'])
ax.set_xlim(-0.5, 17.5)
ax.set_ylim(-0.5, 9.5)
ax.axis('off')

# Title
ax.text(8.5, 9.0, 'CVSS Vector Structure', ha='center', va='center',
        fontsize=20, color=C['text'], fontweight='bold', fontfamily='sans-serif')
ax.text(8.5, 8.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:U/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X',
        ha='center', va='center', fontsize=6, color=C['text_sub'], fontfamily='monospace')

# ============ BASE METRICS (Required) ============
base_y = 7.0
rounded_box(ax, 8.5, base_y + 0.6, 16, 0.5, '', C['base'], alpha=0.15,
            border_color=C['base'], border_width=1.5)
ax.text(8.5, base_y + 0.6, 'BASE METRICS (Required)', ha='center', va='center',
        fontsize=13, color=C['base'], fontweight='bold', fontfamily='sans-serif', zorder=5)

# Exploitability sub-group
exp_x = 3.5
rounded_box(ax, exp_x, base_y - 0.3, 5.5, 0.5, '', C['base_light'], alpha=0.3,
            border_color=C['base'], border_width=0.8)
ax.text(exp_x, base_y - 0.3, 'Exploitability', ha='center', va='center',
        fontsize=9, color='#58a6ff', fontweight='bold', fontfamily='sans-serif', zorder=5)

# Impact sub-group
imp_x = 10.0
rounded_box(ax, imp_x, base_y - 0.3, 4.5, 0.5, '', C['base_light'], alpha=0.3,
            border_color=C['base'], border_width=0.8)
ax.text(imp_x, base_y - 0.3, 'Impact', ha='center', va='center',
        fontsize=9, color='#58a6ff', fontweight='bold', fontfamily='sans-serif', zorder=5)

# Scope
rounded_box(ax, 14.0, base_y - 0.3, 1.5, 0.5, '', C['base_light'], alpha=0.3,
            border_color=C['base'], border_width=0.8)
ax.text(14.0, base_y - 0.3, 'Scope', ha='center', va='center',
        fontsize=9, color='#58a6ff', fontweight='bold', fontfamily='sans-serif', zorder=5)

# Base metric boxes
base_metrics = [
    # Exploitability
    (1.5, 5.5, 'AV', 'Attack\nVector', 'N/L/A/P'),
    (3.0, 5.5, 'AC', 'Attack\nComplexity', 'L/H'),
    (4.5, 5.5, 'PR', 'Privileges\nRequired', 'N/L/H'),
    (6.0, 5.5, 'UI', 'User\nInteraction', 'N/R'),
    # Impact
    (8.5, 5.5, 'C', 'Confiden-\ntiality', 'H/L/N'),
    (10.0, 5.5, 'I', 'Integrity', 'H/L/N'),
    (11.5, 5.5, 'A', 'Availa-\nbility', 'H/L/N'),
    # Scope
    (14.0, 5.5, 'S', 'Scope', 'C/U'),
]
for x, y, short, long_name, values in base_metrics:
    rounded_box(ax, x, y, 1.3, 1.0, '', C['base'], alpha=0.85,
                border_color='#58a6ff', border_width=1)
    ax.text(x, y + 0.25, short, ha='center', va='center',
            fontsize=12, color=C['text'], fontweight='bold', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.1, long_name, ha='center', va='center',
            fontsize=6, color='#c9d1d9', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.38, values, ha='center', va='center',
            fontsize=5.5, color=C['text_sub'], fontfamily='monospace', zorder=5)

# ============ TEMPORAL METRICS (Optional) ============
temp_y = 3.8
rounded_box(ax, 8.5, temp_y + 0.6, 16, 0.5, '', C['temporal'], alpha=0.15,
            border_color=C['temporal'], border_width=1.5)
ax.text(8.5, temp_y + 0.6, 'TEMPORAL METRICS (Optional)', ha='center', va='center',
        fontsize=13, color=C['temporal'], fontweight='bold', fontfamily='sans-serif', zorder=5)

temp_metrics = [
    (5.0, temp_y - 0.5, 'E', 'Exploit Code\nMaturity', 'X/H/F/P/U'),
    (8.5, temp_y - 0.5, 'RL', 'Remediation\nLevel', 'X/U/W/F/O'),
    (12.0, temp_y - 0.5, 'RC', 'Report\nConfidence', 'X/U/R/C'),
]
for x, y, short, long_name, values in temp_metrics:
    rounded_box(ax, x, y, 1.8, 1.0, '', C['temporal'], alpha=0.85,
                border_color='#e3b341', border_width=1)
    ax.text(x, y + 0.25, short, ha='center', va='center',
            fontsize=12, color=C['text'], fontweight='bold', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.1, long_name, ha='center', va='center',
            fontsize=6, color='#c9d1d9', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.38, values, ha='center', va='center',
            fontsize=5.5, color=C['text_sub'], fontfamily='monospace', zorder=5)

# ============ ENVIRONMENTAL METRICS (Optional) ============
env_y = 1.5
rounded_box(ax, 8.5, env_y + 0.6, 16, 0.5, '', C['env'], alpha=0.15,
            border_color=C['env'], border_width=1.5)
ax.text(8.5, env_y + 0.6, 'ENVIRONMENTAL METRICS (Optional)', ha='center', va='center',
        fontsize=13, color=C['env'], fontweight='bold', fontfamily='sans-serif', zorder=5)

# Requirements sub-group
rounded_box(ax, 3.5, env_y - 0.3, 5.5, 0.5, '', C['env_light'], alpha=0.3,
            border_color=C['env'], border_width=0.8)
ax.text(3.5, env_y - 0.3, 'Requirements', ha='center', va='center',
        fontsize=9, color='#bc8cff', fontweight='bold', fontfamily='sans-serif', zorder=5)

# Modified sub-group
rounded_box(ax, 12.0, env_y - 0.3, 8.5, 0.5, '', C['env_light'], alpha=0.3,
            border_color=C['env'], border_width=0.8)
ax.text(12.0, env_y - 0.3, 'Modified Base Metrics', ha='center', va='center',
        fontsize=9, color='#bc8cff', fontweight='bold', fontfamily='sans-serif', zorder=5)

env_metrics = [
    # Requirements
    (1.5, env_y - 1.2, 'CR', 'Confidentiality\nRequirement', 'X/H/M/L'),
    (3.0, env_y - 1.2, 'IR', 'Integrity\nRequirement', 'X/H/M/L'),
    (4.5, env_y - 1.2, 'AR', 'Availability\nRequirement', 'X/H/M/L'),
    # Modified
    (7.0, env_y - 1.2, 'MAV', 'Modified\nAttack Vector', 'X/N/L/A/P'),
    (8.5, env_y - 1.2, 'MAC', 'Modified\nAttack Complexity', 'X/L/H'),
    (10.0, env_y - 1.2, 'MPR', 'Modified\nPrivileges Req.', 'X/N/L/H'),
    (11.5, env_y - 1.2, 'MUI', 'Modified\nUser Interaction', 'X/N/R'),
    (13.0, env_y - 1.2, 'MS', 'Modified\nScope', 'X/C/U'),
    (14.5, env_y - 1.2, 'MC', 'Modified\nConfidentiality', 'X/H/L/N'),
    (16.0, env_y - 1.2, 'MI', 'Modified\nIntegrity', 'X/H/L/N'),
]
for x, y, short, long_name, values in env_metrics:
    rounded_box(ax, x, y, 1.3, 0.9, '', C['env'], alpha=0.85,
                border_color='#bc8cff', border_width=1)
    ax.text(x, y + 0.2, short, ha='center', va='center',
            fontsize=9, color=C['text'], fontweight='bold', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.1, long_name, ha='center', va='center',
            fontsize=5, color='#c9d1d9', fontfamily='sans-serif', zorder=5)
    ax.text(x, y - 0.35, values, ha='center', va='center',
            fontsize=4.5, color=C['text_sub'], fontfamily='monospace', zorder=5)

plt.tight_layout(pad=0.5)
output_path = '/home/cc11001100/github/scagogogo/cvss-skills/docs/images/vector-structure.png'
fig.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor(), edgecolor='none')
plt.close()
print(f'Vector structure saved to {output_path}')
