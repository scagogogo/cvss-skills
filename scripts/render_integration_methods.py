#!/usr/bin/env python3
"""Render integration methods comparison diagram."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np

C = {
    'bg': '#0d1117',
    'text': '#f0f6fc',
    'text_sub': '#8b949e',
    'line': '#30363d',
    'skill': '#8957e5',
    'sdk': '#1f6feb',
    'cli': '#f78166',
    'mcp': '#3fb950',
    'card': '#161b22',
}

def card(ax, x, y, w, h, title, color, items, icon_text=''):
    """Draw a feature card."""
    # Card background
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle="round,pad=0.05",
        facecolor=C['card'], edgecolor=color,
        linewidth=2, alpha=0.95, zorder=3
    )
    ax.add_patch(box)

    # Color header strip
    header_h = 0.6
    header = FancyBboxPatch(
        (x - w/2 + 0.05, y + h/2 - header_h - 0.05), w - 0.1, header_h,
        boxstyle="round,pad=0.02",
        facecolor=color, edgecolor='none', alpha=0.9, zorder=4
    )
    ax.add_patch(header)

    # Title
    ax.text(x, y + h/2 - header_h/2 - 0.05, title, ha='center', va='center',
            fontsize=14, color=C['text'], fontweight='bold', fontfamily='sans-serif', zorder=5)

    # Items
    item_y = y + h/2 - header_h - 0.4
    for item in items:
        ax.text(x - w/2 + 0.3, item_y, item, ha='left', va='center',
                fontsize=8, color=C['text_sub'], fontfamily='sans-serif', zorder=5)
        # Bullet
        ax.plot(x - w/2 + 0.15, item_y, 'o', color=color, markersize=3, zorder=5)
        item_y -= 0.35

fig, ax = plt.subplots(1, 1, figsize=(20, 8))
fig.patch.set_facecolor(C['bg'])
ax.set_facecolor(C['bg'])
ax.set_xlim(-0.5, 19.5)
ax.set_ylim(-0.5, 7.5)
ax.axis('off')

# Title
ax.text(9.5, 7.0, '4 Ways to Integrate CVSS Skills', ha='center', va='center',
        fontsize=22, color=C['text'], fontweight='bold', fontfamily='sans-serif')
ax.text(9.5, 6.5, 'Choose the integration method that fits your workflow',
        ha='center', va='center', fontsize=12, color=C['text_sub'], fontfamily='sans-serif')

# Cards
card_w = 4.2
card_h = 5.0
card_y = 3.2
cards_data = [
    (2.5, card_y, card_w, card_h, 'Skills', C['skill'], [
        'Claude Code integration',
        '9 built-in CVSS skills',
        'Natural language interface',
        'One-line installation',
        'Interactive analysis',
        'No code required',
    ]),
    (7.0, card_y, card_w, card_h, 'Go SDK', C['sdk'], [
        'Full-featured Go library',
        'Type-safe API',
        'Builder pattern',
        'Parse, score, validate',
        'Diff, merge, distance',
        'JSON serialization',
    ]),
    (11.5, card_y, card_w, card_h, 'CLI', C['cli'], [
        '30+ commands',
        'Scriptable & automatable',
        'JSON/CSV output',
        'Batch processing',
        'Preset vectors',
        'Cross-platform binary',
    ]),
    (16.0, card_y, card_w, card_h, 'MCP', C['mcp'], [
        'Model Context Protocol',
        'Any MCP client',
        'Tool-based interface',
        'Standard protocol',
        'AI agent integration',
        'GitHub-hosted server',
    ]),
]

for x, y, w, h, title, color, items in cards_data:
    card(ax, x, y, w, h, title, color, items)

# Bottom: Quick start commands
cmd_y = 0.3
commands = [
    (2.5, 'claude mcp add cvss-skills', C['skill']),
    (7.0, 'go get github.com/scagogogo/cvss-skills', C['sdk']),
    (11.5, 'cvss score "CVSS:3.1/AV:N/..."', C['cli']),
    (16.0, 'Connect via MCP protocol', C['mcp']),
]
for x, cmd, color in commands:
    rounded_box = FancyBboxPatch(
        (x - 2.0, cmd_y - 0.2), 4.0, 0.4,
        boxstyle="round,pad=0.03",
        facecolor='#0d1117', edgecolor=color,
        linewidth=1, alpha=0.9, zorder=3
    )
    ax.add_patch(rounded_box)
    ax.text(x, cmd_y, cmd, ha='center', va='center',
            fontsize=7, color=color, fontfamily='monospace', zorder=4)

plt.tight_layout(pad=0.5)
output_path = '/home/cc11001100/github/scagogogo/cvss-skills/docs/images/integration-methods.png'
fig.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor(), edgecolor='none')
plt.close()
print(f'Integration methods saved to {output_path}')
