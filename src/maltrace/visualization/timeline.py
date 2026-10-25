"""
Execution Event Timeline Visualizer.
Renders chronological execution sequences, highlighting security anchors,
API transitions, and process switching in HTML/SVG timeline formats.
"""

from typing import List, Dict, Any, Optional
from maltrace.contracts.schemas import NormalizedEvent


CATEGORY_COLORS = {
    "process": "#3b82f6",
    "registry": "#8b5cf6",
    "file": "#eab308",
    "network": "#ef4444",
    "service": "#10b981",
    "memory": "#ec4899",
    "synchronization": "#6b7280",
    "other": "#94a3b8"
}


def generate_event_timeline_html(events: List[NormalizedEvent], title: str = "Execution Event Timeline") -> str:
    """
    Generate an HTML/CSS chronological event timeline.
    """
    items_html = []

    for ev in events[:50]:  # Cap at top 50 for clean visual rendering
        cat_color = CATEGORY_COLORS.get(ev.category.lower(), "#64748b")
        anchor_badge = " <span style='background: #fee2e2; color: #991b1b; font-size: 0.75em; padding: 2px 6px; border-radius: 4px; font-weight: bold;'>ANCHOR</span>" if ev.is_persistence else ""
        
        args_snippet = str(ev.safe_arguments)[:100] if ev.safe_arguments else ""
        
        items_html.append(f"""
        <div style="display: flex; gap: 12px; margin-bottom: 8px; align-items: baseline;">
            <div style="min-width: 40px; font-family: monospace; font-size: 0.8em; color: #64748b;">#{ev.event_order}</div>
            <div style="min-width: 80px;">
                <span style="background: {cat_color}; color: #ffffff; font-size: 0.75em; padding: 2px 6px; border-radius: 4px; font-weight: 500; text-transform: uppercase;">
                    {ev.category}
                </span>
            </div>
            <div style="flex-grow: 1; font-size: 0.85em; font-family: monospace;">
                <b style="color: #1e293b;">{ev.api_name}</b>{anchor_badge}
                <span style="color: #64748b; margin-left: 6px;">PID {ev.process_id}</span>
                <div style="color: #475569; font-size: 0.9em; word-break: break-all; margin-top: 2px;">{args_snippet}</div>
            </div>
        </div>
        """)

    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin: 16px 0;">
        <h4 style="margin: 0 0 12px 0; color: #0f172a;">⏱️ {title} ({len(events)} Total Events)</h4>
        <div style="max-height: 400px; overflow-y: auto; padding-right: 8px;">
            {''.join(items_html) if items_html else '<p style="color: #94a3b8;">No events to display in timeline.</p>'}
        </div>
    </div>
    """
    return html
