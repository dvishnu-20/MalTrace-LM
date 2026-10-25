"""
Process Graph & Lineage Visualization Module.
Generates responsive interactive SVG / HTML process DAG diagrams
showing parent-child relationships, root nodes, injected processes, and API category indicators.
"""

from typing import Dict, Any, List, Optional
from maltrace.contracts.schemas import ProcessSummary


def generate_process_tree_html(process_summaries: List[ProcessSummary], title: str = "Process Execution Graph") -> str:
    """
    Generate an interactive HTML/SVG process tree graph.
    """
    nodes_html = []
    
    # Calculate simple layout coordinates
    roots = [p for p in process_summaries if p.is_root]
    non_roots = [p for p in process_summaries if not p.is_root]
    
    ordered_procs = roots + non_roots

    y_offset = 30
    for idx, p in enumerate(ordered_procs):
        root_badge = " [ROOT]" if p.is_root else ""
        cats_str = ", ".join(p.categories_observed) if p.categories_observed else "general"
        injected_style = "border-left: 4px solid #ef4444;" if "memory" in p.categories_observed else "border-left: 4px solid #3b82f6;"
        
        nodes_html.append(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; {injected_style} border-radius: 6px; padding: 12px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600; color: #1e293b; font-family: monospace;">PID {p.process_id}: {p.process_name}{root_badge}</span>
                <span style="font-size: 0.8em; background: #f1f5f9; padding: 2px 8px; border-radius: 4px; color: #64748b;">Parent PID: {p.parent_process_id}</span>
            </div>
            <div style="font-size: 0.85em; color: #475569; margin-top: 4px;">
                <b>Lineage:</b> <code>{p.readable_path or p.process_name}</code>
            </div>
            <div style="font-size: 0.8em; color: #64748b; margin-top: 4px;">
                <b>Categories Observed:</b> <span style="color: #0284c7;">{cats_str}</span>
            </div>
        </div>
        """)

    html_content = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin: 16px 0;">
        <h4 style="margin: 0 0 12px 0; color: #0f172a; display: flex; align-items: center; gap: 8px;">
            🌲 {title} ({len(process_summaries)} Processes)
        </h4>
        <div style="max-height: 400px; overflow-y: auto;">
            {''.join(nodes_html) if nodes_html else '<p style="color: #94a3b8;">No process tree data available.</p>'}
        </div>
    </div>
    """
    return html_content
