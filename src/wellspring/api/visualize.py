from __future__ import annotations

import json
from typing import Optional

from ..schemas import Subgraph


def render_html(subgraph: Subgraph, title: Optional[str] = None) -> str:
    payload = {
        "nodes": [node.model_dump() for node in subgraph.nodes],
        "links": [
            {
                "id": edge.id,
                "source": edge.subject_id,
                "target": edge.object_id,
                "predicate": edge.predicate,
                "confidence": edge.confidence,
                "origin": edge.attrs.get("origin"),
            }
            for edge in subgraph.edges
        ],
    }
    title = title or "Wellspring Graph"
    data_json = json.dumps(payload)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #f4f2ec;
      --ink: #1c1c1c;
      --accent: #2563eb;
      --muted: #6b7280;
    }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #ffffff 0%, #f4f2ec 55%, #efe8dc 100%);
      color: var(--ink);
    }}
    header {{
      padding: 20px 28px;
      border-bottom: 1px solid rgba(0,0,0,0.08);
      background: rgba(255,255,255,0.85);
      backdrop-filter: blur(6px);
    }}
    h1 {{
      font-size: 20px;
      letter-spacing: 0.02em;
      margin: 0 0 6px 0;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }}
    #graph {{
      width: 100vw;
      height: calc(100vh - 86px);
    }}
    .link {{
      stroke: #9ca3af;
      stroke-opacity: 0.7;
    }}
    .link.inferred {{
      stroke-dasharray: 6 4;
      stroke: #64748b;
    }}
    .link.cooccurrence {{
      stroke-dasharray: 3 3;
      stroke: #9aa3af;
      stroke-opacity: 0.5;
    }}
    .node circle {{
      fill: var(--accent);
      stroke: #1e293b;
      stroke-width: 1px;
    }}
    .label {{
      font-size: 12px;
      pointer-events: none;
    }}
    .edge-label {{
      font-size: 10px;
      fill: #374151;
      pointer-events: none;
    }}
  </style>
</head>
<body>
  <header>
    <h1>{title}</h1>
    <p>Drag nodes to explore. Zoom with scroll.</p>
  </header>
  <svg id="graph"></svg>

  <script src="static/vendor/d3.v7.min.js"></script>
  <script>
    const data = {data_json};
    const width = window.innerWidth;
    const height = window.innerHeight - 86;
    const svg = d3.select('#graph')
      .attr('width', width)
      .attr('height', height)
      .call(d3.zoom().on('zoom', (event) => {{
        g.attr('transform', event.transform);
      }}));

    const g = svg.append('g');

    const link = g.selectAll('.link')
      .data(data.links)
      .enter().append('line')
      .attr('class', d => {{
        if (d.origin === 'inferred') return 'link inferred';
        if (d.origin === 'cooccurrence') return 'link cooccurrence';
        return 'link';
      }});

    const node = g.selectAll('.node')
      .data(data.nodes)
      .enter().append('g')
      .attr('class', 'node')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

    node.append('circle')
      .attr('r', 14);

    node.append('text')
      .attr('class', 'label')
      .attr('x', 18)
      .attr('y', 4)
      .text(d => d.name);

    const edgeLabel = g.selectAll('.edge-label')
      .data(data.links)
      .enter().append('text')
      .attr('class', 'edge-label')
      .text(d => d.predicate);

    const simulation = d3.forceSimulation(data.nodes)
      .force('link', d3.forceLink(data.links).id(d => d.id).distance(140))
      .force('charge', d3.forceManyBody().strength(-320))
      .force('center', d3.forceCenter(width / 2, height / 2));

    simulation.on('tick', () => {{
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);

      edgeLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2);
    }});

    function dragstarted(event) {{
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }}

    function dragged(event) {{
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }}

    function dragended(event) {{
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }}

    window.addEventListener('resize', () => {{
      const newWidth = window.innerWidth;
      const newHeight = window.innerHeight - 86;
      svg.attr('width', newWidth).attr('height', newHeight);
      simulation.force('center', d3.forceCenter(newWidth / 2, newHeight / 2));
      simulation.alpha(0.3).restart();
    }});
  </script>
</body>
</html>"""
