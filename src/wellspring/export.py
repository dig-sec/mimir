"""Export helpers — CSV (zipped), GraphML, plain JSON, Markdown report."""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List

from .schemas import Subgraph, SubgraphNode

# ── CSV (two CSVs in a ZIP) ──────────────────────────────────────────────


def export_csv_zip(subgraph: Subgraph) -> bytes:
    """Return a ZIP archive containing entities.csv and relations.csv."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # entities.csv
        ent_io = io.StringIO()
        ew = csv.writer(ent_io)
        ew.writerow(["id", "name", "type"])
        for n in sorted(subgraph.nodes, key=lambda n: n.name.lower()):
            ew.writerow([n.id, n.name, n.type or ""])
        zf.writestr("entities.csv", ent_io.getvalue())

        # relations.csv
        rel_io = io.StringIO()
        rw = csv.writer(rel_io)
        rw.writerow(
            [
                "id",
                "source_id",
                "source_name",
                "predicate",
                "target_id",
                "target_name",
                "confidence",
            ]
        )
        name_map = {n.id: n.name for n in subgraph.nodes}
        for e in sorted(subgraph.edges, key=lambda e: e.predicate):
            rw.writerow(
                [
                    e.id,
                    e.subject_id,
                    name_map.get(e.subject_id, e.subject_id),
                    e.predicate,
                    e.object_id,
                    name_map.get(e.object_id, e.object_id),
                    f"{e.confidence:.2f}",
                ]
            )
        zf.writestr("relations.csv", rel_io.getvalue())

    return buf.getvalue()


# ── GraphML ──────────────────────────────────────────────────────────────

_GRAPHML_NS = "http://graphml.graphstruct.org/xmlns"


def export_graphml(subgraph: Subgraph) -> str:
    """Return a GraphML XML string compatible with Gephi / Cytoscape / yEd."""
    root = ET.Element("graphml", xmlns=_GRAPHML_NS)

    # attribute declarations
    ET.SubElement(
        root,
        "key",
        id="label",
        attrib={"for": "node", "attr.name": "label", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="type",
        attrib={"for": "node", "attr.name": "type", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="predicate",
        attrib={"for": "edge", "attr.name": "predicate", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="confidence",
        attrib={"for": "edge", "attr.name": "confidence", "attr.type": "double"},
    )

    graph = ET.SubElement(root, "graph", id="G", edgedefault="directed")

    for n in subgraph.nodes:
        node_el = ET.SubElement(graph, "node", id=n.id)
        d_label = ET.SubElement(node_el, "data", key="label")
        d_label.text = n.name
        d_type = ET.SubElement(node_el, "data", key="type")
        d_type.text = n.type or ""

    for e in subgraph.edges:
        edge_el = ET.SubElement(
            graph, "edge", id=e.id, source=e.subject_id, target=e.object_id
        )
        d_pred = ET.SubElement(edge_el, "data", key="predicate")
        d_pred.text = e.predicate
        d_conf = ET.SubElement(edge_el, "data", key="confidence")
        d_conf.text = f"{e.confidence:.4f}"

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


# ── Plain JSON knowledge-graph ───────────────────────────────────────────


def export_json(subgraph: Subgraph) -> Dict[str, Any]:
    """Return a self-contained JSON-friendly dict of the knowledge graph."""
    name_map = {n.id: n.name for n in subgraph.nodes}
    return {
        "meta": {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "tool": "Wellspring",
            "entity_count": len(subgraph.nodes),
            "relation_count": len(subgraph.edges),
        },
        "entities": [
            {"id": n.id, "name": n.name, "type": n.type}
            for n in sorted(subgraph.nodes, key=lambda n: n.name.lower())
        ],
        "relations": [
            {
                "id": e.id,
                "source": {"id": e.subject_id, "name": name_map.get(e.subject_id, "")},
                "predicate": e.predicate,
                "target": {"id": e.object_id, "name": name_map.get(e.object_id, "")},
                "confidence": round(e.confidence, 4),
            }
            for e in subgraph.edges
        ],
    }


# ── Markdown report ──────────────────────────────────────────────────────


def export_markdown(subgraph: Subgraph) -> str:
    """Return a human-readable Markdown report of the knowledge graph."""
    name_map = {n.id: n.name for n in subgraph.nodes}
    lines: List[str] = []
    lines.append("# Wellspring — Knowledge Graph Export")
    lines.append("")
    lines.append(
        f"**Exported:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    lines.append(f"**Entities:** {len(subgraph.nodes)}  ")
    lines.append(f"**Relations:** {len(subgraph.edges)}")
    lines.append("")

    # Group entities by type
    by_type: Dict[str, List[SubgraphNode]] = {}
    for n in subgraph.nodes:
        t = n.type or "unknown"
        by_type.setdefault(t, []).append(n)

    lines.append("## Entities")
    lines.append("")
    for t in sorted(by_type):
        nodes = sorted(by_type[t], key=lambda n: n.name.lower())
        lines.append(f"### {t.replace('_', ' ').title()} ({len(nodes)})")
        lines.append("")
        for n in nodes:
            lines.append(f"- {n.name}")
        lines.append("")

    # Relations table
    lines.append("## Relations")
    lines.append("")
    lines.append("| Source | Predicate | Target | Confidence |")
    lines.append("|--------|-----------|--------|------------|")
    for e in sorted(
        subgraph.edges, key=lambda e: (e.predicate, name_map.get(e.subject_id, ""))
    ):
        src = name_map.get(e.subject_id, e.subject_id)
        tgt = name_map.get(e.object_id, e.object_id)
        lines.append(f"| {src} | {e.predicate} | {tgt} | {e.confidence:.2f} |")
    lines.append("")

    return "\n".join(lines)
