"""Deterministic graph derived from the Task 10.1 reconnaissance artifact."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class AttackNode:
    """A reconnaissance-derived endpoint and its testable surface metadata."""

    node_id: str
    path: str
    method: str
    primary_category: str
    categories: tuple[str, ...]
    parameters: tuple[str, ...]
    target_params: tuple[str, ...]
    requires_auth: bool
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttackEdge:
    """A directed planning transition between endpoint nodes."""

    source: str
    target: str
    relation: str


@dataclass(frozen=True, slots=True)
class AttackGraph:
    """Immutable attack surface graph; recon labels indicate hypotheses only."""

    nodes: tuple[AttackNode, ...]
    edges: tuple[AttackEdge, ...]
    target_url: str = ""
    spec_source: str = ""

    @classmethod
    def from_file(cls, path: str | Path) -> AttackGraph:
        """Load a serialized ReconReport / attack_surface.json artifact."""
        with Path(path).open(encoding="utf-8") as artifact:
            data = json.load(artifact)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackGraph:
        """Build a stable graph from the public ReconReport dictionary schema."""
        if not isinstance(data, dict) or not isinstance(data.get("endpoints"), list):
            raise ValueError("Attack surface must be an object containing an endpoints list")

        nodes: list[AttackNode] = []
        for index, endpoint in enumerate(data["endpoints"]):
            if not isinstance(endpoint, dict):
                raise ValueError(f"Endpoint at index {index} must be an object")
            path = endpoint.get("path")
            method = endpoint.get("method")
            if not isinstance(path, str) or not path.strip() or not isinstance(method, str):
                raise ValueError(f"Endpoint at index {index} requires non-empty path and method")

            categories = _unique(
                [str(item.get("vuln_type", "")).upper() for item in endpoint.get("potential_vulnerabilities", [])
                 if isinstance(item, dict) and item.get("vuln_type")]
            )
            primary = str(endpoint.get("primary_category") or "GENERAL").upper()
            if primary != "GENERAL" and primary not in categories:
                categories = (primary, *categories)

            parameter_names = [
                str(item["name"])
                for item in endpoint.get("parameters", [])
                if isinstance(item, dict) and item.get("name")
            ]
            body = endpoint.get("request_body") or {}
            parameter_names.extend(
                str(item["name"])
                for item in body.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            )
            targets = [
                str(name)
                for indicator in endpoint.get("potential_vulnerabilities", [])
                if isinstance(indicator, dict)
                for name in indicator.get("target_params", [])
                if name
            ]
            nodes.append(
                AttackNode(
                    node_id=f"{method.upper()}:{path}",
                    path=path,
                    method=method.upper(),
                    primary_category=primary,
                    categories=categories,
                    parameters=_unique(parameter_names),
                    target_params=_unique(targets),
                    requires_auth=bool(endpoint.get("requires_auth", False)),
                    tags=_unique([str(tag) for tag in endpoint.get("tags", []) if tag]),
                )
            )

        if len({node.node_id for node in nodes}) != len(nodes):
            raise ValueError("Attack surface contains duplicate method/path endpoints")

        edges: list[AttackEdge] = []
        for source in nodes:
            for target in nodes:
                if source.node_id == target.node_id:
                    continue
                shared_tags = set(source.tags).intersection(target.tags)
                shared_categories = set(source.categories).intersection(target.categories)
                if shared_tags:
                    edges.append(AttackEdge(source.node_id, target.node_id, "shared_tag"))
                elif shared_categories:
                    edges.append(AttackEdge(source.node_id, target.node_id, "shared_category"))

        # Preserve ReconReport order as an explicit deterministic progression
        # when adjacent endpoints have no tag/category relationship.
        edge_pairs = {(edge.source, edge.target) for edge in edges}
        for source, target in zip(nodes, nodes[1:]):
            if (source.node_id, target.node_id) not in edge_pairs:
                edges.append(AttackEdge(source.node_id, target.node_id, "recon_order"))

        return cls(
            nodes=tuple(nodes),
            edges=tuple(edges),
            target_url=str(data.get("target_url", "")),
            spec_source=str(data.get("spec_source", "")),
        )

    def node(self, node_id: str) -> AttackNode:
        """Return a node by stable id."""
        for item in self.nodes:
            if item.node_id == node_id:
                return item
        raise KeyError(node_id)


def _unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
