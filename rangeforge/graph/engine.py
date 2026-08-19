"""Certification-agnostic attack graph engine."""

from itertools import pairwise, product

import networkx as nx

from rangeforge.models import AccessState, Primitive


class AttackGraphEngine:
    """Construct a state-transition graph entirely from primitive metadata."""

    def __init__(self, primitives: tuple[Primitive, ...]) -> None:
        self.primitives = tuple(sorted(primitives, key=lambda item: item.id))
        self.graph: nx.MultiDiGraph[AccessState] = nx.MultiDiGraph()
        self.graph.add_nodes_from(AccessState)
        for primitive in self.primitives:
            for required_state in primitive.requires.states:
                self.graph.add_edge(
                    required_state,
                    primitive.provides.state,
                    key=primitive.id,
                    primitive=primitive,
                )

    def candidate_paths(
        self,
        start: AccessState,
        objective: AccessState,
        minimum_steps: int,
        maximum_steps: int,
    ) -> tuple[tuple[Primitive, ...], ...]:
        """Return every simple primitive path in a deterministic base order."""
        state_graph = nx.DiGraph(self.graph)
        candidates: list[tuple[Primitive, ...]] = []
        for states in nx.all_simple_paths(state_graph, start, objective, cutoff=maximum_steps):
            step_count = len(states) - 1
            if not minimum_steps <= step_count <= maximum_steps:
                continue
            choices: list[tuple[Primitive, ...]] = []
            for source, target in pairwise(states):
                edge_data = self.graph.get_edge_data(source, target, default={})
                choices.append(
                    tuple(
                        edge["primitive"]
                        for _, edge in sorted(edge_data.items())
                    )
                )
            candidates.extend(tuple(path) for path in product(*choices))
        return tuple(sorted(candidates, key=lambda path: tuple(item.id for item in path)))
