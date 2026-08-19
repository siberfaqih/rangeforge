"""The single source of pseudorandomness for scenario generation."""

import random
from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


class ScenarioRandomizer:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def choice(self, values: Sequence[T]) -> T:
        if not values:
            raise ValueError("Cannot choose from an empty sequence")
        return self.rng.choice(values)

    def randint(self, start: int, end: int) -> int:
        return self.rng.randint(start, end)

