"""Round-robin balancer over a pool of Cloudflare-proxied fallback domains."""
from __future__ import annotations

import random
from collections import Counter
from typing import Dict, Iterator, List

from .constants import DC_IDS


class DomainBalancer:
    """Maps each DC to a 'current' domain, rotating on demand."""

    def __init__(self) -> None:
        self.domains: List[str] = []
        self._active: Dict[int, str] = {}

    def update_pool(self, domains: List[str]) -> None:
        if Counter(self.domains) == Counter(domains):
            return
        self.domains = list(domains)
        self._active = {dc: random.choice(self.domains) for dc in DC_IDS}

    def promote(self, dc_id: int, domain: str) -> bool:
        """Pin `domain` as the preferred one for `dc_id`. Returns True if it changed."""
        if self._active.get(dc_id) == domain:
            return False
        self._active[dc_id] = domain
        return True

    def candidates_for(self, dc_id: int) -> Iterator[str]:
        """Yield active first, then the rest in random order."""
        active = self._active.get(dc_id)
        if active is not None:
            yield active
        shuffled = list(self.domains)
        random.shuffle(shuffled)
        for domain in shuffled:
            if domain != active:
                yield domain


balancer = DomainBalancer()
