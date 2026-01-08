from __future__ import annotations

from typing import List

from core.context import ScanContext
from core.ir import Finding


class BaseScanner:
    name = "base"

    def run(self, ctx: ScanContext) -> List[Finding]:
        raise NotImplementedError
