from __future__ import annotations

from typing import Tuple

from androguard.misc import AnalyzeAPK


def load_apk(apk_path: str) -> Tuple[object, object, object]:
    apk, dex, analysis = AnalyzeAPK(apk_path)
    return apk, dex, analysis
