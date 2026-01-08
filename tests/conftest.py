from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.context import ScanConfig, ScanContext
from core.dataflow.catalog import load_rules
from core.logging import Logger
from tests.helpers.fakes import FakeAPK, FakeAnalysis


@pytest.fixture
def make_ctx():
    def _make_ctx(
        components,
        methods=None,
        max_depth=0,
        component_filter=None,
        apk=None,
        scan_mode="fast",
        verbose=False,
        rules=None,
    ):
        apk_obj = apk or FakeAPK()
        analysis = FakeAnalysis(methods or [])
        config = ScanConfig(
            scan_mode=scan_mode,
            component_filter=component_filter,
            verbose=verbose,
            max_depth=max_depth,
        )
        ruleset = rules
        if ruleset is None:
            ruleset = load_rules({
                "sources": "rules/sources.yml",
                "sinks": "rules/sinks.yml",
                "sanitizers": "rules/sanitizers.yml",
                "policy": "rules/policy.yml",
            })
        return ScanContext(
            apk_path="fake.apk",
            apk=apk_obj,
            analysis=analysis,
            dex=None,
            components=components,
            config=config,
            rules=ruleset,
            androguard_version="test",
            logger=Logger(verbose=verbose),
        )

    return _make_ctx
