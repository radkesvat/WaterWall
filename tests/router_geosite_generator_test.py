#!/usr/bin/env python3
"""Check GeoSite generator normalization using local source-list fixtures.

Exercises parsing, deduplication and JSON generation for literal keyword dots
and normalized full/root domains. No downloaded domain database is required.
Run: python3 tests/router_geosite_generator_test.py
CTest: waterwall.router_geosite_generator_unit
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
GENERATOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "tunnels/Router/geosite_ww_style_generator/generate.py"
)
SPEC = importlib.util.spec_from_file_location("router_geosite_generator", GENERATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
generator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)


class GeositeGeneratorTest(unittest.TestCase):
    def generate_domains(self, source: str) -> list[dict]:
        with tempfile.TemporaryDirectory(prefix="waterwall-geosite-generator-") as directory:
            data_dir = Path(directory)
            (data_dir / "example").write_text(source, encoding="utf-8")
            raw = generator.read_raw_lists(data_dir)
            output = generator.generate_json_data(generator.resolve_lists(raw))
            return output["lists"][0]["domains"]

    def test_keyword_trailing_dot_remains_distinct(self) -> None:
        domains = self.generate_domains("keyword:GOOGLE.\nkeyword:google\n")
        self.assertEqual(
            {(rule["type"], rule["value"]) for rule in domains},
            {("plain", "google."), ("plain", "google")},
        )

    def test_punctuation_only_keyword_survives(self) -> None:
        domains = self.generate_domains("keyword:.\n")
        self.assertEqual(domains, [{"type": "plain", "value": ".", "attributes": []}])

    def test_full_and_root_domains_normalize_trailing_dot(self) -> None:
        domains = self.generate_domains("domain:EXAMPLE.COM.\nfull:HOST.EXAMPLE.COM.\n")
        self.assertEqual(
            {(rule["type"], rule["value"]) for rule in domains},
            {("domain", "example.com"), ("full", "host.example.com")},
        )


if __name__ == "__main__":
    unittest.main()
