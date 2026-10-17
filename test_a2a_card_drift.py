"""Tests for a2a-card-drift — deterministic, no network."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import a2a_card_drift as cd


def card(pv="0.3.0", **kw):
    c = {"name": "x", "protocolVersion": pv, "preferredTransport": "JSONRPC"}
    c.update(kw)
    return c


class CheckTests(unittest.TestCase):
    def test_clean_03(self):
        self.assertEqual(cd.check_card(card()), [])

    def test_missing_version(self):
        c = card(); del c["protocolVersion"]
        sev, msg = cd.check_card(c)[0]
        self.assertEqual(sev, "critical")
        self.assertIn("missing", msg)

    def test_mcp_date_version(self):
        findings = cd.check_card(card(pv="2025-06-18"))
        self.assertEqual(findings[0][0], "critical")
        self.assertIn("MCP", findings[0][1])

    def test_garbage_version(self):
        findings = cd.check_card(card(pv="9.2.9"))
        self.assertEqual(findings[0][0], "critical")

    def test_v10_without_supported_interfaces(self):
        c = card(pv="1.0", url="https://x/y", preferredTransport="JSONRPC")
        findings = cd.check_card(c)
        self.assertTrue(any("pre-1.0 shape" in m for _, m in findings))

    def test_interface_version_mismatch(self):
        c = card(pv="1.0", supportedInterfaces=[
            {"url": "https://x", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}])
        findings = cd.check_card(c)
        self.assertTrue(any("LiteLLM#30795" in m for _, m in findings))

    def test_interface_drops_version(self):
        c = card(pv="1.0", supportedInterfaces=[{"url": "https://x", "protocolBinding": "JSONRPC"}])
        findings = cd.check_card(c)
        self.assertTrue(any("drops protocolVersion" in m for _, m in findings))

    def test_interface_mcp_date(self):
        c = card(pv="1.0", supportedInterfaces=[
            {"url": "https://x", "protocolBinding": "JSONRPC", "protocolVersion": "2026-07-28"}])
        self.assertTrue(any("MCP date" in m for _, m in cd.check_card(c)))

    def test_bad_security_scheme(self):
        c = card(securitySchemes={"a": {"type": "bearer-token-magic"}})
        findings = cd.check_card(c)
        self.assertTrue(any("not an OpenAPI type" in m for _, m in findings))

    def test_not_object(self):
        self.assertEqual(cd.check_card([1])[0][0], "critical")


class DiffTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(cd.diff_cards(card(), card()), [])

    def test_top_level_version_bump(self):
        findings = cd.diff_cards(card(pv="0.3"), card(pv="1.0"))
        self.assertEqual(findings[0][0], "critical")
        self.assertIn("Apicurio#9455", findings[0][1])

    def test_interface_version_bump(self):
        old = card(supportedInterfaces=[{"url": "u", "protocolBinding": "b", "protocolVersion": "0.3"}])
        new = card(supportedInterfaces=[{"url": "u", "protocolBinding": "b", "protocolVersion": "1.0"}])
        findings = cd.diff_cards(old, new)
        self.assertTrue(any("protocolVersion '0.3' -> '1.0'" in m for _, m in findings))

    def test_interface_dropped_version(self):
        old = card(supportedInterfaces=[{"url": "u", "protocolBinding": "b", "protocolVersion": "0.3"}])
        new = card(supportedInterfaces=[{"url": "u", "protocolBinding": "b"}])
        findings = cd.diff_cards(old, new)
        self.assertTrue(any("dropped protocolVersion" in m for _, m in findings))

    def test_interface_removed(self):
        old = card(supportedInterfaces=[{"url": "u", "protocolBinding": "b"}])
        new = card(pv="0.3.0")
        findings = cd.diff_cards(old, new)
        self.assertTrue(any("removed" in m for _, m in findings))

    def test_security_scheme_drift(self):
        old = card(securitySchemes={"b": {"type": "http", "scheme": "bearer"}})
        new = card(securitySchemes={"b": {"type": "apiKey", "name": "k", "in": "header"}})
        findings = cd.diff_cards(old, new)
        self.assertTrue(any("securitySchemes['b']" in m for _, m in findings))
        self.assertEqual(findings[0][0], "critical")

    def test_capability_flip(self):
        findings = cd.diff_cards(card(capabilities={"streaming": True}),
                                 card(capabilities={"streaming": False}))
        self.assertTrue(any("flipped off" in m for _, m in findings))
        self.assertEqual(findings[0][0], "warning")

    def test_not_object(self):
        self.assertEqual(cd.diff_cards(None, {})[0][0], "critical")


class CliTests(unittest.TestCase):
    def _write(self, obj):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_card.json")
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def _write2(self, obj):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_card2.json")
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def test_cli_check_clean_exit0(self):
        p = self._write(card())
        try:
            self.assertEqual(cd.main(["check", p]), 0)
        finally:
            os.remove(p)

    def test_cli_check_critical_exit2(self):
        p = self._write(card(pv="2025-06-18"))
        try:
            self.assertEqual(cd.main(["check", p]), 2)
        finally:
            os.remove(p)

    def test_cli_diff_exit2(self):
        a, b = self._write(card(pv="0.3")), self._write2(card(pv="1.0"))
        try:
            self.assertEqual(cd.main(["diff", a, b]), 2)
        finally:
            os.remove(a); os.remove(b)

    def test_cli_bad_usage(self):
        self.assertEqual(cd.main(["wat"]), 2)

    def test_cli_missing_file(self):
        with self.assertRaises(SystemExit):
            cd.main(["check", "/nope.json"])


if __name__ == "__main__":
    unittest.main()
