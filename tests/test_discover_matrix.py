#!/usr/bin/env python3
"""Unit tests for discover_matrix.py"""

import re
import unittest
from datetime import date, datetime, timezone
from unittest.mock import patch

from scripts.discover_matrix import (
    generate_release_tag,
    get_boringssl_head_info,
    get_supported_runners,
    parse_available_runners_from_readme,
    parse_brownout_from_issue,
)


class TestDiscoverMatrix(unittest.TestCase):

    def test_generate_release_tag_format(self):
        dt = datetime(2026, 11, 20, 4, 0, tzinfo=timezone.utc)
        self.assertEqual(generate_release_tag(dt), "v1.2026.11.20.0400")

    def test_generate_release_tag_default_now(self):
        tag = generate_release_tag()
        self.assertTrue(re.match(r"^v1\.\d{4}\.\d{2}\.\d{2}\.\d{4}$", tag))

    def test_get_boringssl_head_info(self):
        mock_commit = {
            "sha": "ddd732967025c608598b9984a1ada358fa82f6f0",
            "commit": {"committer": {"date": "2026-11-20T01:39:12Z"}},
        }
        with patch("scripts.discover_matrix.github_api_get", return_value=mock_commit):
            ver, sha = get_boringssl_head_info("main")
            self.assertEqual(ver, "20261120-ddd732967025")
            self.assertEqual(sha, "ddd732967025c608598b9984a1ada358fa82f6f0")

    def test_parse_brownout_from_direct_sentence(self):
        body = "macos-14 was deprecated July 14 and brownouts will begin October 6th, 2026."
        fb, cutoff = parse_brownout_from_issue(body, reference_year=2026)
        self.assertEqual(fb, date(2026, 10, 6))
        self.assertEqual(cutoff, date(2026, 10, 5))

    def test_parse_brownout_from_schedule_list(self):
        body = """
        The brownouts are scheduled for the following dates and times:
        - October 5, 14:00 UTC - October 6, 00:00 UTC
        - October 12, 14:00 UTC - October 13, 00:00 UTC
        """
        fb, cutoff = parse_brownout_from_issue(body, reference_year=2026)
        self.assertEqual(fb, date(2026, 10, 5))
        self.assertEqual(cutoff, date(2026, 10, 4))

    def test_detect_and_exclude_paid_larger_runners(self):
        sample_readme = """
        ## Available Images

        | Image | Architecture | YAML Label | Included Software |
        | --------------------|--------------|---------------------|------------------|
        | macOS 14 | x64 | `macos-14-large` | [macOS-14] |
        | macOS 15 | x64 | `macos-15-large`, or `macos-15-intel` | [macOS-15] |
        | macOS 15 Arm64 | arm64 | `macos-15`, or `macos-15-xlarge` | [macOS-15-arm64] |
        """
        runners = parse_available_runners_from_readme(sample_readme, free_only=True)
        macos14_intel = next(r for r in runners if r["os"] == "macos-14-large")
        self.assertTrue(macos14_intel["paid"])
        self.assertFalse(macos14_intel["active"])

        macos15_intel = next(r for r in runners if r["os"] == "macos-15-intel")
        self.assertFalse(macos15_intel["paid"])
        self.assertTrue(macos15_intel["active"])

    def test_get_supported_runners_raises_on_api_failure(self):
        with patch("scripts.discover_matrix.github_api_get", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                get_supported_runners()
            self.assertIn("Failed to fetch actions/runner-images README", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
