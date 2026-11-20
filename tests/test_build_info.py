#!/usr/bin/env python3
"""Unit tests for build_info.py"""

import json
import os
import shutil
import tempfile
import unittest

from scripts.build_info import (
    format_build_summary,
    get_boringssl_info,
    get_or_create_summary,
)


class TestBuildInfo(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_format_build_summary_complete(self):
        py_info = {
            "version": "3.15.2",
            "build_tag": "3.15.2 (main, Nov 2026) [Clang 21.0.0]",
            "compiler": "Clang 21.0.0",
            "cc": "clang",
            "architecture": "arm64",
            "bitness": "64-bit",
            "ssl_version": "BoringSSL",
            "config_args": "--enable-optimizations --with-lto",
            "cflags": "-O3 -Wall",
            "ldflags": "-Wl,-rpath,@executable_path/../lib",
            "openssl_libs": "-lssl -lcrypto -lc++",
        }
        bssl_info = {
            "version": "20261119-ddd732967025",
            "commit_sha": "ddd732967025c608598b9984a1ada358fa82f6f0",
            "commit_date": "2026-11-19T17:39:12-08:00",
            "api_version": "45",
            "build_type": "Release (static, PIC, BUILD_TESTING=OFF)",
            "platform": "Darwin (arm64)",
            "compiler": "cc",
        }

        summary = format_build_summary(
            py_info=py_info,
            bssl_info=bssl_info,
            runner_label="macos-15",
            runner_arch="arm64",
            commit_sha="abcdef123456",
        )

        self.assertIn("Python + BoringSSL Build Configuration & Compiler Flags Summary", summary)
        self.assertIn("Python Version:      3.15.2", summary)
        self.assertIn("BoringSSL Version:   20261119-ddd732967025", summary)
        self.assertIn("BORINGSSL_API_VER:   45", summary)
        self.assertIn("TLS 1.2+ floor", summary)
        self.assertIn("Target Platform:     macos-15 (arm64)", summary)

    def test_get_boringssl_info_from_metadata(self):
        meta = {
            "version": "20261119-ddd732967025",
            "commit_sha": "ddd732967025c608598b9984a1ada358fa82f6f0",
            "api_version": "45",
            "platform": "Linux (x64)",
        }
        with open(os.path.join(self.temp_dir, "BORINGSSL_METADATA.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f)

        info = get_boringssl_info(ssl_root=self.temp_dir)
        self.assertEqual(info["version"], "20261119-ddd732967025")
        self.assertEqual(info["api_version"], "45")

    def test_get_or_create_summary_generates_and_caches(self):
        summary = get_or_create_summary(
            install_dir=self.temp_dir,
            runner_label="ubuntu-24.04",
            runner_arch="x64",
            commit_sha="commit123",
        )
        self.assertIn("Python + BoringSSL Build Configuration & Compiler Flags Summary", summary)
        self.assertTrue(os.path.isfile(os.path.join(self.temp_dir, "BUILD_INFO.txt")))


if __name__ == "__main__":
    unittest.main()
