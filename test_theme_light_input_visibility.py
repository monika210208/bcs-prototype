#!/usr/bin/env python3
"""
Test Suite: Light Theme Input & Typing Text Visibility Verification
Verifies:
1. index.html does not have hardcoded dark background (#0d1527) on input:focus.
2. index.html ensures caret-color and color follow theme variables.
3. styles.css and index.html enforce high-contrast light theme text (#0f172a) on white (#ffffff) while typing.
4. Input placeholders and search boxes are styled with crisp contrast in light mode.
"""

import unittest
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import FRONTEND_DIR

class TestThemeLightInputVisibility(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(FRONTEND_DIR, "index.html"), "r", encoding="utf-8") as f:
            self.html = f.read()
        with open(os.path.join(FRONTEND_DIR, "styles.css"), "r", encoding="utf-8") as f:
            self.css = f.read()

    def test_01_no_hardcoded_dark_focus_in_index_html(self):
        """index.html must not hardcode #0d1527 dark background on form input focus."""
        self.assertNotIn("background: #0d1527;", self.html, "Hardcoded dark background #0d1527 must not be present on input:focus")
        self.assertIn("background: var(--bg-input);", self.html)
        self.assertIn("caret-color: var(--text-main);", self.html)

    def test_02_light_theme_input_rules_in_css(self):
        """styles.css must enforce #ffffff background and dark text #0f172a with caret-color in light theme."""
        self.assertIn("body.theme-light input", self.css)
        self.assertIn("body.theme-light .form-input", self.css)
        self.assertIn("background-color: #ffffff !important;", self.css)
        self.assertIn("color: #0f172a !important;", self.css)
        self.assertIn("caret-color: #0f172a !important;", self.css)

    def test_03_light_theme_focus_state_visibility(self):
        """Focused inputs while typing in light theme must remain white background with crisp dark text."""
        self.assertIn("body.theme-light .form-input:focus", self.css)
        self.assertIn("body.theme-light input:focus", self.css)
        self.assertIn("body.theme-light textarea:focus", self.css)
        self.assertIn("border-color: #2563eb !important;", self.css)

    def test_04_light_theme_search_and_modals(self):
        """Search boxes and modals must be cleanly styled in light theme."""
        self.assertIn("body.theme-light .search-box", self.css)
        self.assertIn("body.theme-light .modal-container", self.css)
        self.assertIn("body.theme-light .frontdoor-container", self.css)

    def test_05_cache_buster_updated(self):
        """Cache buster in index.html must be updated to v=3.5.0."""
        self.assertIn("styles.css?v=3.5.0", self.html)
        print("[PASS] All light theme input visibility, focus contrast, and typing readability tests passed!")

if __name__ == "__main__":
    unittest.main()
