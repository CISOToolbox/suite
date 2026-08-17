"""Unit tests for the name-normalization key used by name-based SI matching
(reviews._norm_name).

Contract: 'lastname|firstname', accent-stripped, lower-cased,
whitespace-collapsed; empty when either part is missing (never match on a
half-identity).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes.reviews import _norm_name  # noqa: E402


class TestNormName:
    def test_basic(self):
        assert _norm_name("Vasseur", "Camille") == "vasseur|camille"

    def test_accents_and_case(self):
        assert _norm_name("BÉNÉDICTE", "Élodie") == "benedicte|elodie"

    def test_whitespace_collapsed(self):
        assert _norm_name("  Le  Goff ", " Jean  Marie ") == "le goff|jean marie"

    def test_missing_part_is_empty(self):
        assert _norm_name("Vasseur", "") == ""
        assert _norm_name("", "Camille") == ""
        assert _norm_name("", "") == ""

    def test_two_people_same_name_same_key(self):
        # Same normalized key -> the caller treats it as ambiguous and skips.
        assert _norm_name("Martin", "Jean") == _norm_name("MARTIN", "jean")
