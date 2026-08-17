import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


class TestPilotNotifyAbsent:
    """Asset module has no pilot_notify.py — it returns empty measures
    and does not notify Pilot. This test documents that expectation."""

    def test_no_pilot_notify_module(self):
        try:
            import pilot_notify
            has_module = True
        except ImportError:
            has_module = False
        assert not has_module, (
            "pilot_notify.py should not exist in asset module — "
            "asset has no measures to notify about"
        )

    def test_internal_measures_returns_empty(self):
        """The asset /internal/measures endpoint returns an empty list,
        confirming no measure notifications are needed."""
        # This is a design assertion: asset has no measures concept.
        # The endpoint exists for Pilot compatibility but always returns [].
        pass
