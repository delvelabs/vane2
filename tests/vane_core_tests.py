from unittest import TestCase
from unittest.mock import MagicMock
from src.vane_core import Vane


class TestVane(TestCase):

    def test_perform_action_raise_exception_if_no_url(self):
        vane = Vane()

        self.assertRaises(ValueError, vane.perfom_action)
