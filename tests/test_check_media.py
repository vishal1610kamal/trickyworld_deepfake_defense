"""Tests for check_media.py (skipped when c2pa-python isn't installed). Run: python3 -m unittest -v"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import check_media as cm  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def f(name):
    return os.path.join(FIX, name)


@unittest.skipIf(cm.c2pa is None, "pip install c2pa-python to run these tests")
class CheckMedia(unittest.TestCase):
    def summary(self, name, trust="none"):
        context, label = cm.load_trust(trust)
        return cm.summarize(f(name), cm.read_store(f(name), context), label)

    def test_ai_image_is_reported_as_ai(self):
        s = self.summary("ai-generated.jpg")
        self.assertEqual(s["integrity"], "OK")
        self.assertEqual(s["origin"], ["Created using generative AI"])
        self.assertIn("generative AI", s["verdict"])

    def test_changed_pixels_break_the_credentials(self):
        s = self.summary("ai-generated-tampered.jpg")
        self.assertEqual(s["integrity"], "FAILED")
        self.assertTrue(any(p.startswith("assertion.dataHash.mismatch") for p in s["problems"]))

    def test_resaving_strips_the_credentials(self):
        self.assertFalse(self.summary("ai-generated-resaved.jpg")["credentials"])
        self.assertFalse(self.summary("no-credentials.jpg")["credentials"])

    def test_capture_claim_needs_a_trusted_signer(self):
        self.assertIn("unproven", self.summary("camera-capture.jpg")["verdict"])
        trusted = self.summary("camera-capture.jpg", trust=f("c2pa-test-intermediate-ca.pem"))
        self.assertEqual(trusted["validation_state"], "Trusted")
        self.assertIn("trusted device", trusted["verdict"])

    def test_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cm.main(["--trust", "none", f("ai-generated.jpg")]), 0)
            self.assertEqual(cm.main(["--trust", "none", f("no-credentials.jpg")]), 2)
            self.assertEqual(cm.main(["--trust", "none", f("no-credentials.jpg"),
                                      f("ai-generated-tampered.jpg")]), 1)


if __name__ == "__main__":
    unittest.main()
