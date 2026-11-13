"""Tests for callcode.py. Run from the project folder: python3 -m unittest -v"""
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import callcode as cc  # noqa: E402

T0 = 1_800_000_000.0   # a fixed clock for the tests


class Vectors(unittest.TestCase):
    def test_rfc6238(self):
        for t, *want in cc.RFC6238:
            for alg, code in zip(("SHA1", "SHA256", "SHA512"), want):
                self.assertEqual(cc.totp(cc.SEEDS[alg], t, 8, 30, alg), code, (t, alg))

    def test_rfc4226(self):
        for counter, code in enumerate(cc.RFC4226):
            self.assertEqual(cc.hotp(cc.SEEDS["SHA1"], counter), code)

    def test_base32_as_apps_show_it(self):
        self.assertEqual(cc.b32decode("gezd gnbv gy3t qojq"), b"1234567890")


class Flow(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "store.json")
        self.store = cc.Store(self.path)
        self.secret, self.uri = cc.enroll(self.store, "CFO", "Callback check", T0)
        self.key = cc.b32decode(self.secret)

    def code(self, at):
        return cc.totp(self.key, at)

    def test_store_is_private_and_uri_is_standard(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertTrue(self.uri.startswith("otpauth://totp/Callback%20check%3ACFO?secret="))
        self.assertIn("&digits=6&period=30", self.uri)

    def test_current_and_adjacent_steps_pass_far_ones_fail(self):
        self.assertTrue(cc.check(self.store, "CFO", self.code(T0 - 30), T0)[0])
        self.assertTrue(cc.check(self.store, "CFO", self.code(T0 + 30), T0 + 1)[0])
        self.assertFalse(cc.check(self.store, "CFO", self.code(T0 + 120), T0 + 2)[0])

    def test_a_code_works_once(self):
        code = self.code(T0)
        self.assertTrue(cc.check(self.store, "CFO", code, T0)[0])
        ok, message = cc.check(self.store, "CFO", code, T0 + 5)
        self.assertFalse(ok)
        self.assertIn("already used", message)

    def test_lockout_after_five_wrong_codes(self):
        for i in range(cc.MAX_FAILURES):
            self.assertFalse(cc.check(self.store, "CFO", "000000", T0 + i)[0])
        ok, message = cc.check(self.store, "CFO", self.code(T0 + 10), T0 + 10)
        self.assertFalse(ok)
        self.assertIn("locked", message)
        later = T0 + cc.LOCKOUT + 60
        self.assertTrue(cc.check(self.store, "CFO", self.code(later), later)[0])

    def test_audit_log_never_holds_codes(self):
        code = self.code(T0)
        cc.check(self.store, "CFO", code, T0)
        log = open(os.path.join(self.dir, "store-audit.log")).read()
        self.assertIn('"accepted"', log)
        self.assertNotIn(code, log)

    def test_refuses_a_store_others_can_read(self):
        os.chmod(self.path, 0o644)
        with self.assertRaises(SystemExit):
            cc.Store(self.path)

    def test_command_line_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cc.main(["--store", self.path, "check", "CFO", self.code(T0)], now=T0), 0)
            self.assertEqual(cc.main(["--store", self.path, "check", "CFO", "123456"], now=T0 + 31), 1)
            self.assertEqual(cc.main(["selftest"]), 0)
        self.assertEqual(json.load(open(self.path))["people"]["CFO"]["algorithm"], "SHA1")


if __name__ == "__main__":
    unittest.main()
