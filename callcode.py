#!/usr/bin/env python3
"""Callback codes that a cloned voice can't produce.

Each person who may ask for money, password resets or access over a call adds a key to an ordinary
authenticator app (Google Authenticator, Microsoft Authenticator, any RFC 6238 app). When "they" call,
the person taking the call asks for the 6-digit code on their phone and checks it here. A deepfake can
copy a face and a voice; it can't read a code off a phone it doesn't hold.

    python3 callcode.py enroll "Priya Sharma (CFO)"      # once per person: prints a key for their app
    python3 callcode.py check  "Priya Sharma (CFO)" 492817
    python3 callcode.py selftest                          # RFC 6238 / RFC 4226 test vectors

Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import quote

VERSION = "1.0.0"
DEFAULT_STORE = os.path.join(os.path.expanduser("~"), ".config", "callcode", "store.json")
DIGITS, PERIOD, ALGORITHM = 6, 30, "SHA1"   # what every authenticator app supports by default
WINDOW = 1                                  # accept one 30-second step either side for clock drift
MAX_FAILURES, FAILURE_SPAN, LOCKOUT = 5, 600, 600   # 5 wrong codes in 10 minutes -> locked for 10 minutes
ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


# --------------------------------------------------------------------------- RFC 4226 / RFC 6238
def hotp(key: bytes, counter: int, digits: int = DIGITS, algorithm: str = ALGORITHM) -> str:
    """HMAC-based one-time password (RFC 4226), with the hash choices RFC 6238 adds."""
    mac = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def totp(key: bytes, at: float, digits: int = DIGITS, period: int = PERIOD, algorithm: str = ALGORITHM) -> str:
    """Time-based one-time password (RFC 6238) for the Unix time `at`."""
    return hotp(key, int(at // period), digits, algorithm)


def b32decode(text: str) -> bytes:
    """Base32 as authenticator apps show it: any case, spaces allowed, padding optional."""
    clean = "".join(text.split()).upper()
    return base64.b32decode(clean + "=" * (-len(clean) % 8))


def b32encode(key: bytes) -> str:
    return base64.b32encode(key).decode().rstrip("=")


# --------------------------------------------------------------------------- store
class Store:
    """People and their keys, in a JSON file only the owner can read (mode 0600)."""

    def __init__(self, path: str):
        self.path = path
        self.data = {"version": 1, "people": {}}
        if os.path.exists(path):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                raise SystemExit(f"{path} is readable by other users (mode {oct(mode)}). "
                                 f"Run: chmod 600 {path}")
            with open(path, encoding="utf-8") as fh:
                self.data = json.load(fh)

    @property
    def people(self) -> dict:
        return self.data["people"]

    def save(self) -> None:
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".store-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def audit(self, name: str, result: str, now: float) -> None:
        """One line per check. The code itself is never written down."""
        line = json.dumps({"time": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"),
                           "person": name, "result": result})
        log = os.path.splitext(self.path)[0] + "-audit.log"
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# --------------------------------------------------------------------------- actions
def enroll(store: Store, name: str, issuer: str, now: float) -> tuple[str, str]:
    if name in store.people:
        raise SystemExit(f"{name!r} is already enrolled. Remove them first to issue a new key.")
    key = secrets.token_bytes(20)               # 160 bits, the size RFC 4226 recommends
    secret = b32encode(key)
    store.people[name] = {"secret": secret, "digits": DIGITS, "period": PERIOD, "algorithm": ALGORITHM,
                          "created": int(now), "last_step": -1, "failures": [], "locked_until": 0}
    store.save()
    label = quote(f"{issuer}:{name}", safe="")
    uri = (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
           f"&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD}")
    return secret, uri


def check(store: Store, name: str, code: str, now: float) -> tuple[bool, str]:
    """Accept a code once, within one step of now, unless the person is locked out."""
    person = store.people.get(name)
    if person is None:
        return False, f"unknown person {name!r}"
    if now < person.get("locked_until", 0):
        store.audit(name, "locked", now)
        wait = int(person["locked_until"] - now)
        return False, f"too many wrong codes: locked for another {wait} s. Verify another way."
    code = "".join(code.split())
    key = b32decode(person["secret"])
    step = int(now // person["period"])
    match = None
    if code.isdigit() and len(code) == person["digits"]:
        for candidate in range(step - WINDOW, step + WINDOW + 1):
            if hmac.compare_digest(hotp(key, candidate, person["digits"], person["algorithm"]), code):
                match = candidate
                break
    if match is not None and match <= person.get("last_step", -1):
        result, ok, message = "replay", False, "this code was already used. Ask for the next one."
    elif match is not None:
        person["last_step"], person["failures"] = match, []
        result, ok, message = "accepted", True, "code is correct: the caller has this person's authenticator app"
    else:
        recent = [t for t in person.get("failures", []) if now - t < FAILURE_SPAN] + [int(now)]
        person["failures"] = recent
        if len(recent) >= MAX_FAILURES:
            person["locked_until"] = int(now) + LOCKOUT
            person["failures"] = []
        result, ok, message = "rejected", False, "wrong code. Do not act on this call."
    store.save()
    store.audit(name, result, now)
    return ok, message


# --------------------------------------------------------------------------- self-test
RFC6238 = [  # RFC 6238 Appendix B: (time, SHA1, SHA256, SHA512), 8 digits
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
RFC4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
SEEDS = {"SHA1": b"12345678901234567890",                       # the RFC 6238 seeds: 20, 32 and 64 bytes
         "SHA256": b"12345678901234567890123456789012",
         "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}


def selftest() -> bool:
    ok = True
    for t, *expected in RFC6238:
        for algorithm, want in zip(("SHA1", "SHA256", "SHA512"), expected):
            got = totp(SEEDS[algorithm], t, 8, 30, algorithm)
            ok &= got == want
            print(f"  RFC 6238  T={t:<11} {algorithm:<6} {got} {'ok' if got == want else 'FAIL, want ' + want}")
    for counter, want in enumerate(RFC4226):
        got = hotp(SEEDS["SHA1"], counter, 6, "SHA1")
        ok &= got == want
        print(f"  RFC 4226  counter={counter} {got} {'ok' if got == want else 'FAIL, want ' + want}")
    print("all test vectors match" if ok else "TEST VECTORS FAILED")
    return ok


# --------------------------------------------------------------------------- command line
def main(argv=None, now=None) -> int:
    ap = argparse.ArgumentParser(description="Callback codes for verifying a caller's identity.")
    ap.add_argument("--store", default=os.environ.get("CALLCODE_STORE", DEFAULT_STORE), help="key store file")
    sub = ap.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll", help="create a key for one person's authenticator app")
    e.add_argument("name")
    e.add_argument("--issuer", default="Callback check", help="label the app shows (default: Callback check)")
    c = sub.add_parser("check", help="check the code a caller reads out")
    c.add_argument("name")
    c.add_argument("code")
    sub.add_parser("list", help="list enrolled people")
    r = sub.add_parser("remove", help="remove a person (for example when a phone is lost)")
    r.add_argument("name")
    sub.add_parser("selftest", help="check the algorithm against the RFC test vectors")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    now = time.time() if now is None else now

    if args.command == "selftest":
        return 0 if selftest() else 1
    store = Store(args.store)
    if args.command == "enroll":
        secret, uri = enroll(store, args.name, args.issuer, now)
        print(f"Enrolled {args.name}. Add this key to their authenticator app, then close this window.")
        print(f"  key (type it in):  {' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))}")
        print(f"  or as a link/QR:   {uri}")
        print("  (to show a QR code in the terminal: qrencode -t ansiutf8 '<link above>')")
        return 0
    if args.command == "check":
        ok, message = check(store, args.name, args.code, now)
        print(("OK: " if ok else "STOP: ") + message)
        return 0 if ok else 1
    if args.command == "list":
        for name, person in sorted(store.people.items()):
            created = datetime.fromtimestamp(person["created"], timezone.utc).date()
            print(f"{name}  (enrolled {created})")
        return 0
    if args.command == "remove":
        if store.people.pop(args.name, None) is None:
            print(f"{args.name!r} is not enrolled")
            return 1
        store.save()
        print(f"Removed {args.name}. Delete the entry from their authenticator app too.")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
