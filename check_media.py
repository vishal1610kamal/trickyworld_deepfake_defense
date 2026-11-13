#!/usr/bin/env python3
"""Read a photo's or video's Content Credentials (C2PA) and say what they prove.

Content Credentials are a signed record, embedded in the file, of who made it and how: a camera that
captured it, an app that edited it, or a generative AI model that created it. This script reports three
things separately, because they fail separately:

  1. integrity  - were the pixels or the record changed after signing?
  2. trust      - is the signer on a trust list you choose (the official C2PA list by default)?
  3. origin     - what the record says: camera capture, human edit, or generative AI

    python3 check_media.py photo.jpg                # read and validate
    python3 check_media.py --trust none photo.jpg   # skip the trust list (offline)
    python3 check_media.py --json clip.mp4          # machine-readable

Missing credentials prove nothing either way: many apps and platforms strip them, and most cameras don't
add them yet. Needs: pip install c2pa-python
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

try:
    import c2pa
except ImportError:                       # keep --help usable without the library
    c2pa = None

VERSION = "1.0.0"
C2PA_TRUST_LIST = ("https://raw.githubusercontent.com/c2pa-org/conformance-public/main/"
                   "trust-list/C2PA-TRUST-LIST.pem")
IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"
# IPTC digital source types (cv.iptc.org/newscodes/digitalsourcetype), the vocabulary C2PA actions use.
SOURCE_TYPES = {
    "trainedAlgorithmicMedia": ("Created using generative AI", "ai"),
    "compositeWithTrainedAlgorithmicMedia": ("Edited using generative AI", "ai"),
    "compositeSynthetic": ("Composite including generative AI elements", "ai"),
    "virtualRecording": ("Recording of a virtual event (may include generative AI)", "ai?"),
    "algorithmicMedia": ("Pure algorithmic media (no trained model)", "software"),
    "digitalCapture": ("Captured with a digital camera or recorder", "capture"),
    "computationalCapture": ("Multi-frame computational capture", "capture"),
    "negativeFilm": ("Digitised from film negative", "capture"),
    "positiveFilm": ("Digitised from film positive", "capture"),
    "print": ("Digitised from a print", "capture"),
    "screenCapture": ("Screen capture", "capture"),
    "compositeCapture": ("Composite of captured elements", "capture"),
    "minorHumanEdits": ("Original with minor human edits", "edit"),
    "humanEdits": ("Human-edited with non-generative tools", "edit"),
    "algorithmicallyEnhanced": ("Algorithmically enhanced, content unchanged", "edit"),
    "composite": ("Composite of elements (may or may not include AI)", "edit"),
    "softwareImage": ("Created by software", "software"),
    "digitalArt": ("Digital art made by a person", "software"),
    "digitalCreation": ("Created by a person with non-generative tools", "software"),
    "dataDrivenMedia": ("Data-driven media", "software"),
}
EXPLAIN = {   # the validation codes people meet most often, in plain words
    "assertion.dataHash.mismatch": "the file's content changed after it was signed",
    "assertion.bmffHash.mismatch": "the video's content changed after it was signed",
    "assertion.boxesHash.mismatch": "the file's content changed after it was signed",
    "claimSignature.mismatch": "the signed record itself was altered",
    "signingCredential.untrusted": "the signer is not on the trust list in use",
    "signingCredential.expired": "the signing certificate had expired",
    "signingCredential.revoked": "the signing certificate was revoked",
    "signingCredential.invalid": "the signing certificate is not valid for signing credentials",
}
TAMPER_CODES = ("mismatch", "claimSignature", "Missing", "missing", "malformed")


def load_trust(choice: str):
    """A c2pa Context that checks signers against the chosen anchors, or None for no trust check."""
    if choice == "none":
        return None, "not checked"
    if choice == "c2pa":
        with urllib.request.urlopen(C2PA_TRUST_LIST, timeout=30) as resp:
            pem, label = resp.read().decode(), "official C2PA trust list"
    else:
        with open(choice, encoding="utf-8") as fh:
            pem, label = fh.read(), os.path.basename(choice)
    settings = c2pa.Settings.from_dict({"verify": {"verify_cert_anchors": True}, "trust": {"trust_anchors": pem}})
    return c2pa.Context(settings), label


def read_store(path: str, context):
    """The manifest store as a dict, or None when the file carries no Content Credentials."""
    try:
        reader = c2pa.Reader(path, context=context) if context else c2pa.Reader(path)
        with reader:
            return json.loads(reader.json())
    except c2pa.C2paError.ManifestNotFound:
        return None


def source_types(manifest: dict) -> list[str]:
    found = []
    for assertion in manifest.get("assertions", []):
        if assertion.get("label", "").startswith("c2pa.actions"):
            for action in (assertion.get("data") or {}).get("actions", []):
                dst = action.get("digitalSourceType")
                if dst and dst not in found:
                    found.append(dst)
    return found


def summarize(path: str, store: dict | None, trust_label: str) -> dict:
    if store is None:
        return {"file": path, "credentials": False, "verdict": "no Content Credentials",
                "note": "That proves nothing either way: many apps and platforms strip them, "
                        "and most cameras don't add them yet."}
    manifest = store["manifests"][store["active_manifest"]]
    results = (store.get("validation_results") or {}).get("activeManifest") or {}
    failures = [f.get("code", "") for f in results.get("failure", [])]
    if trust_label == "not checked":       # with no trust list loaded, every signer is "untrusted"
        failures = [c for c in failures if c != "signingCredential.untrusted"]
    tampered = [c for c in failures if any(t in c for t in TAMPER_CODES)]
    state = store.get("validation_state")                     # Invalid, Valid or Trusted
    sig = manifest.get("signature_info") or {}
    types = source_types(manifest)
    kinds = {SOURCE_TYPES.get(t.replace(IPTC, ""), ("", "unknown"))[1] for t in types}
    generator = manifest.get("claim_generator") or ", ".join(
        f"{g.get('name', '')} {g.get('version', '')}".strip() for g in manifest.get("claim_generator_info", []))
    trusted = state == "Trusted"
    who = "a trusted signer" if trusted else "a signer that isn't verified"
    if state == "Invalid" or tampered:
        verdict = "credentials BROKEN: " + "; ".join(EXPLAIN.get(c, c) for c in (tampered or failures))
    elif "ai" in kinds:
        verdict = f"made or edited with generative AI, says {who}"
    elif "capture" in kinds and trusted:
        verdict = "camera capture, signed by a trusted device or app"
    elif "capture" in kinds:
        verdict = "claims to be a camera capture, but the signer isn't verified: treat the claim as unproven"
    else:
        verdict = f"signed by {who}; no capture or AI statement found"
    return {
        "file": path, "credentials": True, "manifests": len(store.get("manifests", {})),
        "integrity": "FAILED" if (state == "Invalid" or tampered) else "OK",
        "trust": ("trusted signer (" + trust_label + ")" if state == "Trusted"
                  else "signer not on " + trust_label if trust_label != "not checked" else "not checked"),
        "signer": sig.get("common_name") or sig.get("issuer"), "issuer": sig.get("issuer"),
        "signed_at": sig.get("time"), "generator": generator,
        "origin": [SOURCE_TYPES.get(t.replace(IPTC, ""), (t, ""))[0] for t in types],
        "problems": [f"{c}: {EXPLAIN.get(c, 'see the C2PA validation codes')}" for c in failures],
        "validation_state": state, "verdict": verdict,
    }


def print_summary(s: dict) -> None:
    print(f"File: {s['file']}")
    if not s["credentials"]:
        print(f"  Content Credentials: none\n  Verdict: {s['verdict']}\n  Note: {s['note']}")
        return
    print(f"  Content Credentials: present ({s['manifests']} manifest(s))")
    print(f"  Integrity: {s['integrity']}")
    print(f"  Trust: {s['trust']}")
    print(f"  Signer: {s['signer']} (issuer: {s['issuer']}), signed {s['signed_at'] or 'time not recorded'}")
    print(f"  Made with: {s['generator'] or 'not stated'}")
    print(f"  Origin: {'; '.join(s['origin']) or 'not stated'}")
    for p in s["problems"]:
        print(f"  Problem: {p}")
    print(f"  Verdict: {s['verdict']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", help="images or videos to check")
    ap.add_argument("--trust", default="c2pa",
                    help="'c2pa' (official C2PA trust list, downloaded), 'none', or a PEM file of anchors")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    if c2pa is None:
        print("This tool needs the C2PA library: pip install c2pa-python", file=sys.stderr)
        return 3
    try:
        context, label = load_trust(args.trust)
    except OSError as err:
        print(f"Could not load the trust list ({err}); continuing without it.", file=sys.stderr)
        context, label = None, "not checked"
    summaries = []
    for path in args.files:
        try:
            s = summarize(path, read_store(path, context), label)
        except c2pa.C2paError as err:
            s = {"file": path, "credentials": None, "verdict": f"could not read: {err}"}
        summaries.append(s)
    if args.json:
        print(json.dumps(summaries, indent=1))
    else:
        for s in summaries:
            if s["credentials"] is None:
                print(f"File: {s['file']}\n  Verdict: {s['verdict']}")
            else:
                print_summary(s)
    if any(s.get("integrity") == "FAILED" for s in summaries):
        return 1            # at least one file's credentials were broken: treat it as tampered
    if any(s["credentials"] is None for s in summaries):
        return 3            # could not read a file
    if any(s["credentials"] is False for s in summaries):
        return 2            # no credentials (which proves nothing either way)
    return 0                # every file carries intact credentials


if __name__ == "__main__":
    sys.exit(main())
