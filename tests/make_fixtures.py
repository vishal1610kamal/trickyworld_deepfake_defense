"""Rebuild the sample images in tests/fixtures.

They are signed with the C2PA project's public *test* certificate, which the c2pa-python repository
publishes for exactly this purpose. That certificate is on no trust list, so the samples show up as
"signer not on ... trust list", as they should. The key is downloaded from a pinned commit, checked by
SHA-256 and kept in memory only: it is never written to disk or stored in this repository.

    pip install c2pa-python pillow
    python3 tests/make_fixtures.py
"""
import hashlib
import json
import os
import urllib.request

import c2pa
from PIL import Image

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
COMMIT = "48d07023d4f37e978c5b30745b49b26668774b08"   # contentauth/c2pa-python, 12 November 2026
BASE = f"https://raw.githubusercontent.com/contentauth/c2pa-python/{COMMIT}/tests/fixtures/"
PINNED = {
    "es256_certs.pem": "f18a293626ac261b18201e269ee0ed9c10bc30afb3b5c8708bb16e41a05bf040",
    "es256_private.key": "f547ec8dbf24e50b51cf9924e58c250d246ed8844304408a072801fcf70a95d7",
}
IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"


def fetch(name: str) -> bytes:
    with urllib.request.urlopen(BASE + name, timeout=30) as resp:
        data = resp.read()
    if hashlib.sha256(data).hexdigest() != PINNED[name]:
        raise SystemExit(f"{name}: checksum mismatch, refusing to use it")
    return data


def sign(source: str, dest: str, source_type: str, title: str, cert: bytes, key: bytes) -> None:
    manifest = json.dumps({
        "claim_generator_info": [{"name": "trickyworld deepfake-defense fixtures", "version": "1.0"}],
        "title": title,
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [
            {"action": "c2pa.created", "digitalSourceType": IPTC + source_type}]}}],
    })
    info = c2pa.C2paSignerInfo(alg=c2pa.C2paSigningAlg.ES256, sign_cert=cert, private_key=key, ta_url=None)
    with c2pa.Signer.from_info(info) as signer, c2pa.Builder(manifest) as builder:
        builder.sign_file(source, dest, signer)


def main() -> None:
    os.makedirs(HERE, exist_ok=True)
    cert, key = fetch("es256_certs.pem"), fetch("es256_private.key")
    plain = os.path.join(HERE, "no-credentials.jpg")
    Image.new("RGB", (480, 270), (28, 110, 190)).save(plain, quality=90)
    ai = os.path.join(HERE, "ai-generated.jpg")
    sign(plain, ai, "trainedAlgorithmicMedia", "ai-generated.jpg", cert, key)
    camera = os.path.join(HERE, "camera-capture.jpg")
    sign(plain, camera, "digitalCapture", "camera-capture.jpg", cert, key)
    del cert, key
    # Same AI image with 8 bytes of picture data flipped: the record survives, the hash doesn't match.
    data = bytearray(open(ai, "rb").read())
    start = data.rfind(b"\xff\xda") + 200          # inside the compressed image data
    for i in range(start, start + 8):
        if data[i] != 0xFF:
            data[i] ^= 0x01
    with open(os.path.join(HERE, "ai-generated-tampered.jpg"), "wb") as fh:
        fh.write(data)
    # Same AI image opened and saved again, as a screenshot or an upload pipeline would: the record is gone.
    Image.open(ai).save(os.path.join(HERE, "ai-generated-resaved.jpg"), quality=90)
    print("fixtures written to", HERE)


if __name__ == "__main__":
    main()
