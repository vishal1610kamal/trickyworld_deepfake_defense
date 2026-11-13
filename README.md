# Deepfake defense: two small tools

Two scripts from the TrickyWorld article
[Deepfake scams: the question a fake CEO failed](https://www.trickyworld.in/computer-tricks/cyber-security/deepfake-scams-defense/).
Both are plain Python 3.10+.

| Tool | What it does | Needs |
|---|---|---|
| `callcode.py` | Callback codes: a caller who asks for money or access reads out the 6-digit code from their authenticator app, and you check it. A cloned voice or face can't produce it. | Nothing: standard library only |
| `check_media.py` | Reads a photo's or video's Content Credentials (C2PA) and reports, separately, whether the file was changed after signing, whether the signer is trusted, and whether its own record says it was made by AI. | `pip install c2pa-python` |

## callcode.py

```bash
python3 callcode.py selftest                       # checks the algorithm against the RFC 6238 and RFC 4226 test vectors
python3 callcode.py enroll "Priya Sharma (CFO)"    # prints a key for her authenticator app; do this once, in person
python3 callcode.py check  "Priya Sharma (CFO)" 492817
```

- Works with Google Authenticator, Microsoft Authenticator, Aegis, 1Password and any other app that follows RFC 6238
  (6 digits, 30 seconds, SHA-1).
- A code is accepted once. Five wrong codes in ten minutes lock the person out for ten minutes.
- Keys live in `~/.config/callcode/store.json`, readable only by its owner; the script refuses a store that other users
  can read. Every check is written to `store-audit.log` with the result but never the code.
- Exit code 0 means the code was right, 1 means stop.

Enrol people face to face, or over a channel you already trust. Treat `enroll` output like a password: it is the key.

## check_media.py

```bash
pip install c2pa-python
python3 check_media.py photo.jpg                    # validates against the official C2PA trust list (downloaded)
python3 check_media.py --trust none clip.mp4        # offline: integrity and origin only
python3 check_media.py --json *.jpg                 # machine-readable
```

Exit codes: 0 every file carries intact credentials, 1 at least one file's credentials are broken, 2 a file has
none, 3 a file couldn't be read.

What the verdicts mean:

| Verdict | Meaning |
|---|---|
| `made or edited with generative AI, says ...` | The file's own signed record says so. With a trusted signer, that is as good as a label gets. |
| `camera capture, signed by a trusted device or app` | A certified camera or app signed it and the pixels are unchanged since. |
| `claims to be a camera capture, but the signer isn't verified` | Anyone can sign a claim. Without a trusted signer it is just a claim. |
| `credentials BROKEN` | The content changed after signing. Treat the file as edited. |
| `no Content Credentials` | Proves nothing either way. Many apps and platforms strip them, and most cameras don't add them yet. |

## Tests

```bash
python3 -m unittest -v
```

15 tests. The 5 media tests need `c2pa-python` and skip without it. `tests/fixtures/` holds a plain JPEG, the same
image signed as "created using generative AI" and as a "digital capture", a copy with eight bytes of picture data
flipped, and a copy re-saved by an image library. They are signed with the C2PA project's public test certificate,
which is on no trust list, so the checker reports them as unverified unless you pass the test CA with
`--trust tests/fixtures/c2pa-test-intermediate-ca.pem`. `tests/make_fixtures.py` rebuilds them; the test key is
fetched from a pinned commit of the c2pa-python repository, checksummed and never written to disk.

## Sources

- RFC 6238 (TOTP) and RFC 4226 (HOTP), with their published test vectors
- [C2PA specifications](https://c2pa.org/specifications/specifications/2.5/index.html), the
  [C2PA conformance program and trust list](https://c2pa.org/conformance/) and the
  [c2pa-python library](https://github.com/contentauth/c2pa-python)
- [IPTC digital source type vocabulary](https://cv.iptc.org/newscodes/digitalsourcetype), which C2PA records use to
  say how a file was made
