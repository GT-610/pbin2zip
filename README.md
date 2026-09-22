# pbin2zip

A small command-line tool that converts Panorama `.pbin` containers to and
from standard ZIP archives.

In CS:GO the Panorama UI ships as `csgo/panorama/code.pbin`. Despite the
`.pbin` extension it is a plain ZIP file wrapped in a small signed envelope,
so any archive tool can open it once the wrapper is stripped — the trick
described in [this unknowncheats post](https://www.unknowncheats.me/forum/2157360-post2.html):
"remove the first 516 bytes in the file".

## Container format

Layout common to all versions:

| Offset    | Size      | Contents                                                         |
|-----------|-----------|------------------------------------------------------------------|
| `0`       | `4`       | Header: `'P'`, `'A'`, `'N'`, version                             |
| `4`       | `512`     | RSA-4096 PKCS#1 v1.5 SHA-1 signature over bytes `[516, EOF)`     |
| `516`     | `n`       | A standard ZIP archive (`PK\x03\x04` local file headers)         |
| `516 + n` | `t`       | Trailer of `t` bytes, always ending with the version byte        |

Two versions are known:

| | Version 1 (up to 2019) | Version 2 (final 2023 client) |
|---|---|---|
| Trailer | 1 byte (the version) | 5 bytes: 4-byte gate value + the version (official gate: `0x00003639` = 13881) |
| Total overhead | 517 bytes | 521 bytes |
| Minimum file size | 517 bytes | 581 bytes |
| Public key | `C3 77 62 5E …` | rotated: `B0 9F D8 72 …`, exponent 17 |

The version-1 layout comes from Valve's own packer and verifier in the leaked
CS:GO source: `utils/panzip/panzip.cpp` (writer) and
`panorama/source2/panoramauiengine.cpp` (`PanoramaResourceFileIntegrityCheck`).

The version-2 layout was confirmed by reverse engineering the final client's
`panorama.dll` parser (`FUN_10011f80`):

```asm
CMP  ECX, 0x245                ; minimum file size 581
MOV  dword [EBP+8], 0x24e4150  ; 'P','A','N',0x02 — version 2
CMP  byte [EDX+ECX-1], 0x2     ; trailer must end with 0x02
LEA  EAX, [EDX+0x204]          ; ZIP starts at +516
SUB  EAX, 0x209                ; ZIP length = total-521 → 5-byte trailer
                               ; gate: read u32 at size-5 (trailer[0:4]),
                               ; must equal INETSUPPORT_003's value, else
                               ; reject before verifying the 512-byte
                               ; RSA signature at +4 (rotated key)
```

Stripping the fixed `516`-byte prefix and cutting at the ZIP's
end-of-central-directory record therefore yields a byte-identical,
warning-free ZIP — for version 1, version 2, and unknown versions alike.

## Usage

```
pbin2zip unpack [-o out.zip] <file.pbin | ->
pbin2zip pack   [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->
pbin2zip info   [-l] <file.pbin | ->
pbin2zip verify <file.pbin | ->
```

Examples:

```console
# code.pbin -> code.zip; the version is auto-detected from the header
$ pbin2zip unpack code.pbin
unpacked 4704000 bytes of ZIP (726 entries) from code.pbin to code.zip \
  (container version 2, 5-byte trailer)

# inspect the container (version, signature state, trailer, entries)
$ pbin2zip info -l code.pbin

# check a container exactly the way the stock final client would:
# version 2, gate 13881, official signature — exit 0 = accepted
$ pbin2zip verify code.pbin
code.pbin: accepted — version 2, gate 13881, official signature valid

# a repacked file with a placeholder signature fails the same check
$ pbin2zip verify modified.pbin
pbin2zip: modified.pbin: signature verification failed: ...
pbin2zip: error: the stock 2023 client would reject this container (1 problem(s))

# repack a modified UI archive for the final 2023 client (version 2, the default)
$ pbin2zip pack code.zip -o code.pbin

# unmodified round trip: reuse the official envelope so the output is
# byte-identical to a Valve-signed file (verified against the official key)
$ pbin2zip pack -template code.pbin code.zip -o repacked.pbin

# legacy pre-2020 container
$ pbin2zip pack -version 1 code.zip -o old-code.pbin

# pipelines work too: "-" is stdin/stdout
$ pbin2zip unpack - < code.pbin > code.zip
```

### Versions

- **unpack** auto-detects the container version and finds the ZIP end via the
  end-of-central-directory record, so v1, v2, and unknown versions all
  unpack. Versions with a trailer size we have never seen are unpacked on a
  best-effort basis.
- **pack** guarantees only the **2023 format (version 2)** — envelope size,
  trailer, and the 581-byte minimum are enforced. `-version 1` is also fully
  supported; any other version packs best-effort with a warning.
- **verify** applies the stock client's checks in its own order and reports
  each failing one; exit status 0 means the final client would load the file.

### Signature notes

- `pack` writes an all-zero placeholder signature by default and warns about
  it: the 2023 client verifies `code.pbin` against Valve's embedded,
  since-rotated public key with mandatory fail-closed checking, so a repacked
  container fails that check.
- `-sign key.pem` signs the container with your own 4096-bit RSA key
  (PKCS#1 or PKCS#8 PEM, SHA-1 PKCS#1 v1.5 — exactly what `panzip` produces,
  over ZIP || trailer). Only useful for research against a patched verifier
  or for producing self-consistent fixtures.
- The four non-version trailer bytes in v2 are covered by the signature and
  read back by the client as the pre-verify gate value; see below.
- Because those gate bytes are signed, combining `-template` with a changed
  `-build-number` invalidates the copied signature: `pack` warns about it and
  `verify` reports the output as rejected (exit 1).

### Will the stock 2023 client read a packed file?

Run `pbin2zip verify <file.pbin>` to check any container against exactly the
rules below (exit 0 = accepted). In detail:

- **Unmodified round trip: yes.** `pack -template` copies the official
  envelope and verifies it against the embedded official key, so the output
  is byte-identical to Valve's own file (the test suite asserts this when
  the local sample is present).
- **Modified ZIP: not without patching the client.** The parser runs a
  mandatory, fail-closed RSA verify (`FUN_10011f80`, verify call at
  `panorama.dll` RVA `0x12548`) against Valve's rotated private-key
  counterpart, which we do not have. Research setups patch the client —
  e.g. replace that 5-byte `CALL` with `B8 01 00 00 00` (`MOV EAX,1`) —
  or swap the embedded certificate; `-sign` then signs with your key.
- Both cases still need the gate value correct (default 13881, tunable via
  `-build-number`) and legal resource names/paths inside the ZIP: the
  loader rejects illegal names and empty manifests.

### Where is the private key?

Nowhere reachable — stated plainly, because we looked rather than assumed.
The signing half of Valve's panorama-pack key was never shipped, never
leaked, and cannot be derived:

- **The leaked source names the file but does not contain it.**
  `utils/panzip/panzip.cpp` includes
  `devtools/bin/certificates/panoramapack.private.h` directly into the
  packer and signs with it (`launcher_keypair_signdata`). The leaked
  `csgo_partner` tree only ships the matching `panoramapack.public.h`
  (the 2019 key, modulus starting `C3 77 62 5E`); a filesystem-wide
  search for `panoramapack*` finds no `.private.h` anywhere.
- **No shipped binary contains a PEM private key.** A case-insensitive
  byte scan for `PRIVATE KEY` — which covers every PEM private-key label,
  including `RSA PRIVATE KEY` and `PRIVATE KEY` — plus `BEGIN RSA`, over
  the installed game's DLLs and EXEs, hits only crypto-library label
  tables: OpenSSL's PEM names in `video.dll`, libssh's
  `-----BEGIN OPENSSH PRIVATE KEY-----` template in
  `steamnetworkingsockets.dll`, Go `crypto/x509` labels in the non-Valve
  `csgo-inventory-editor.exe`, and lowercase prose in `engine.dll`.
  `panorama.dll`, `panoramauiclient.dll`, `client.dll`, and `csgo.exe`
  have zero hits, and `engine.dll` contains no `-----BEGIN` PEM header
  at all.
- **What the client embeds is only the public half.** The blob
  reconstructed from `panorama.dll` (`tools/certcheck`) is a 548-byte
  SubjectPublicKeyInfo — modulus plus exponent 17. A 4096-bit private key
  is a ~2.4 KB structure of nine INTEGERs (`d`, `p`, `q`, `dP`, `dQ`,
  `qInv`, …); no structure of that shape exists in the binary.
- **It could not be derived either.** The client only verifies, so it
  needs only the public half; recovering the private exponent from a
  4096-bit modulus means factoring that modulus, which is not feasible.
  And shipping the private key would let anyone sign an arbitrary
  `code.pbin`, defeating the check — which is why it exists only in
  Valve's build tree.
- **Even the 2019 private key would not help the 2023 client.** The key
  rotated (`C3 77 62 5E …` → `B0 9F D8 72 …`, an entirely different
  modulus), so a recovered old key could only sign version-1 containers
  for pre-2020 clients.

Consequences, honestly: a modified ZIP can **never** satisfy the stock
2023 verifier — the routes above are patching the verifier or swapping
the embedded certificate, after which `-sign` produces signatures valid
only under your own key or patched client. The only stock-safe repack
remains `pack -template` with byte-identical, unmodified content.

## Verified against the official sample

All of the above was cross-checked against Valve's unmodified final
`code.pbin` (4,704,521 bytes, 726 entries, trailer `39 36 00 00 02`):

- it parses, re-marshals byte-identically, and unpacks to a working ZIP;
- it is byte-identical (same SHA-256) to the `code.pbin` shipped in a stock
  Steam install of CS:GO Legacy, so the sample is provably unmodified;
- its signature verifies against the public key extracted from the shipped
  `panorama.dll` — `tools/certcheck` reconstructs the 548-byte DER key from
  Ghidra-captured instruction bytes — confirming the signed range
  `[516, EOF)` = ZIP || trailer, SHA-1 PKCS#1 v1.5, and the rotated
  4096-bit key (modulus starting `00 B0 9F D8 72`, **exponent 17**);
- `internal/pbin.TestOfficialSample` repeats all of this automatically when
  the sample is present at `.vscode/code.pbin` (game content, not committed;
  override with `PBIN2ZIP_SAMPLE`) and skips otherwise.

The four trailer bytes are `39 36 00 00` — a little-endian uint32 of
**13881**, not a content checksum: the parser seeks to `size-5`, reads them
back, and compares them against the value `INETSUPPORT_003` reports, rejecting
the file before the signature check if they differ (CRC32/CRC32C/Adler32 and
CRC16 families over the ZIP, central directory, pre-EOCD region, uncompressed
concatenation, and per-entry CRC aggregates all failed to match, confirming
they are a gate value rather than a hash). `pack` writes 13881 by default —
the value the frozen 2023 build expects — overridable with `-build-number`.

## Build and test

```console
$ go build .
$ go test ./...
```

Requires Go 1.24+; no third-party dependencies.

## Related projects

- `CSGOPanorama` — dumps of the source extracted from `code.pbin` for every
  Panorama-era CS:GO version.
- `csgo_gc` — GC support for the discontinued CS:GO.

## License

[MIT](LICENSE)
