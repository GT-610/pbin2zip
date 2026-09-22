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
| Trailer | 1 byte (the version) | 5 bytes (4 unknown + the version) |
| Total overhead | 517 bytes | 521 bytes |
| Minimum file size | 517 bytes | 581 bytes |
| Public key | `C3 77 62 5E …` | rotated: `B0 9F D8 72 …` |

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
                               ; then a mandatory RSA verify (512-byte
                               ; signature at +4) with Valve's rotated key
```

Stripping the fixed `516`-byte prefix and cutting at the ZIP's
end-of-central-directory record therefore yields a byte-identical,
warning-free ZIP — for version 1, version 2, and unknown versions alike.

## Usage

```
pbin2zip unpack [-o out.zip] <file.pbin | ->
pbin2zip pack   [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->
pbin2zip info   [-l] <file.pbin | ->
```

Examples:

```console
# code.pbin -> code.zip; the version is auto-detected from the header
$ pbin2zip unpack code.pbin
unpacked 18434112 bytes of ZIP (1103 entries) from code.pbin to code.zip \
  (container version 2, 5-byte trailer)

# inspect the container (version, signature state, trailer, entries)
$ pbin2zip info -l code.pbin

# repack a modified UI archive for the final 2023 client (version 2, the default)
$ pbin2zip pack code.zip -o code.pbin

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

### Signature notes

- `pack` writes an all-zero placeholder signature by default and warns about
  it: the 2023 client verifies `code.pbin` against Valve's embedded,
  since-rotated public key with mandatory fail-closed checking, so a repacked
  container fails that check.
- `-sign key.pem` signs the container with your own 4096-bit RSA key
  (PKCS#1 or PKCS#8 PEM, SHA-1 PKCS#1 v1.5 — exactly what `panzip` produces,
  over ZIP || trailer). Only useful for research against a patched verifier
  or for producing self-consistent fixtures.
- The four non-version trailer bytes in v2 are never read back by any module
  of the final client; `pack` writes them as zeros.

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
