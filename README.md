# pbin2zip

A small command-line tool that converts Panorama `.pbin` containers to and
from standard ZIP archives.

In CS:GO the Panorama UI ships as `csgo/panorama/code.pbin`. Despite the
`.pbin` extension it is a plain ZIP file wrapped in a 517-byte container, so
any archive tool can open it once the wrapper is stripped — the trick described
in [this unknowncheats post](https://www.unknowncheats.me/forum/2157360-post2.html):
"remove the first 516 bytes in the file".

## Container format

| Offset    | Size      | Contents                                                     |
|-----------|-----------|--------------------------------------------------------------|
| `0`       | `4`       | Header: `'P'`, `'A'`, `'N'`, version (currently `1`)         |
| `4`       | `512`     | RSA-4096 PKCS#1 v1.5 SHA-1 signature over `(zip \|\| version)` |
| `516`     | `n`       | A standard ZIP archive (`PK\x03\x04` local file headers)     |
| `516 + n` | `1`       | Version byte again, covered by the signature                 |

Total overhead: `4 + 512 + 1 = 517` bytes.

The layout is taken from Valve's own packer and verifier in the leaked CS:GO
source:

- writer: `utils/panzip/panzip.cpp` — builds the ZIP, appends the version byte,
  signs the result, and writes `header || signature || zip || version`.
- verifier: `panorama/source2/panoramauiengine.cpp`
  (`PanoramaResourceFileIntegrityCheck`) — requires the `PAN` magic, hardcodes
  the `512`-byte signature field, and checks the trailing version byte.

Stripping the fixed `516`-byte prefix and dropping the trailing byte therefore
yields a byte-identical, warning-free ZIP.

## Usage

```
pbin2zip unpack [-o out.zip] <file.pbin | ->
pbin2zip pack   [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->
pbin2zip info   [-l] <file.pbin | ->
```

Examples:

```console
# code.pbin -> code.zip (output path defaults to the swapped extension)
$ pbin2zip unpack code.pbin

# inspect the container and list the archive contents
$ pbin2zip info -l code.pbin

# repack a modified UI archive
$ pbin2zip pack code.zip -o code.pbin

# pipelines work too: "-" is stdin/stdout
$ pbin2zip unpack - < code.pbin > code.zip
```

### Signature notes

- `pack` writes an all-zero placeholder signature by default and warns about
  it: the game verifies `code.pbin` against Valve's embedded public key, so a
  repacked container fails that check.
- `-sign key.pem` signs the container with your own 4096-bit RSA key
  (PKCS#1 or PKCS#8 PEM, SHA-1 PKCS#1 v1.5 — exactly what `panzip` produces).
  This is only useful for research against a patched verifier or for producing
  self-consistent fixtures.

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
