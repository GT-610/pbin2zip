// Package pbin implements reading and writing of Panorama .pbin containers.
//
// A .pbin is the packaged Panorama UI archive shipped with CS:GO as
// csgo/panorama/code.pbin. Despite the extension it is a regular ZIP file
// wrapped in a small signed envelope, which is why stripping the fixed
// 516-byte prefix yields an openable archive, as described at
// https://www.unknowncheats.me/forum/2157360-post2.html
//
// Layout common to all versions:
//
//	offset  size  contents
//	0       4     header: 'P', 'A', 'N', version
//	4       512   RSA-4096 PKCS#1 v1.5 SHA-1 signature over bytes [516, EOF)
//	516     n     a standard ZIP archive
//	516+n   t     trailer of t bytes, always ending with the version byte
//
// Two versions are known:
//
//   - Version 1 (CS:GO up to 2019, PANORAMA_ZIPFILE_VERSION in the leaked
//     source): t = 1, total overhead 517 bytes. See
//     utils/panzip/panzip.cpp (writer) and panorama/source2/
//     panoramauiengine.cpp (PanoramaResourceFileIntegrityCheck, reader).
//   - Version 2 (final 2023 client): t = 5 — four bytes of gate value plus
//     the version byte — total overhead 521 bytes, minimum file size 581.
//     Verified in the shipped panorama.dll parser (FUN_10011f80): magic
//     0x024E4150, payload at +0x204, length total-0x209, trailing byte == 2,
//     a pre-verify gate that reads the four trailer bytes back and compares
//     them against a value supplied by INETSUPPORT_003 (official file:
//     0x00003639 = 13881), then a mandatory RSA verify with a rotated
//     public key (modulus starting 00 B0 9F D8 72..., exponent 17).
//
// Unpacking auto-detects the version from the header and locates the ZIP end
// via the end-of-central-directory record, so it also copes with versions we
// have never seen. Packing only guarantees the 2023 (version 2) format.
package pbin

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// HeaderSize is the size of the fixed 'PAN'+version header.
	HeaderSize = 4

	// SignatureSize is the size of the RSA signature. The final client's
	// verifier hardcodes 512 bytes (a 4096-bit RSA key) — see the 0x200
	// length passed to the verify helper from FUN_10011f80.
	SignatureSize = 512

	// OverheadSize is the fixed prefix preceding the ZIP blob (header +
	// signature). Removing it from a .pbin leaves ZIP plus trailer.
	OverheadSize = HeaderSize + SignatureSize // 516

	// Version1 is the container version used by CS:GO up to 2019.
	Version1 = 1

	// Version2 is the container version used by the final (2023) client.
	Version2 = 2

	// DefaultVersion targets packing at the final 2023 client.
	DefaultVersion = Version2

	// TrailerSizeV1: the version byte only.
	TrailerSizeV1 = 1

	// TrailerSizeV2: a four-byte gate value plus the version byte. The final
	// client's parser computes the payload length as total-0x209 while the
	// payload starts at +0x204, leaving exactly 5 trailing bytes, and reads
	// the first four back as the gate value (see DefaultBuildNumber).
	TrailerSizeV2 = 5

	// DefaultBuildNumber is the four-byte gate value the final client
	// expects: the parser reads trailer[0:4] as a little-endian uint32 and
	// requires it to equal the value INETSUPPORT_003 reports, otherwise the
	// container is rejected before signature verification. Valve's official
	// final code.pbin carries 0x00003639 (13881), which pins the expected
	// value for the frozen 2023 build.
	DefaultBuildNumber = 0x00003639 // 13881

	// MinSizeV2 is the smallest file the final client accepts
	// (CMP ECX,0x245 in FUN_10011f80).
	MinSizeV2 = 0x245 // 581

	// MinSize is the smallest possible .pbin overall (version-1 envelope).
	MinSize = OverheadSize + TrailerSizeV1 // 517
)

// magic is the 'PAN' prefix of the header.
var magic = [3]byte{'P', 'A', 'N'}

// localHeaderSig is the normal start of a ZIP archive.
var localHeaderSig = []byte{'P', 'K', 0x03, 0x04}

// eocdSig is the ZIP end-of-central-directory signature. It is also the first
// record of an empty ZIP archive, so it serves as both a payload-start
// signature and the marker used to locate the ZIP end.
var eocdSig = []byte{'P', 'K', 0x05, 0x06}

// isZipStart reports whether data begins with a signature accepted for a ZIP
// payload: a local file header, or an empty archive's EOCD record.
func isZipStart(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return bytes.Equal(data[:4], localHeaderSig) || bytes.Equal(data[:4], eocdSig)
}

// ErrNotPbin is returned by Parse when the data does not start with 'PAN'.
var ErrNotPbin = errors.New("not a pbin container: missing \"PAN\" magic")

// ExpectedTrailerSize returns how many bytes follow the ZIP payload for a
// known container version, or -1 when the version is unknown.
func ExpectedTrailerSize(version byte) int {
	switch version {
	case Version1:
		return TrailerSizeV1
	case Version2:
		return TrailerSizeV2
	default:
		return -1
	}
}

// File is a parsed .pbin container.
type File struct {
	// Version is the container version from the header; it is also the last
	// byte of the trailer and is covered by the signature.
	Version byte

	// Signature is the RSA-4096 PKCS#1 v1.5 SHA-1 signature over
	// (Zip || Trailer). For containers packed without Valve's private key it
	// is a zero placeholder.
	Signature []byte

	// Zip is the raw ZIP archive payload, verbatim and truncated at its
	// end-of-central-directory record (no trailer bytes).
	Zip []byte

	// Trailer is everything between the end of the ZIP and EOF. Version 1
	// files have 1 byte (the version), version 2 files have 5 bytes (the
	// four-byte gate value then the version). Preserved verbatim by Parse.
	Trailer []byte
}

// SignedPayload returns the exact byte range covered by the signature:
// everything after the 516-byte prefix, i.e. the ZIP plus the trailer. This
// matches panzip, which signs the buffer after appending the version byte,
// and the final client's verifier, which hashes from the end of the
// signature field to EOF.
func (f *File) SignedPayload() []byte {
	out := make([]byte, 0, len(f.Zip)+len(f.Trailer))
	out = append(out, f.Zip...)
	out = append(out, f.Trailer...)
	return out
}

// Parse validates a .pbin and splits it into header, signature, ZIP payload,
// and trailer. The container version comes from the header; the ZIP end is
// located via the end-of-central-directory record, so versions with unknown
// envelope sizes still unpack.
func Parse(data []byte) (*File, error) {
	if len(data) < MinSize {
		return nil, fmt.Errorf("not a pbin container: only %d bytes (minimum is %d)", len(data), MinSize)
	}
	if data[0] != magic[0] || data[1] != magic[1] || data[2] != magic[2] {
		return nil, fmt.Errorf("%w, got %q", ErrNotPbin, data[:min(HeaderSize, len(data))])
	}

	version := data[3]
	if last := data[len(data)-1]; last != version {
		return nil, fmt.Errorf("corrupt pbin: trailing byte 0x%02x does not match header version 0x%02x", last, version)
	}

	signature := make([]byte, SignatureSize)
	copy(signature, data[HeaderSize:OverheadSize])

	payload := data[OverheadSize:]
	if !isZipStart(payload) {
		return nil, errors.New("corrupt pbin: payload after the 516-byte prefix is not a ZIP archive (missing \"PK\" signature)")
	}

	end, err := findZipEnd(payload, ExpectedTrailerSize(version))
	if err != nil {
		return nil, fmt.Errorf("corrupt pbin: %w", err)
	}

	return &File{
		Version:   version,
		Signature: signature,
		Zip:       payload[:end],
		Trailer:   payload[end:],
	}, nil
}

// findZipEnd returns the offset just past the ZIP inside payload. expected is
// the trailer size implied by the container version, or -1 when unknown. For
// known versions it prefers an exact trailer size and falls back to the
// end-of-central-directory record nearest the end, so a mislabeled or odd
// file still unpacks instead of failing outright.
func findZipEnd(payload []byte, expected int) (int, error) {
	fallback := -1
	for i := len(payload) - 22; i >= 0; i-- {
		if !bytes.Equal(payload[i:i+4], eocdSig) {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(payload[i+20 : i+22]))
		end := i + 22 + commentLen
		if end > len(payload) {
			continue
		}
		if expected < 0 {
			return end, nil
		}
		if len(payload)-end == expected {
			return end, nil
		}
		if fallback < 0 {
			fallback = end
		}
	}
	if fallback >= 0 {
		return fallback, nil
	}
	return 0, errors.New("payload is not a ZIP archive (no end-of-central-directory record found)")
}

// MarshalBinary serializes the container back into .pbin bytes.
func (f *File) MarshalBinary() ([]byte, error) {
	if f.Version == 0 {
		return nil, errors.New("pbin: version must not be 0")
	}
	if len(f.Signature) != SignatureSize {
		return nil, fmt.Errorf("pbin: signature must be exactly %d bytes, got %d", SignatureSize, len(f.Signature))
	}
	if !isZipStart(f.Zip) {
		return nil, errors.New("pbin: payload is not a ZIP archive (missing \"PK\" signature)")
	}
	if len(f.Trailer) == 0 {
		return nil, errors.New("pbin: trailer must not be empty")
	}
	if expected := ExpectedTrailerSize(f.Version); expected >= 0 && len(f.Trailer) != expected {
		return nil, fmt.Errorf("pbin: version %d requires a %d-byte trailer, got %d", f.Version, expected, len(f.Trailer))
	}
	if f.Trailer[len(f.Trailer)-1] != f.Version {
		return nil, fmt.Errorf("pbin: trailer must end with the version byte 0x%02x, got 0x%02x", f.Version, f.Trailer[len(f.Trailer)-1])
	}

	out := make([]byte, 0, OverheadSize+len(f.Zip)+len(f.Trailer))
	out = append(out, magic[0], magic[1], magic[2], f.Version)
	out = append(out, f.Signature...)
	out = append(out, f.Zip...)
	out = append(out, f.Trailer...)
	return out, nil
}

// IsSigned reports whether the signature looks like a real signature rather
// than the all-zero placeholder used when packing without a private key.
func (f *File) IsSigned() bool {
	for _, b := range f.Signature {
		if b != 0 {
			return true
		}
	}
	return false
}

// BuildNumberTrailer returns a version-2 trailer carrying the given gate
// value (little-endian uint32) followed by the version byte.
func BuildNumberTrailer(build, version uint32) []byte {
	b := build
	return []byte{byte(b), byte(b >> 8), byte(b >> 16), byte(b >> 24), byte(version)}
}

// defaultTrailer returns the trailer bytes written by Pack for a version.
func defaultTrailer(version byte) []byte {
	switch version {
	case Version1:
		return []byte{Version1}
	case Version2:
		// The official gate value (13881) so the final client's pre-verify
		// gate passes; these four bytes are a gate value, not a content
		// checksum.
		return BuildNumberTrailer(DefaultBuildNumber, uint32(version))
	default:
		return []byte{version}
	}
}

// BuildNumber reports the v2 trailer's gate value. ok is false when the
// trailer is not the version-2 shape.
func (f *File) BuildNumber() (build uint32, ok bool) {
	if len(f.Trailer) != TrailerSizeV2 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(f.Trailer[:4]), true
}

// SetBuildNumber overwrites the v2 trailer's gate value.
func (f *File) SetBuildNumber(build uint32) error {
	if len(f.Trailer) != TrailerSizeV2 {
		return fmt.Errorf("pbin: gate value only exists in %d-byte (version 2) trailers, got %d", TrailerSizeV2, len(f.Trailer))
	}
	binary.LittleEndian.PutUint32(f.Trailer[:4], build)
	return nil
}

// Pack builds a container around a ZIP payload with a zero placeholder
// signature (Valve's game will reject it; see PackSigned for a real
// signature). Packing targets version 2 (the final 2023 client) unless
// stated otherwise.
func Pack(zipData []byte, version byte) (*File, error) {
	if version == 0 {
		return nil, errors.New("pbin: version must not be 0")
	}
	if !isZipStart(zipData) {
		return nil, errors.New("pbin: input is not a ZIP archive (missing \"PK\" signature)")
	}
	if version == Version2 && OverheadSize+len(zipData)+TrailerSizeV2 < MinSizeV2 {
		return nil, fmt.Errorf("pbin: the 2023 client rejects files smaller than %d bytes (this container would be %d)",
			MinSizeV2, OverheadSize+len(zipData)+TrailerSizeV2)
	}
	return &File{
		Version:   version,
		Signature: make([]byte, SignatureSize),
		Zip:       zipData,
		Trailer:   defaultTrailer(version),
	}, nil
}

// PackSigned is Pack plus a real signature over (Zip || Trailer) made with
// the given key, mirroring panzip's launcher_keypair_signdata: SHA-1, RSA
// PKCS#1 v1.5. The key must be 4096-bit so the signature fits the fixed
// 512-byte field. The final client verifies against Valve's embedded
// (rotated) public key, so only a patched verifier accepts a self-signed
// container.
func PackSigned(zipData []byte, version byte, key *rsa.PrivateKey) (*File, error) {
	f, err := Pack(zipData, version)
	if err != nil {
		return nil, err
	}
	signature, err := Sign(key, f.SignedPayload())
	if err != nil {
		return nil, err
	}
	f.Signature = signature
	return f, nil
}

// Sign computes the 512-byte pbin signature over a payload consisting of the
// ZIP bytes followed by the trailer.
func Sign(key *rsa.PrivateKey, payload []byte) ([]byte, error) {
	sum := sha1.Sum(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("pbin requires a %d-bit RSA key so the signature is %d bytes (got %d bytes)", SignatureSize*8, SignatureSize, len(signature))
	}
	return signature, nil
}

// Verify checks the container signature (over ZIP || trailer) against a
// public key.
func (f *File) Verify(key *rsa.PublicKey) error {
	sum := sha1.Sum(f.SignedPayload())
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, sum[:], f.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// LoadPrivateKey reads an RSA private key from PEM data, accepting both
// PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") encodings.
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in key file")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#1 key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not an RSA key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// Entry describes one file inside the embedded ZIP archive.
type Entry struct {
	Name             string
	CompressedSize   int64
	UncompressedSize int64
}

// ZipEntries opens the container payload as a ZIP archive and lists its files.
func (f *File) ZipEntries() ([]Entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(f.Zip), int64(len(f.Zip)))
	if err != nil {
		return nil, fmt.Errorf("reading embedded ZIP: %w", err)
	}
	entries := make([]Entry, 0, len(zr.File))
	for _, zf := range zr.File {
		entries = append(entries, Entry{
			Name:             zf.Name,
			CompressedSize:   int64(zf.CompressedSize64),
			UncompressedSize: int64(zf.UncompressedSize64),
		})
	}
	return entries, nil
}
