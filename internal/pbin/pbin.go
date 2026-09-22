// Package pbin implements reading and writing of Panorama .pbin containers.
//
// A .pbin is the packaged Panorama UI archive shipped with CS:GO as
// csgo/panorama/code.pbin. Valve's own panzip tool builds it, and the engine
// verifies it before mounting the embedded ZIP. The on-disk layout is:
//
//	offset  size  contents
//	0       4     header: 'P', 'A', 'N', version (currently 1)
//	4       512   RSA-4096 PKCS#1 v1.5 SHA-1 signature over (zip || version)
//	516     n     a standard ZIP archive
//	516+n   1     version byte again, covered by the signature
//
// Because the 4-byte header plus the 512-byte signature is a fixed 516-byte
// prefix, stripping it yields a regular ZIP file, which is exactly the trick
// described at https://www.unknowncheats.me/forum/2157360-post2.html
//
// Reference: utils/panzip/panzip.cpp (writer) and
// panorama/source2/panoramauiengine.cpp (PanoramaResourceFileIntegrityCheck,
// reader) from the leaked CS:GO source tree.
package pbin

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// HeaderSize is the size of the fixed 'PAN'+version header.
	HeaderSize = 4

	// SignatureSize is the size of the RSA signature. Valve's verifier hardcodes
	// 512 bytes (a 4096-bit RSA key); panzip writes exactly that much.
	SignatureSize = 512

	// OverheadSize is the fixed prefix preceding the ZIP blob (header + signature).
	// Removing this many bytes from a .pbin produces a plain ZIP file.
	OverheadSize = HeaderSize + SignatureSize // 516

	// TrailerSize is the trailing version byte after the ZIP blob.
	TrailerSize = 1

	// MinSize is the smallest possible .pbin: header + signature + trailer.
	MinSize = OverheadSize + TrailerSize // 517

	// DefaultVersion is the container version used by current CS:GO builds.
	DefaultVersion = 1
)

// magic is the 'PAN' prefix of the header.
var magic = [3]byte{'P', 'A', 'N'}

// ErrNotPbin is returned by Parse when the data does not start with 'PAN'.
var ErrNotPbin = errors.New("not a pbin container: missing \"PAN\" magic")

// File is a parsed .pbin container.
type File struct {
	// Version is the container version, stored both in the header and in the
	// trailing byte, and covered by the signature.
	Version byte

	// Signature is the RSA-4096 PKCS#1 v1.5 SHA-1 signature over (Zip || Version).
	// For containers packed without Valve's private key it is a zero placeholder.
	Signature []byte

	// Zip is the raw ZIP archive payload, verbatim.
	Zip []byte
}

// Parse validates a .pbin and splits it into header, signature, and ZIP payload.
func Parse(data []byte) (*File, error) {
	if len(data) < MinSize {
		return nil, fmt.Errorf("not a pbin container: only %d bytes (minimum is %d)", len(data), MinSize)
	}
	if data[0] != magic[0] || data[1] != magic[1] || data[2] != magic[2] {
		return nil, fmt.Errorf("%w, got %q", ErrNotPbin, data[:min(HeaderSize, len(data))])
	}

	version := data[3]
	trailer := data[len(data)-1]
	if trailer != version {
		return nil, fmt.Errorf("corrupt pbin: trailing version byte 0x%02x does not match header version 0x%02x", trailer, version)
	}

	signature := make([]byte, SignatureSize)
	copy(signature, data[HeaderSize:OverheadSize])

	// The payload must be a plausible ZIP: it has to start with the local file
	// header signature. Anything else means the file is not really a pbin.
	zipData := data[OverheadSize : len(data)-TrailerSize]
	if len(zipData) < 4 || !bytes.Equal(zipData[:4], []byte("PK\x03\x04")) {
		return nil, errors.New("corrupt pbin: payload after the 516-byte prefix is not a ZIP archive (missing \"PK\\x03\\x04\" local file header)")
	}

	return &File{Version: version, Signature: signature, Zip: zipData}, nil
}

// MarshalBinary serializes the container back into .pbin bytes.
func (f *File) MarshalBinary() ([]byte, error) {
	if f.Version == 0 {
		return nil, errors.New("pbin: version must not be 0")
	}
	if len(f.Signature) != SignatureSize {
		return nil, fmt.Errorf("pbin: signature must be exactly %d bytes, got %d", SignatureSize, len(f.Signature))
	}
	if len(f.Zip) < 4 || !bytes.Equal(f.Zip[:4], []byte("PK\x03\x04")) {
		return nil, errors.New("pbin: payload is not a ZIP archive (missing \"PK\\x03\\x04\" local file header)")
	}

	out := make([]byte, 0, OverheadSize+len(f.Zip)+TrailerSize)
	out = append(out, magic[0], magic[1], magic[2], f.Version)
	out = append(out, f.Signature...)
	out = append(out, f.Zip...)
	out = append(out, f.Version)
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

// Pack builds a container around a ZIP payload with a zero placeholder
// signature (Valve's game will reject it; see PackSigned for a real signature).
func Pack(zipData []byte, version byte) *File {
	signature := make([]byte, SignatureSize)
	return &File{Version: version, Signature: signature, Zip: zipData}
}

// PackSigned builds a container around a ZIP payload and signs it with the
// given private key, mirroring panzip's launcher_keypair_signdata: SHA-1 of
// (zip || version), RSA PKCS#1 v1.5. The key must be a 4096-bit RSA key so the
// signature fits the fixed 512-byte field expected by the engine verifier.
func PackSigned(zipData []byte, version byte, key *rsa.PrivateKey) (*File, error) {
	if version == 0 {
		return nil, errors.New("pbin: version must not be 0")
	}
	signature, err := Sign(key, zipData, version)
	if err != nil {
		return nil, err
	}
	return &File{Version: version, Signature: signature, Zip: zipData}, nil
}

// Sign computes the 512-byte pbin signature over (zip || version).
func Sign(key *rsa.PrivateKey, zipData []byte, version byte) ([]byte, error) {
	digest, err := digest(zipData, version)
	if err != nil {
		return nil, err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("pbin requires a %d-bit RSA key so the signature is %d bytes (got %d bytes)", SignatureSize*8, SignatureSize, len(signature))
	}
	return signature, nil
}

// Verify checks the container signature against a public key.
func (f *File) Verify(key *rsa.PublicKey) error {
	digest, err := digest(f.Zip, f.Version)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, digest, f.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// digest mirrors the signed payload: SHA-1 over (zip bytes || version byte).
func digest(zipData []byte, version byte) ([]byte, error) {
	h := sha1.New()
	if _, err := h.Write(zipData); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{version}); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
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
