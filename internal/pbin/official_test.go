package pbin

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// TestOfficialSample verifies the tool's assumptions against Valve's
// unmodified final (2023) code.pbin when it is available locally. The sample
// is game content and is not committed: place it at .vscode/code.pbin in the
// repository root, or point PBIN2ZIP_SAMPLE at it. The test skips otherwise.
//
// The public key in testdata/panoramapack_2023.der was extracted from the
// shipped panorama.dll parser (FUN_10011f80) by tools/certcheck.
func TestOfficialSample(t *testing.T) {
	sample := os.Getenv("PBIN2ZIP_SAMPLE")
	if sample == "" {
		sample = filepath.Join("..", "..", ".vscode", "code.pbin")
	}
	data, err := os.ReadFile(sample)
	if err != nil {
		t.Skipf("official code.pbin not available: %v", err)
	}

	der, err := os.ReadFile(filepath.Join("testdata", "panoramapack_2023.der"))
	if err != nil {
		t.Fatalf("reading embedded public key: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parsing embedded public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("embedded key is not RSA")
	}

	f, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Structural facts of the final client's format.
	if f.Version != Version2 {
		t.Errorf("Version = %d, want %d", f.Version, Version2)
	}
	if len(f.Trailer) != TrailerSizeV2 {
		t.Errorf("len(Trailer) = %d, want %d", len(f.Trailer), TrailerSizeV2)
	} else if f.Trailer[len(f.Trailer)-1] != Version2 {
		t.Errorf("trailer does not end with %d: %x", Version2, f.Trailer)
	}
	if want := len(data) - OverheadSize - TrailerSizeV2; len(f.Zip) != want {
		t.Errorf("len(Zip) = %d, want %d", len(f.Zip), want)
	}
	// The trailer's gate value must match what pack now emits by default;
	// it is what the final client's pre-verify gate compares against.
	if build, ok := f.BuildNumber(); !ok || build != DefaultBuildNumber {
		t.Errorf("official gate value = %d (ok=%v), want DefaultBuildNumber %d", build, ok, DefaultBuildNumber)
	}

	// Re-marshaling must reproduce the official file byte for byte.
	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(blob, data) {
		t.Fatal("re-marshaled container differs from the official file")
	}

	// The official signature must verify against the final client's key.
	// This is what pins SignedPayload to [516, EOF) = ZIP || trailer.
	if !f.IsSigned() {
		t.Error("official container reports unsigned")
	}
	if err := f.Verify(rsaPub); err != nil {
		t.Fatalf("official signature does not verify: %v", err)
	}

	// And any payload change must break it.
	f.Zip = append([]byte(nil), f.Zip...)
	f.Zip[100] ^= 0x01
	if err := f.Verify(rsaPub); err == nil {
		t.Fatal("Verify succeeded on tampered official payload")
	}

	entries, err := f.ZipEntries()
	if err != nil {
		t.Fatalf("ZipEntries: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("official ZIP has no entries")
	}
	t.Logf("official sample: %d bytes, %d zip entries, trailer %x, key %d bits (E=%d)",
		len(data), len(entries), f.Trailer, rsaPub.N.BitLen(), rsaPub.E)
}
