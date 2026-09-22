package pbin

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// buildZip creates a small but real ZIP archive for use as a payload.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("writing zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

func sampleZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, map[string]string{
		"panorama/layout.xml": "<root><panel class=\"x\"/></root>",
		"panorama/styles.css": "body { color: red; }",
		"panorama/script.js":  "const x = 1;",
	})
}

func TestRoundTrip(t *testing.T) {
	zipData := sampleZip(t)

	cases := []struct {
		version     byte
		trailerSize int
	}{
		{Version1, TrailerSizeV1},
		{Version2, TrailerSizeV2},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("v%d", tc.version), func(t *testing.T) {
			f, err := Pack(zipData, tc.version)
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if f.IsSigned() {
				t.Fatal("freshly packed container claims to be signed")
			}

			blob, err := f.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}

			wantLen := OverheadSize + len(zipData) + tc.trailerSize
			if len(blob) != wantLen {
				t.Fatalf("packed size = %d, want %d", len(blob), wantLen)
			}
			if blob[3] != tc.version || blob[len(blob)-1] != tc.version {
				t.Fatalf("version byte mismatch: header %d, trailer %d, want %d",
					blob[3], blob[len(blob)-1], tc.version)
			}

			// The 516-byte prefix trick: stripping it and the trailer must
			// leave a ZIP that Go's standard reader accepts.
			payload := blob[OverheadSize:]
			zipBytes := payload[:len(payload)-tc.trailerSize]
			if _, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes))); err != nil {
				t.Fatalf("stripped payload is not a valid zip: %v", err)
			}

			parsed, err := Parse(blob)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if parsed.Version != tc.version {
				t.Errorf("Version = %d, want %d", parsed.Version, tc.version)
			}
			if !bytes.Equal(parsed.Zip, zipData) {
				t.Error("payload round trip mismatch")
			}
			if len(parsed.Trailer) != tc.trailerSize {
				t.Errorf("len(Trailer) = %d, want %d", len(parsed.Trailer), tc.trailerSize)
			}
			if parsed.Trailer[len(parsed.Trailer)-1] != tc.version {
				t.Errorf("trailer does not end with version byte %d", tc.version)
			}
			if parsed.IsSigned() {
				t.Error("signature placeholder should parse as unsigned")
			}
			if len(parsed.Signature) != SignatureSize {
				t.Errorf("len(Signature) = %d, want %d", len(parsed.Signature), SignatureSize)
			}
		})
	}
}

func TestV2DefaultTrailer(t *testing.T) {
	f, err := Pack(sampleZip(t), Version2)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// The final client's pre-verify gate compares trailer[0:4] against the
	// value INETSUPPORT_003 reports; the official sample pins it to 13881.
	if want := []byte{0x39, 0x36, 0x00, 0x00, Version2}; !bytes.Equal(f.Trailer, want) {
		t.Errorf("v2 default trailer = %x, want %x", f.Trailer, want)
	}
	if build, ok := f.BuildNumber(); !ok || build != DefaultBuildNumber {
		t.Errorf("BuildNumber() = %d, %v; want %d, true", build, ok, DefaultBuildNumber)
	}
}

func TestSetBuildNumber(t *testing.T) {
	f, err := Pack(sampleZip(t), Version2)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := f.SetBuildNumber(0x11223344); err != nil {
		t.Fatalf("SetBuildNumber: %v", err)
	}
	if want := []byte{0x44, 0x33, 0x22, 0x11, Version2}; !bytes.Equal(f.Trailer, want) {
		t.Errorf("trailer after SetBuildNumber = %x, want %x", f.Trailer, want)
	}
	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	parsed, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if build, _ := parsed.BuildNumber(); build != 0x11223344 {
		t.Errorf("round-tripped gate value = %#x, want 0x11223344", build)
	}

	// Version 1 has no gate value.
	f1, err := Pack(sampleZip(t), Version1)
	if err != nil {
		t.Fatalf("Pack v1: %v", err)
	}
	if _, ok := f1.BuildNumber(); ok {
		t.Error("v1 trailer reports a gate value")
	}
	if err := f1.SetBuildNumber(1); err == nil {
		t.Error("SetBuildNumber on v1 succeeded, want error")
	}
}

func TestParseAutoDetectsUnknownVersion(t *testing.T) {
	// A version we have never seen still unpacks: the ZIP end is found via
	// the end-of-central-directory record, and the odd-size trailer survives.
	zipData := sampleZip(t)
	f := &File{
		Version:   3,
		Signature: make([]byte, SignatureSize),
		Zip:       zipData,
		Trailer:   []byte{9, 9, 9, 9, 3},
	}
	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	parsed, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Version != 3 {
		t.Errorf("Version = 3 mismatch: got %d", parsed.Version)
	}
	if !bytes.Equal(parsed.Zip, zipData) {
		t.Error("payload round trip mismatch for unknown version")
	}
	if !bytes.Equal(parsed.Trailer, f.Trailer) {
		t.Errorf("trailer = %x, want %x", parsed.Trailer, f.Trailer)
	}
}

func TestParseToleratesMislabeledTrailer(t *testing.T) {
	// Header claims v1 (1-byte trailer) but five bytes follow the ZIP: the
	// exact-size probe misses and the EOCD fallback still unpacks the file.
	zipData := sampleZip(t)
	blob := make([]byte, 0, OverheadSize+len(zipData)+TrailerSizeV2)
	blob = append(blob, 'P', 'A', 'N', Version1)
	blob = append(blob, make([]byte, SignatureSize)...)
	blob = append(blob, zipData...)
	blob = append(blob, 0, 0, 0, 0, Version1)

	parsed, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(parsed.Zip, zipData) {
		t.Error("payload round trip mismatch")
	}
	if len(parsed.Trailer) != TrailerSizeV2 {
		t.Errorf("len(Trailer) = %d, want %d (fallback)", len(parsed.Trailer), TrailerSizeV2)
	}
}

func TestParseRejects(t *testing.T) {
	valid, err := Pack(sampleZip(t), DefaultVersion)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	validBlob, err := valid.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"too short", []byte("PAN\x01")},
		{"bad magic", bytes.Repeat([]byte("XZQ"), 300)},
		{"trailer byte mismatch", func() []byte {
			b := append([]byte(nil), validBlob...)
			b[len(b)-1] = 0x09
			return b
		}()},
		{"payload not a zip", append([]byte{'P', 'A', 'N', Version1},
			append(bytes.Repeat([]byte{0}, SignatureSize),
				append(bytes.Repeat([]byte{0xBB}, 64), Version1)...)...)},
		{"payload without EOCD", append([]byte{'P', 'A', 'N', Version1},
			append(bytes.Repeat([]byte{0}, SignatureSize),
				append(append([]byte{'P', 'K', 0x03, 0x04}, bytes.Repeat([]byte{0xAA}, 100)...), Version1)...)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.data); err == nil {
				t.Fatal("Parse succeeded, want error")
			}
		})
	}

	if _, err := Parse(validBlob[:len(validBlob)-8]); err == nil {
		// Truncation breaks the trailing version-byte and/or ZIP checks.
		t.Fatal("Parse of truncated blob succeeded, want error")
	}
}

func TestMarshalRejectsInvalidFields(t *testing.T) {
	zipData := sampleZip(t)

	f, err := Pack(zipData, DefaultVersion)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	f.Signature = f.Signature[:8]
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with short signature succeeded, want error")
	}

	f, err = Pack(zipData, Version1)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	f.Version = 0
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with version 0 succeeded, want error")
	}

	f = &File{Version: Version1, Signature: make([]byte, SignatureSize), Zip: []byte("not a zip"), Trailer: []byte{Version1}}
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with non-zip payload succeeded, want error")
	}

	f, err = Pack(zipData, Version1)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	f.Trailer = nil
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with empty trailer succeeded, want error")
	}

	f.Trailer = []byte{0, 1} // v1 requires exactly one trailer byte
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with oversized v1 trailer succeeded, want error")
	}

	f.Trailer = []byte{Version2} // last byte must match the version
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with trailer not ending in version byte succeeded, want error")
	}
}

func TestPackEnforcesMinSizeV2(t *testing.T) {
	// An empty zip (EOCD only, 22 bytes) yields a container below the final
	// client's 581-byte floor; version 1 has no such constraint.
	var buf bytes.Buffer
	if err := zip.NewWriter(&buf).Close(); err != nil {
		t.Fatalf("building empty zip: %v", err)
	}
	emptyZip := buf.Bytes()

	if _, err := Pack(emptyZip, Version2); err == nil {
		t.Fatal("Pack v2 with undersized payload succeeded, want error")
	}
	if _, err := Pack(emptyZip, Version1); err != nil {
		t.Fatalf("Pack v1 with small payload: %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	zipData := sampleZip(t)

	for _, version := range []byte{Version1, Version2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			f, err := PackSigned(zipData, version, key)
			if err != nil {
				t.Fatalf("PackSigned: %v", err)
			}
			if !f.IsSigned() {
				t.Fatal("signed container reports unsigned")
			}
			if err := f.Verify(&key.PublicKey); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			// Tampering with the payload must break verification.
			f.Zip = append([]byte(nil), f.Zip...)
			copy(f.Zip[10:], "TAMPERED")
			if err := f.Verify(&key.PublicKey); err == nil {
				t.Fatal("Verify succeeded on tampered payload, want failure")
			}
		})
	}

	// The trailer is inside the signed range: flipping a byte breaks it.
	f, err := PackSigned(zipData, Version2, key)
	if err != nil {
		t.Fatalf("PackSigned: %v", err)
	}
	f.Trailer = append([]byte(nil), f.Trailer...)
	f.Trailer[0] = 0xFF
	if err := f.Verify(&key.PublicKey); err == nil {
		t.Fatal("Verify succeeded on tampered trailer, want failure")
	}

	// A short key cannot produce the fixed 512-byte signature field.
	shortKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating short RSA key: %v", err)
	}
	if _, err := PackSigned(zipData, Version2, shortKey); err == nil {
		t.Fatal("PackSigned with 2048-bit key succeeded, want error")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	pkcs1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	loaded, err := LoadPrivateKey(pkcs1)
	if err != nil {
		t.Fatalf("LoadPrivateKey(PKCS#1): %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Error("PKCS#1 round trip lost the modulus")
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8: %v", err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	loaded, err = LoadPrivateKey(pkcs8)
	if err != nil {
		t.Fatalf("LoadPrivateKey(PKCS#8): %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Error("PKCS#8 round trip lost the modulus")
	}

	if _, err := LoadPrivateKey([]byte("not pem")); err == nil {
		t.Error("LoadPrivateKey on garbage succeeded, want error")
	}
}

func TestZipEntries(t *testing.T) {
	zipData := buildZip(t, map[string]string{
		"panorama/layout.xml": "<root/>",
		"panorama/styles.css": "body {}",
	})
	f, err := Pack(zipData, DefaultVersion)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	entries, err := f.ZipEntries()
	if err != nil {
		t.Fatalf("ZipEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
		if e.UncompressedSize <= 0 {
			t.Errorf("entry %s has uncompressed size %d", e.Name, e.UncompressedSize)
		}
	}
	if !names["panorama/layout.xml"] || !names["panorama/styles.css"] {
		t.Errorf("unexpected entry names: %v", names)
	}
}
