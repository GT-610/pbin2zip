package pbin

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func TestRoundTrip(t *testing.T) {
	zipData := buildZip(t, map[string]string{
		"panorama/layout.xml": "<root/>",
		"panorama/styles.css": "body {}",
		"panorama/script.js":  "const x = 1;",
	})

	f := Pack(zipData, DefaultVersion)
	if f.IsSigned() {
		t.Fatal("freshly packed container claims to be signed")
	}

	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	wantLen := OverheadSize + len(zipData) + TrailerSize
	if len(blob) != wantLen {
		t.Fatalf("packed size = %d, want %d", len(blob), wantLen)
	}

	// The 516-byte prefix trick from the unknowncheats post: stripping it must
	// leave a ZIP that Go's standard reader accepts.
	stripped := blob[OverheadSize:]
	if _, err := zip.NewReader(bytes.NewReader(stripped[:len(stripped)-1]), int64(len(stripped)-1)); err != nil {
		t.Fatalf("stripped payload is not a valid zip: %v", err)
	}

	parsed, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Version != DefaultVersion {
		t.Errorf("Version = %d, want %d", parsed.Version, DefaultVersion)
	}
	if !bytes.Equal(parsed.Zip, zipData) {
		t.Error("payload round trip mismatch")
	}
	if parsed.IsSigned() {
		t.Error("signature placeholder should parse as unsigned")
	}
	if len(parsed.Signature) != SignatureSize {
		t.Errorf("len(Signature) = %d, want %d", len(parsed.Signature), SignatureSize)
	}
}

func TestParseRejects(t *testing.T) {
	valid := Pack(buildZip(t, map[string]string{"a.txt": "a"}), DefaultVersion)
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
		{"version mismatch", func() []byte {
			b := append([]byte(nil), validBlob...)
			b[len(b)-1] = 0x02
			return b
		}()},
		{"payload not a zip", append([]byte{'P', 'A', 'N', 0x01},
			append(bytes.Repeat([]byte{0xAA}, SignatureSize),
				append(bytes.Repeat([]byte{0xBB}, 64), 0x01)...)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.data); err == nil {
				t.Fatal("Parse succeeded, want error")
			}
		})
	}

	if _, err := Parse(validBlob[:len(validBlob)-8]); err == nil {
		// Truncating the payload keeps the magic but breaks both the trailing
		// version byte check and the ZIP check; either way it must fail.
		t.Fatal("Parse of truncated blob succeeded, want error")
	}
}

func TestMarshalRejectsInvalidFields(t *testing.T) {
	zipData := buildZip(t, map[string]string{"a.txt": "a"})

	f := Pack(zipData, DefaultVersion)
	f.Signature = f.Signature[:8]
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with short signature succeeded, want error")
	}

	f = Pack(zipData, 0)
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with version 0 succeeded, want error")
	}

	f = Pack([]byte("not a zip"), DefaultVersion)
	if _, err := f.MarshalBinary(); err == nil {
		t.Error("MarshalBinary with non-zip payload succeeded, want error")
	}
}

func TestSignAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	zipData := buildZip(t, map[string]string{"panorama/layout.xml": "<root/>"})
	f, err := PackSigned(zipData, DefaultVersion, key)
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

	// A short key cannot produce the fixed 512-byte signature field.
	shortKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating short RSA key: %v", err)
	}
	if _, err := PackSigned(zipData, DefaultVersion, shortKey); err == nil {
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
	entries, err := Pack(zipData, DefaultVersion).ZipEntries()
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
