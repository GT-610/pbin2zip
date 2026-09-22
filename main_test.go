package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// makeTestZip writes a small ZIP file into the given directory.
func makeTestZip(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "code.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("panorama/layout.xml")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := w.Write([]byte("<root/>")); err != nil {
		t.Fatalf("writing zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("writing zip file: %v", err)
	}
	return path
}

func TestReplaceExt(t *testing.T) {
	cases := []struct{ in, want string }{
		{"code.pbin", "code.zip"},
		{"code.zip", "code.pbin"},
		{filepath.Join("a", "b.pbin"), filepath.Join("a", "b.zip")},
		{"noext", "noext.zip"},
	}
	for _, tc := range cases {
		got := replaceExt(tc.in, filepath.Ext(tc.want))
		if got != tc.want {
			t.Errorf("replaceExt(%q, %q) = %q, want %q", tc.in, filepath.Ext(tc.want), got, tc.want)
		}
	}
}

func TestRunRoundTrip(t *testing.T) {
	dir := t.TempDir()
	zipPath := makeTestZip(t, dir)
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("reading test zip: %v", err)
	}

	pbinPath := filepath.Join(dir, "out.pbin")
	if code := run([]string{"pack", "-o", pbinPath, zipPath}); code != 0 {
		t.Fatalf("pack exit code = %d, want 0", code)
	}

	outPath := filepath.Join(dir, "roundtrip.zip")
	if code := run([]string{"unpack", "-o", outPath, pbinPath}); code != 0 {
		t.Fatalf("unpack exit code = %d, want 0", code)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading unpacked zip: %v", err)
	}
	if !bytes.Equal(got, zipBytes) {
		t.Fatal("round trip changed the ZIP payload")
	}

	// info must accept the container we just built.
	if code := run([]string{"info", pbinPath}); code != 0 {
		t.Fatalf("info exit code = %d, want 0", code)
	}
}

func TestRunDefaultOutputName(t *testing.T) {
	dir := t.TempDir()
	zipPath := makeTestZip(t, dir)
	if code := run([]string{"pack", zipPath}); code != 0 {
		t.Fatalf("pack exit code = %d, want 0", code)
	}
	pbinPath := filepath.Join(dir, "code.pbin")
	if _, err := os.Stat(pbinPath); err != nil {
		t.Fatalf("default pack output missing: %v", err)
	}
	if code := run([]string{"unpack", pbinPath}); code != 0 {
		t.Fatalf("unpack exit code = %d, want 0", code)
	}
	// The default unpack output overwrites code.zip with identical bytes.
	got, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("reading default unpack output: %v", err)
	}
	orig := makeTestZipBytes(t)
	if !bytes.Equal(got, orig) {
		t.Fatal("default unpack output differs from the original zip")
	}
}

func makeTestZipBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("panorama/layout.xml")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := w.Write([]byte("<root/>")); err != nil {
		t.Fatalf("writing zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()

	if code := run(nil); code != 2 {
		t.Errorf("no args: exit code = %d, want 2", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Errorf("unknown command: exit code = %d, want 2", code)
	}
	if code := run([]string{"unpack"}); code != 2 {
		t.Errorf("missing input: exit code = %d, want 2", code)
	}
	if code := run([]string{"unpack", filepath.Join(dir, "missing.pbin")}); code != 1 {
		t.Errorf("missing file: exit code = %d, want 1", code)
	}
	if code := run([]string{"pack", "-version", "0", makeTestZip(t, dir)}); code != 2 {
		t.Errorf("bad version: exit code = %d, want 2", code)
	}

	// A non-zip input must be rejected by pack.
	notZip := filepath.Join(dir, "not.zip")
	if err := os.WriteFile(notZip, []byte("hello"), 0o644); err != nil {
		t.Fatalf("writing garbage input: %v", err)
	}
	if code := run([]string{"pack", notZip}); code != 1 {
		t.Errorf("non-zip input: exit code = %d, want 1", code)
	}

	// A non-pbin input must be rejected by unpack.
	if code := run([]string{"unpack", notZip}); code != 1 {
		t.Errorf("non-pbin input: exit code = %d, want 1", code)
	}
}
