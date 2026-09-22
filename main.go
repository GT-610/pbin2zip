// Command pbin2zip converts Panorama .pbin containers (the packaged
// csgo/panorama/code.pbin UI archive) to and from standard ZIP files.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GT-610/pbin2zip/internal/pbin"
)

const usageText = `pbin2zip converts Panorama .pbin containers to and from ZIP archives.

Usage:
  pbin2zip unpack [-o out.zip] <file.pbin | ->
  pbin2zip pack   [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->
  pbin2zip info   [-l] <file.pbin | ->

Commands:
  unpack  strip the 516-byte pbin prefix and trailer, writing a plain ZIP
  pack    wrap a ZIP in a pbin container (zeroed signature unless -sign)
  info    show container version, signature state, and ZIP contents

Options:
  -o string      output path (default: input with the other extension; "-" for stdout)
  -sign string   RSA private key PEM (PKCS#1 or PKCS#8) used to sign the container
  -version int   container version byte (default 1)
  -l             list every ZIP entry (info)

A .pbin layout is 'PAN'+version, a 512-byte RSA-4096/SHA-1 signature, the ZIP
payload, then the version byte again. Stripping the fixed 516-byte prefix (and
the trailing byte) yields a valid ZIP, as described at
https://www.unknowncheats.me/forum/2157360-post2.html

Note: the game verifies the signature with Valve's embedded public key, so a
container packed without Valve's private key fails that check; use -sign only
for research against a patched verifier.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}

	var err error
	switch args[0] {
	case "unpack":
		err = cmdUnpack(args[1:])
	case "pack":
		err = cmdPack(args[1:])
	case "info":
		err = cmdInfo(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "pbin2zip: unknown command %q\n\n", args[0])
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}

	if err != nil {
		var usageErr *commandUsageError
		if errors.As(err, &usageErr) {
			fmt.Fprintf(os.Stderr, "pbin2zip: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "pbin2zip: error: %v\n", err)
		return 1
	}
	return 0
}

// commandUsageError marks bad command lines: the message already contains the
// usage line, so no stack of flag noise is printed.
type commandUsageError struct{ msg string }

func (e *commandUsageError) Error() string { return e.msg }

func usageErrorf(format string, a ...any) error {
	return &commandUsageError{msg: fmt.Sprintf(format, a...)}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func cmdUnpack(args []string) error {
	fs := newFlagSet("unpack")
	out := fs.String("o", "", "output zip path (`-` for stdout)")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v\nusage: pbin2zip unpack [-o out.zip] <file.pbin | ->", err)
	}
	if fs.NArg() != 1 {
		return usageErrorf("unpack expects exactly one input\nusage: pbin2zip unpack [-o out.zip] <file.pbin | ->")
	}
	in := fs.Arg(0)

	data, err := readInput(in)
	if err != nil {
		return fmt.Errorf("reading %s: %w", displayName(in), err)
	}
	f, err := pbin.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", displayName(in), err)
	}

	entries, zipErr := f.ZipEntries()
	if zipErr != nil {
		fmt.Fprintf(os.Stderr, "pbin2zip: warning: %v\n", zipErr)
	}

	if *out == "" {
		if in == "-" {
			*out = "-"
		} else {
			*out = replaceExt(in, ".zip")
		}
	}
	if err := writeOutput(*out, f.Zip); err != nil {
		return fmt.Errorf("writing %s: %w", displayOut(*out), err)
	}

	fmt.Fprintf(os.Stderr, "unpacked %d bytes of ZIP (%d entries) from %s to %s\n",
		len(f.Zip), len(entries), displayName(in), displayOut(*out))
	return nil
}

func cmdPack(args []string) error {
	fs := newFlagSet("pack")
	out := fs.String("o", "", "output pbin path (`-` for stdout)")
	signPath := fs.String("sign", "", "RSA private key PEM used to sign the container")
	version := fs.Int("version", int(pbin.DefaultVersion), "container version byte")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v\nusage: pbin2zip pack [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->", err)
	}
	if fs.NArg() != 1 {
		return usageErrorf("pack expects exactly one input\nusage: pbin2zip pack [-o out.pbin] [-sign key.pem] [-version N] <file.zip | ->")
	}
	if *version <= 0 || *version > 255 {
		return usageErrorf("-version must be between 1 and 255, got %d", *version)
	}
	in := fs.Arg(0)

	data, err := readInput(in)
	if err != nil {
		return fmt.Errorf("reading %s: %w", displayName(in), err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%s is not a valid ZIP archive: %w", displayName(in), err)
	}

	var f *pbin.File
	if *signPath != "" {
		keyPEM, err := os.ReadFile(*signPath)
		if err != nil {
			return fmt.Errorf("reading key %s: %w", *signPath, err)
		}
		key, err := pbin.LoadPrivateKey(keyPEM)
		if err != nil {
			return fmt.Errorf("loading key %s: %w", *signPath, err)
		}
		f, err = pbin.PackSigned(data, byte(*version), key)
		if err != nil {
			return err
		}
	} else {
		f = pbin.Pack(data, byte(*version))
		fmt.Fprintln(os.Stderr, "pbin2zip: warning: packing with a zeroed signature; the game's integrity check will reject this container")
	}

	blob, err := f.MarshalBinary()
	if err != nil {
		return err
	}

	if *out == "" {
		if in == "-" {
			*out = "-"
		} else {
			*out = replaceExt(in, ".pbin")
		}
	}
	if err := writeOutput(*out, blob); err != nil {
		return fmt.Errorf("writing %s: %w", displayOut(*out), err)
	}

	state := "zeroed signature"
	if f.IsSigned() {
		state = "signed"
	}
	fmt.Fprintf(os.Stderr, "packed %d ZIP entries (%d payload bytes) from %s to %s (%d bytes, %s)\n",
		len(zr.File), len(data), displayName(in), displayOut(*out), len(blob), state)
	return nil
}

func cmdInfo(args []string) error {
	fs := newFlagSet("info")
	list := fs.Bool("l", false, "list every ZIP entry")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v\nusage: pbin2zip info [-l] <file.pbin | ->", err)
	}
	if fs.NArg() != 1 {
		return usageErrorf("info expects exactly one input\nusage: pbin2zip info [-l] <file.pbin | ->")
	}
	in := fs.Arg(0)

	data, err := readInput(in)
	if err != nil {
		return fmt.Errorf("reading %s: %w", displayName(in), err)
	}
	f, err := pbin.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", displayName(in), err)
	}

	sum := sha256.Sum256(f.Signature)
	fmt.Printf("file:        %s\n", displayName(in))
	fmt.Printf("size:        %d bytes\n", len(data))
	fmt.Printf("version:     %d\n", f.Version)
	fmt.Printf("signature:   %d bytes, sha256:%x\n", len(f.Signature), sum)
	if !f.IsSigned() {
		fmt.Printf("             (all-zero placeholder, container is unsigned)\n")
	}
	fmt.Printf("zip payload: %d bytes (prefix: %d, trailer: %d)\n",
		len(f.Zip), pbin.OverheadSize, pbin.TrailerSize)

	entries, err := f.ZipEntries()
	if err != nil {
		fmt.Printf("zip entries: unreadable (%v)\n", err)
		return nil
	}
	var compressed, uncompressed int64
	for _, e := range entries {
		compressed += e.CompressedSize
		uncompressed += e.UncompressedSize
	}
	fmt.Printf("zip entries: %d (%d bytes uncompressed, %d bytes compressed)\n",
		len(entries), uncompressed, compressed)

	if *list {
		for _, e := range entries {
			fmt.Printf("  %10d  %10d  %s\n", e.UncompressedSize, e.CompressedSize, e.Name)
		}
	}
	return nil
}

// readInput reads a file, treating "-" as stdin.
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// writeOutput writes a file, treating "-" as stdout.
func writeOutput(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// replaceExt swaps a file extension, e.g. code.pbin -> code.zip.
func replaceExt(path, newExt string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + newExt
}

// displayName renders "-" nicely in messages.
func displayName(path string) string {
	if path == "-" {
		return "<stdin>"
	}
	return path
}

// displayOut is displayName for output paths.
func displayOut(path string) string {
	if path == "-" {
		return "<stdout>"
	}
	return path
}
