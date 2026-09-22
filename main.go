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
  pbin2zip verify <file.pbin | ->

Commands:
  unpack  strip the signed envelope, writing a plain ZIP; the container
          version is auto-detected from the header (v1, v2, and unknown
          versions all unpack)
  pack    wrap a ZIP in a pbin container, targeting the final 2023 client
          (version 2) by default; zeroed signature unless -sign
  info    show container version, signature state, trailer, and ZIP contents
  verify  check a container the way the stock final 2023 client would:
          at least 581 bytes, version-2 envelope, gate value 13881,
          official RSA signature; exit 0 when the client would load it,
          exit 1 when it would not

Options:
  -o string         output path (default: input with the other extension; "-" for stdout)
  -sign string      RSA private key PEM (PKCS#1 or PKCS#8) used to sign the container
  -template string  reuse the signature and trailer of an existing pbin; the
                    result is verified against the official key, so an
                    unmodified round trip reproduces a byte-identical file
                    the stock client accepts
  -build-number N   v2 trailer gate value the client expects (default 13881)
  -version int      container version: 2 = final 2023 client (default), 1 = pre-2020
  -l                list every ZIP entry (info)

Envelope layout (all versions): 'PAN'+version header, 512-byte RSA-4096/SHA-1
signature over everything after the prefix, the ZIP, then a trailer ending
with the version byte — 1 byte for v1, 5 bytes for v2 (a gate value the
client checks before the signature). The fixed 516-byte prefix is what
"remove the first 516 bytes" strips:
https://www.unknowncheats.me/forum/2157360-post2.html

Note: the 2023 client verifies the signature with Valve's embedded (rotated)
public key, fail-closed. Unmodified round trips should use -template;
modified content cannot satisfy a stock client without patching the
verifier (panorama.dll FUN_10011f80, verify call at RVA 0x12548), so use
-sign only for research against such a patched verifier.
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
	case "verify":
		err = cmdVerify(args[1:])
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

	fmt.Fprintf(os.Stderr, "unpacked %d bytes of ZIP (%d entries) from %s to %s (container version %d, %d-byte trailer)\n",
		len(f.Zip), len(entries), displayName(in), displayOut(*out), f.Version, len(f.Trailer))
	return nil
}

func cmdPack(args []string) error {
	fs := newFlagSet("pack")
	out := fs.String("o", "", "output pbin path (`-` for stdout)")
	signPath := fs.String("sign", "", "RSA private key PEM used to sign the container")
	template := fs.String("template", "", "reuse signature and trailer from this pbin (verified against the official key)")
	buildNumber := fs.Uint64("build-number", pbin.DefaultBuildNumber, "v2 trailer gate value the client expects")
	version := fs.Int("version", int(pbin.DefaultVersion), "container version (2 = final 2023 client, 1 = pre-2020)")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v\nusage: pbin2zip pack [-o out.pbin] [-sign key.pem | -template ref.pbin] [-build-number N] [-version N] <file.zip | ->", err)
	}
	if fs.NArg() != 1 {
		return usageErrorf("pack expects exactly one input\nusage: pbin2zip pack [-o out.pbin] [-sign key.pem | -template ref.pbin] [-build-number N] [-version N] <file.zip | ->")
	}
	if *buildNumber > uint64(^uint32(0)) {
		return usageErrorf("-build-number must be between 0 and 4294967295, got %d", *buildNumber)
	}
	if *version <= 0 || *version > 255 {
		return usageErrorf("-version must be between 1 and 255, got %d", *version)
	}
	if *version != pbin.Version1 && *version != pbin.Version2 {
		fmt.Fprintf(os.Stderr, "pbin2zip: warning: container version %d is not verified against any known client; output is best-effort\n", *version)
	}
	if *template != "" && *signPath != "" {
		return usageErrorf("-template and -sign cannot be combined")
	}
	bnExplicit := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "build-number" {
			bnExplicit = true
		}
	})
	if bnExplicit && *version != pbin.Version2 {
		return usageErrorf("-build-number only applies to version 2 (got -version %d)", *version)
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
	templateVerified := false
	switch {
	case *signPath != "":
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
	case *template != "":
		f, err = pbin.Pack(data, byte(*version))
		if err != nil {
			return err
		}
		refData, err := os.ReadFile(*template)
		if err != nil {
			return fmt.Errorf("reading template %s: %w", *template, err)
		}
		ref, err := pbin.Parse(refData)
		if err != nil {
			return fmt.Errorf("template %s: %w", *template, err)
		}
		if ref.Version != f.Version {
			return fmt.Errorf("template version %d does not match pack version %d", ref.Version, f.Version)
		}
		f.Signature = append([]byte(nil), ref.Signature...)
		f.Trailer = append([]byte(nil), ref.Trailer...)
		if f.Version == pbin.Version2 {
			key, err := pbin.OfficialPublicKey()
			if err != nil {
				return err
			}
			if err := f.Verify(key); err != nil {
				return fmt.Errorf("template envelope does not cover this ZIP: %w — the stock client would reject the output (input must be the template's original, unmodified ZIP)", err)
			}
			templateVerified = true
		} else {
			fmt.Fprintf(os.Stderr, "pbin2zip: warning: template envelope copied but not verified (no embedded key for version %d)\n", f.Version)
		}
	default:
		f, err = pbin.Pack(data, byte(*version))
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "pbin2zip: warning: packing with a zeroed signature; the stock game will reject this container (use -template for unmodified round trips, or patch the verifier for research)")
	}
	if bnExplicit {
		if err := f.SetBuildNumber(uint32(*buildNumber)); err != nil {
			return err
		}
	}
	if templateVerified {
		// The gate value lives in the trailer, which is part of the signed
		// range, so -build-number can invalidate a copied template signature.
		// Verify once more after any gate rewrite and say which way the
		// stock client would now treat the output.
		key, err := pbin.OfficialPublicKey()
		if err != nil {
			return err
		}
		if err := f.Verify(key); err != nil {
			fmt.Fprintf(os.Stderr, "pbin2zip: warning: the gate value set by -build-number breaks the copied signature (the trailer is signed too) — the stock client will reject this output\n")
		} else {
			fmt.Fprintf(os.Stderr, "pbin2zip: template envelope verified against the official key; output is byte-identical to %s\n", displayName(*template))
		}
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
	fmt.Fprintf(os.Stderr, "packed %d ZIP entries (%d payload bytes) from %s to %s (%d bytes, version %d, %s)\n",
		len(zr.File), len(data), displayName(in), displayOut(*out), len(blob), f.Version, state)
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
	trailerNote := "expected: unknown version"
	if expected := pbin.ExpectedTrailerSize(f.Version); expected >= 0 {
		trailerNote = fmt.Sprintf("expected %d", expected)
	}
	fmt.Printf("file:        %s\n", displayName(in))
	fmt.Printf("size:        %d bytes\n", len(data))
	fmt.Printf("version:     %d%s\n", f.Version, versionLabel(f.Version))
	fmt.Printf("signature:   %d bytes, sha256:%x\n", len(f.Signature), sum)
	if !f.IsSigned() {
		fmt.Printf("             (all-zero placeholder, container is unsigned)\n")
	}
	fmt.Printf("zip payload: %d bytes (prefix: %d, trailer: %d bytes, %s): %x\n",
		len(f.Zip), pbin.OverheadSize, len(f.Trailer), trailerNote, f.Trailer)
	if build, ok := f.BuildNumber(); ok {
		fmt.Printf("gate value:  %d (0x%08x) — checked against INETSUPPORT_003 before the signature\n", build, build)
	}

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

// cmdVerify checks a container against exactly what the stock final (2023)
// client enforces, in the client's own order: a file of at least 581 bytes
// (CMP ECX,0x245 in FUN_10011f80), a version-2 envelope, the gate value
// INETSUPPORT_003 reports (13881 for the frozen build), and a valid
// signature under Valve's embedded public key. Exit status 0 means the
// client would accept the file, 1 means it would reject it.
func cmdVerify(args []string) error {
	fs := newFlagSet("verify")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v\nusage: pbin2zip verify <file.pbin | ->", err)
	}
	if fs.NArg() != 1 {
		return usageErrorf("verify expects exactly one input\nusage: pbin2zip verify <file.pbin | ->")
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

	var problems []string
	if len(data) < pbin.MinSizeV2 {
		problems = append(problems, fmt.Sprintf("file is %d bytes, the final client requires at least %d",
			len(data), pbin.MinSizeV2))
	}
	if f.Version != pbin.Version2 {
		problems = append(problems, fmt.Sprintf("container version %d%s — the final client only reads version 2",
			f.Version, versionLabel(f.Version)))
	}
	if build, ok := f.BuildNumber(); !ok {
		problems = append(problems, "trailer carries no v2 gate value")
	} else if build != pbin.DefaultBuildNumber {
		problems = append(problems, fmt.Sprintf("gate value %d (0x%08x), the client expects %d (0x%08x)",
			build, build, pbin.DefaultBuildNumber, pbin.DefaultBuildNumber))
	}
	key, err := pbin.OfficialPublicKey()
	if err != nil {
		return err
	}
	if err := f.Verify(key); err != nil {
		problems = append(problems, err.Error())
	}

	if len(problems) == 0 {
		fmt.Printf("%s: accepted — version 2, gate %d, official signature valid\n",
			displayName(in), pbin.DefaultBuildNumber)
		return nil
	}
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "pbin2zip: %s: %s\n", displayName(in), p)
	}
	return fmt.Errorf("the stock 2023 client would reject this container (%d problem(s))", len(problems))
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

// versionLabel names the container versions we can vouch for.
func versionLabel(version byte) string {
	switch version {
	case pbin.Version1:
		return " (pre-2020 client)"
	case pbin.Version2:
		return " (final 2023 client)"
	default:
		return " (unknown)"
	}
}

// displayOut is displayName for output paths.
func displayOut(path string) string {
	if path == "-" {
		return "<stdout>"
	}
	return path
}
