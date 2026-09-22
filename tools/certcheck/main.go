// Command certcheck is the offline analysis tool behind this repository's
// reverse-engineering claims. Run it from the repository root:
//
//	go run ./tools/certcheck <code.pbin>
//
// It:
//  1. reconstructs the 548-byte DER public key the final client materializes
//     on the stack in panorama.dll FUN_10011f80 (immediate operands of the
//     MOV-dword chain, captured via Ghidra read_memory at 0x10012035) and
//     persists it to internal/pbin/testdata/panoramapack_2023.der;
//  2. verifies the official code.pbin signature over several candidate byte
//     ranges to pin down the signed range ([516, EOF) is the one that
//     passes);
//  3. decodes the 5-byte v2 trailer and searches for the semantics of its
//     first four bytes among common checksum algorithms (no match found as
//     of the official final sample).
package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"math/big"
	"os"
)

// codeHex is the raw instruction bytes of panorama.dll [0x10012035, +1304),
// captured from the shipped final client.
const codeHex = "c785dcfdffff30820220c785e0fdffff300d0609c785e4fdffff2a864886c785e8fdfffff70d0101c785ecfdffff01050003c785f0fdffff82020d00c785f4fdffff30820208c785f8fdffff02820201c785fcfdffff00b09fd8c78500feffff723e5f79c78504feffff2889fa2fc78508feffffadf6b189c7850cfeffffe3fc21acc78510feffff0548f0e5c78514feffffe8290a2ac78518feffff570e8f74c7851cfeffff0c03c70fc78520feffff59e70fc5c78524feffffc4857c20c78528feffff9348f5a7c7852cfeffffc4668773c78530feffff42d10db8c78534feffff37e6f42cc78538feffff7b746cb0c7853cfeffffb8e9d256c78540feffffa80870c1c78544feffff87b8f67cc78548feffff84277a4ec7854cfeffff2d2722c7c78550feffff255beb80c78554feffffdc5f5b8dc78558feffffb06d6839c7855cfeffff590da0a8c78560feffff2182085fc78564feffff94e26b44c78568feffff8b453a2dc7856cfeffffe7e21863c78570fefffff3c1e3e7c78574feffff59bb1f9cc78578feffff4d0ed256c7857cfeffff83c2c49ec78580feffffc23f4353c78584feffffd04c0f74c78588feffffdb15e9eec7858cfeffff0358171ec78590feffffe05231d5c78594feffff27c1cfccc78598feffff28a5f263c7859cfeffff4956aed9c785a0feffffe2a1926fc785a4feffff23260e9ec785a8feffff4558e937c785acfeffffec56f679c785b0feffffea206194c785b4feffffb705ea35c785b8feffff4a28b448c785bcfeffff548310bac785c0feffff40ce93a7c785c4feffffba3ea7ccc785c8feffffefc27f45c785ccfeffff51b8e5abc785d0feffff91ba3cffc785d4feffff38068f5bc785d8feffffece993f5c785dcfeffff1b3d20b4c785e0feffff32ccd0b6c785e4feffff1378c2d4c785e8feffff4cd7e170c785ecfeffff987e43b0c785f0feffff9dc2b9b2c785f4feffffaf308a03c785f8feffff20130966c785fcfeffffb197204ac78500ffffff57b7c792c78504ffffff42c63901c78508ffffff39fc2c71c7850cffffff4ec955c0c78510ffffffc4285124c78514ffffffb1e689b6c78518ffffff4a12201bc7851cfffffffbaf57af8b075183c004c78520ffffff9709886150518b0b8d85dcfdffff508b4510c78524ffffff5aba4f9ac78528ffffff47f32697c7852cffffff72fc97498b1083c205c78530ffffff424fbe4bc78534ffffff43ac604ac78538fffffffced4d7bc7853cffffffb573d4dac78540ffffff5dc29219c78544ffffffae3bd5c1c78548ffffff40611295c7854cffffffa4fa5234c78550fffffff0c2bb53c78554ffffffd3812ad6c78558ffffff63806bf7c7855cffffff71756d96c78560fffffff6c88fbdc78564ffffff56722511c78568ffffffc54297dcc7856cffffffc930e50cc78570ffffffdd1b46b5c78574ffffff8e2ca3b9c78578ffffff1363479ac7857cffffff3e8b0799c7458076135300c745843a0d127ec745888254dcb9c7458c490e6306c74590b1c98835c745946d75de61c745985efeac71c7459c16b0dd72c745a0ed602dabc745a4ae82833ec745a82f29bb07c745ac592fbce1c745b0cb0748bdc745b4f9e6777dc745b8873d1ab8c745bcbf6b99abc745c0ea5dbb6cc745c45b92292dc745c8e1a9b6e7c745cc4058fe16c745d038ed4284c745d4dc6f8b1ec745d80800bd76c745dce0a295e2c745e0c4a3a6e8c745e432c78900c745e82ab7b3dec745ecb488f6d5c745f0b0ba89a7c745f4ecaf7044c745f86e50349cc745fc75020111e8131a0000"

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b byte
		for k := 0; k < 2; k++ {
			c := s[2*i+k]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			default:
				panic("bad hex")
			}
			b = b<<4 | v
		}
		out[i] = b
	}
	return out
}

// extractCert walks the deterministic MOV-dword chain: 105 x C7 85 disp32
// (EBP-0x224 .. EBP-0x84, step 4) then 32 x C7 45 disp8
// (EBP-0x80 .. EBP-0x4, step 4), collecting the 137 immediates = 548 bytes.
func extractCert(code []byte) ([]byte, error) {
	hexOf := func(b []byte) string {
		const digits = "0123456789abcdef"
		s := make([]byte, len(b)*2)
		for i, v := range b {
			s[2*i] = digits[v>>4]
			s[2*i+1] = digits[v&0xf]
		}
		return string(s)
	}
	src := hexOf(code)

	var cert []byte
	pos := 0
	find := func(pat string) (int, error) {
		for i := pos; i+len(pat) <= len(src); i++ {
			if src[i:i+len(pat)] == pat {
				return i, nil
			}
		}
		return 0, fmt.Errorf("pattern %s not found after offset %d", pat, pos)
	}

	// Section 1: C7 85 disp32 imm32, disp from -0x224 to -0x84.
	for v := -0x224; v <= -0x84; v += 4 {
		var d [4]byte
		binary.LittleEndian.PutUint32(d[:], uint32(int32(v)))
		pat := "c785" + hexOf(d[:])
		i, err := find(pat)
		if err != nil {
			return nil, err
		}
		imm := src[i+12 : i+20]
		cert = append(cert, mustHex(imm)...)
		pos = i + 20
	}
	// Section 2: C7 45 disp8 imm32, disp from -0x80 to -0x4.
	for v := -0x80; v <= -0x4; v += 4 {
		pat := fmt.Sprintf("c745%02x", byte(int8(v)))
		i, err := find(pat)
		if err != nil {
			return nil, err
		}
		// "c745" + 1 disp byte = 6 hex chars, imm32 = 8 hex chars.
		imm := src[i+6 : i+14]
		cert = append(cert, mustHex(imm)...)
		pos = i + 14
	}
	return cert, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: certcheck <code.pbin>")
		os.Exit(2)
	}
	pbinPath := os.Args[1]

	code := mustHex(codeHex)
	cert, err := extractCert(code)
	if err != nil {
		fmt.Println("cert extraction failed:", err)
		os.Exit(1)
	}
	fmt.Printf("extracted public key DER: %d bytes\n", len(cert))
	fmt.Printf("prefix: %x\n", cert[:33])
	fmt.Printf("tail:   %x\n", cert[len(cert)-16:])

	// Persist the extracted key for the package's official-sample test.
	if err := os.MkdirAll("internal/pbin/testdata", 0o755); err == nil {
		if err := os.WriteFile("internal/pbin/testdata/panoramapack_2023.der", cert, 0o644); err == nil {
			fmt.Println("wrote internal/pbin/testdata/panoramapack_2023.der")
		}
	}

	// Build the key manually: SPKI layout is fixed — modulus at [33:545],
	// then INTEGER tag/len/value for the exponent.
	var rsaPub *rsa.PublicKey
	if len(cert) == 548 && cert[0] == 0x30 && cert[545] == 0x02 {
		n := new(big.Int).SetBytes(cert[33:545])
		eLen := int(cert[546])
		e := 0
		for _, b := range cert[547 : 547+eLen] {
			e = e<<8 | int(b)
		}
		fmt.Printf("parsed key: N=%d bits, E=%d\n", n.BitLen(), e)
		rsaPub = &rsa.PublicKey{N: n, E: e}
	} else {
		fmt.Println("unexpected DER layout; cannot build key manually")
	}

	// Cross-check with the standard parser (informational).
	if pub, err := x509.ParsePKIXPublicKey(cert); err == nil {
		if p, ok := pub.(*rsa.PublicKey); ok && (rsaPub == nil || p.E != rsaPub.E || p.N.Cmp(rsaPub.N) != 0) {
			fmt.Printf("x509 parsed different key: N=%d bits, E=%d\n", p.N.BitLen(), p.E)
		}
	} else {
		fmt.Println("x509 parser:", err)
	}

	data, err := os.ReadFile(pbinPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(data) < 521 || string(data[:3]) != "PAN" {
		fmt.Println("not a pbin")
		os.Exit(1)
	}
	sig := data[4:516]
	trailer := data[len(data)-5:]
	zipEnd := len(data) - 5

	fmt.Printf("file: %d bytes, version %d, trailer %02x\n", len(data), data[3], trailer)

	// Candidate signed ranges (only when a key was reconstructed).
	if rsaPub != nil {
		cands := []struct {
			name string
			msg  []byte
		}{
			{"[516, EOF) zip||trailer (panzip semantics)", data[516:]},
			{"[516, EOF-5) zip only", data[516:zipEnd]},
			{"[4, EOF) sig-included (sanity)", data[4:]},
			{"[0, EOF) whole file (sanity)", data},
		}
		for _, c := range cands {
			sum := sha1.Sum(c.msg)
			err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, sum[:], sig)
			status := "FAIL"
			if err == nil {
				status = "PASS"
			}
			fmt.Printf("verify %-48s len=%-9d %s\n", c.name, len(c.msg), status)
		}
	}

	// Trailer first-four-bytes semantics.
	t4 := trailer[:4]
	le32 := binary.LittleEndian.Uint32(t4)
	be32 := binary.BigEndian.Uint32(t4)
	le16 := binary.LittleEndian.Uint16(t4[:2])
	fmt.Printf("\ntrailer[0:4]=%x  le32=%d(0x%08x) be32=%d(0x%08x) le16=%d(0x%04x) le16[2:]=%d\n",
		t4, le32, le32, be32, be32, le16, le16, binary.LittleEndian.Uint16(t4[2:]))

	zipData := data[516:zipEnd]

	fmt.Println("\n--- trailer[0:4] candidate search ---")
	targets := map[string]uint64{
		"le32":   uint64(binary.LittleEndian.Uint32(t4)),
		"be32":   uint64(binary.BigEndian.Uint32(t4)),
		"le16lo": uint64(binary.LittleEndian.Uint16(t4[:2])),
		"be16lo": uint64(binary.BigEndian.Uint16(t4[:2])),
		"le16hi": uint64(binary.LittleEndian.Uint16(t4[2:])),
		"be16hi": uint64(binary.BigEndian.Uint16(t4[2:])),
	}
	msgs := map[string][]byte{
		"zip":           zipData,
		"zip||trailer4": data[516 : zipEnd+4],
		"zip||trailer":  data[516:],
		"wholeFile":     data,
	}
	// Uncompressed concatenation of all entries, region slices, and
	// aggregates over the per-entry CRC32s stored in the ZIP directory.
	var entryCRCsum, entryCRCxor uint32
	{
		zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err == nil {
			var buf bytes.Buffer
			for _, zf := range zr.File {
				entryCRCsum += zf.CRC32
				entryCRCxor ^= zf.CRC32
				rc, err := zf.Open()
				if err != nil {
					buf.WriteString(zf.Name)
					continue
				}
				io.Copy(&buf, rc)
				rc.Close()
				buf.WriteString(zf.Name)
			}
			msgs["uncompressed+names"] = buf.Bytes()
		}
		if idx := bytes.LastIndex(zipData, []byte{'P', 'K', 0x05, 0x06}); idx >= 0 {
			msgs["preEocd"] = zipData[:idx]
			eocd := zipData[idx:]
			if len(eocd) >= 22 {
				cdSize := binary.LittleEndian.Uint32(eocd[12:16])
				cdOff := binary.LittleEndian.Uint32(eocd[16:20])
				if uint64(cdOff)+uint64(cdSize) <= uint64(len(zipData)) {
					msgs["centralDir"] = zipData[cdOff : cdOff+cdSize]
				}
			}
		}
	}

	type algo struct {
		name string
		fn   func([]byte) uint64
	}
	ieee := crc32.MakeTable(crc32.IEEE)
	cast := crc32.MakeTable(crc32.Castagnoli)
	algo1s := []algo{
		{"crc32ieee", func(b []byte) uint64 { return uint64(crc32.Checksum(b, ieee)) }},
		{"crc32ieee-init0", func(b []byte) uint64 { return uint64(crc32.Update(0, ieee, b)) }},
		{"crc32ieee-noxor", func(b []byte) uint64 { return uint64(crc32.Update(0xFFFFFFFF, ieee, b) ^ 0) }},
		{"crc32castagnoli", func(b []byte) uint64 { return uint64(crc32.Checksum(b, cast)) }},
		{"crc32cast-init0", func(b []byte) uint64 { return uint64(crc32.Update(0, cast, b)) }},
		{"adler32", func(b []byte) uint64 { return uint64(adler32.Checksum(b)) }},
		{"crc16arc", func(b []byte) uint64 { return uint64(crc16Arc(b)) }},
		{"crc16modbus", func(b []byte) uint64 { return uint64(crc16ArcInit(b, 0xFFFF)) }},
		{"crc16ccitt-ffff", func(b []byte) uint64 { return uint64(crc16Ccitt(b, 0xFFFF)) }},
		{"crc16ccitt-0000", func(b []byte) uint64 { return uint64(crc16Ccitt(b, 0)) }},
		{"crc16kermit", func(b []byte) uint64 { return uint64(crc16Kermit(b)) }},
		{"crc16x25", func(b []byte) uint64 { return uint64(crc16X25(b)) }},
	}

	matches := 0
	for _, a := range algo1s {
		for mn, msg := range msgs {
			v := a.fn(msg)
			for tn, t := range targets {
				if v == t {
					fmt.Printf("MATCH  %-18s %-18s == %s (0x%x)\n", a.name, mn, tn, v)
					matches++
				}
			}
			// 16-bit values compared through the low half of 32-bit algs.
			if v > 0xFFFF {
				for _, tn := range []string{"le16lo", "be16lo"} {
					if uint16(v) == uint16(targets[tn]) || uint16(v>>16) == uint16(targets[tn]) {
						fmt.Printf("MATCH? %-18s %-18s half == %s\n", a.name, mn, tn)
						matches++
					}
				}
			}
		}
	}
	// Aggregates over per-entry CRC32s.
	for _, agg := range []struct {
		name string
		v    uint64
	}{{"entryCRC-sum", uint64(entryCRCsum)}, {"entryCRC-xor", uint64(entryCRCxor)}} {
		for tn, t := range targets {
			if agg.v == t {
				fmt.Printf("MATCH  %-18s (aggregate) == %s (0x%x)\n", agg.name, tn, agg.v)
				matches++
			}
		}
	}
	if matches == 0 {
		fmt.Println("no candidate matched trailer[0:4] (semantics still unknown)")
		fmt.Printf("crc32(zip)=0x%08x adler32(zip)=0x%08x crc16arc=0x%04x crc16ccitt=0x%04x entryCRCsum=0x%08x entryCRCxor=0x%08x\n",
			crc32.Checksum(zipData, ieee), adler32.Checksum(zipData), crc16Arc(zipData), crc16Ccitt(zipData, 0xFFFF),
			entryCRCsum, entryCRCxor)
	}
}

func crc16Arc(data []byte) uint16 {
	return crc16ArcInit(data, 0)
}

func crc16ArcInit(data []byte, init uint16) uint16 {
	crc := init
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// crc16Kermit: reflected CCITT (poly 0x8408), init 0.
func crc16Kermit(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func crc16Ccitt(data []byte, init uint16) uint16 {
	crc := init
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func crc16X25(data []byte) uint16 {
	return ^crc16ArcInner(data)
}

func crc16ArcInner(data []byte) uint16 {
	return crc16ArcInit(data, 0)
}
