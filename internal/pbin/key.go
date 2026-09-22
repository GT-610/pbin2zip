package pbin

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"fmt"
)

//go:embed testdata/panoramapack_2023.der
var officialKeyDER []byte

// OfficialPublicKey returns the final (2023) client's pbin verification key,
// extracted from the shipped panorama.dll parser (tools/certcheck). It is the
// key Valve's stock client checks code.pbin signatures against.
func OfficialPublicKey() (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(officialKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parsing embedded official public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("embedded official key is %T, not *rsa.PublicKey", pub)
	}
	return rsaPub, nil
}
