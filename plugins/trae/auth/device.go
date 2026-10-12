// device.go: EC P-256 device key pair + DeviceProof signing for the bound
// token renewal, shared by the login path (package main wraps the generator)
// and the refresh path (upstream.boundExchangeLocked).
//
// Why (v0.12.73, trae 9074 root cause): a JWT renewed via
// /cloudide/api/v3/trae/oauth/ExchangeToken (ClientID+RefreshToken only)
// carries NO device binding, and Trae CN answers its check-in claim with
// 9074 「当前参与用户太多」 every time while status stays code:0 — the
// official client's own (device-bound) token claims fine at the same moment
// on the same account (magpie#808 mintonight / MiFaZhan side-by-sides,
// 2026-10-05/06; qilimixingkong/trae-checkin TECH_DESIGN §2.8). The bound
// renewal signs with THIS key pair, whose public half the server binds.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

// GenerateDeviceKeyPair creates a fresh P-256 key pair and returns the public
// key as a standard SPKI PEM ("-----BEGIN PUBLIC KEY-----") plus the private
// key as a PKCS#8 PEM — byte-compatible with the official client's uploaded
// DeviceInfo.DevicePublicKey (cockpit-tools pem_wrap shapes).
func GenerateDeviceKeyPair() (publicKeyPEM, privateKeyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate P-256 key: %w", err)
	}
	return marshalDeviceKeyPair(key)
}

// DeterministicDeviceKeyPair derives the SAME P-256 key pair from the SAME
// seed every time (v0.12.77 per-account device identity): the seed — a plain
// SHA-256 digest — is reduced into [1, n-1] as the private scalar and the
// public point follows. Output shapes are byte-identical to
// GenerateDeviceKeyPair (SPKI "PUBLIC KEY" + PKCS#8 "PRIVATE KEY" PEM), so
// the server cannot tell a derived pair from a random one.
//
// The device key is not a secret in the threat model that matters: the
// refresh token is what authenticates a renewal, and the identity file has
// always carried the key pair in plaintext anyway. Determinism is the point —
// the same account always presents the same device, on any install, forever,
// which is exactly the contract the 20401 device-cap lockout demands.
func DeterministicDeviceKeyPair(seed []byte) (publicKeyPEM, privateKeyPEM string, err error) {
	if len(seed) == 0 {
		return "", "", fmt.Errorf("device key seed is empty")
	}
	curve := elliptic.P256()
	n := new(big.Int).Set(curve.Params().N)
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1)) // d ∈ [1, n-1]
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return marshalDeviceKeyPair(key)
}

// marshalDeviceKeyPair renders a P-256 pair in the wire shapes the upstream
// expects (shared by the random and the deterministic generator).
func marshalDeviceKeyPair(key *ecdsa.PrivateKey) (publicKeyPEM, privateKeyPEM string, err error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal SPKI public key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return string(pubPEM), string(privPEM), nil
}

// SignDeviceProof signs payload with the PKCS#8 PEM device private key,
// ECDSA-SHA256, ASN.1 DER, base64 — the official client's DeviceProof
// signature shape (qilimixingkong/trae-checkin _ec_sign cross-verified
// against magpie-community/plugins proofOf).
func SignDeviceProof(privateKeyPEM, payload string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("device private key: bad PEM block %q", blockType(block))
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("device private key parse: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("device private key: %T is not an ECDSA key", key)
	}
	sum := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, ec, sum[:])
	if err != nil {
		return "", fmt.Errorf("device proof sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func blockType(b *pem.Block) string {
	if b == nil {
		return "<nil>"
	}
	return b.Type
}
