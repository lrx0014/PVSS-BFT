package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
)

// Signer uses ecdsa signature
type Signer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewSigner() (*Signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func NewSignerFromPrivateKey(privateKey *ecdsa.PrivateKey) *Signer {
	return &Signer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}
}

func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

func (s *Signer) PrivateKey() *ecdsa.PrivateKey {
	return s.privateKey
}

func (s *Signer) Sign(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, ss, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// encode signature as r || s (64 bytes)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := ss.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return sig, nil
}

func Verify(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	hash := sha256.Sum256(message)
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func HashMultiple(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// SerializeAndHash serializes an object to JSON and hashes it
func SerializeAndHash(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Hash(data), nil
}

func PublicKeyToBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func BytesToPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, errors.New("invalid public key bytes")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func PrivateKeyToBytes(priv *ecdsa.PrivateKey) []byte {
	return priv.D.Bytes()
}

func BytesToPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.D = new(big.Int).SetBytes(data)
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(data)
	return priv, nil
}

func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}
