package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// VRF implements a Verifiable Random Function based on ECVRF
type VRF struct {
	curve elliptic.Curve
}

type VRFKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// VRFProof contains the VRF output and proof
type VRFProof struct {
	Output []byte // the pseudo-random output (hash)
	Proof  []byte // the proof that output was correctly computed

	Gamma *big.Int // γ = H(α, x)^sk
	C     *big.Int // challenge
	S     *big.Int // response
}

func NewVRF() *VRF {
	return &VRF{
		curve: elliptic.P256(),
	}
}

func (v *VRF) GenerateKey() (*VRFKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(v.curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &VRFKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// Evaluate computes VRF output for a given input (view number)
func (v *VRF) Evaluate(privateKey *ecdsa.PrivateKey, input []byte) (*VRFProof, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	hx, hy := v.hashToCurve(input)

	// compute Y = H^sk (where H is the hashed point)
	gammaX, gammaY := v.curve.ScalarMult(hx, hy, privateKey.D.Bytes())

	// generate random k for proof
	k, err := rand.Int(rand.Reader, v.curve.Params().N)
	if err != nil {
		return nil, err
	}

	// u = g^k
	ux, uy := v.curve.ScalarBaseMult(k.Bytes())

	// v = H^k
	vx, vy := v.curve.ScalarMult(hx, hy, k.Bytes())

	// c = H(g, H, pk, γ, U, V)
	c := v.computeChallenge(
		v.curve.Params().Gx, v.curve.Params().Gy,
		hx, hy,
		privateKey.PublicKey.X, privateKey.PublicKey.Y,
		gammaX, gammaY,
		ux, uy,
		vx, vy,
	)

	// s = k - c*sk mod n
	csk := new(big.Int).Mul(c, privateKey.D)
	s := new(big.Int).Sub(k, csk)
	s.Mod(s, v.curve.Params().N)

	output := v.hashPoint(gammaX, gammaY)

	proof := v.encodeProof(gammaX, gammaY, c, s)

	return &VRFProof{
		Output: output,
		Proof:  proof,
		Gamma:  gammaX,
		C:      c,
		S:      s,
	}, nil
}

func (v *VRF) Verify(publicKey *ecdsa.PublicKey, input []byte, proof *VRFProof) (bool, []byte) {
	if publicKey == nil || proof == nil {
		return false, nil
	}

	gammaX, gammaY, c, s := v.decodeProof(proof.Proof)
	if gammaX == nil {
		return false, nil
	}

	hx, hy := v.hashToCurve(input)

	// Verify: U = g^s * pk^c
	gsX, gsY := v.curve.ScalarBaseMult(s.Bytes())
	pkcX, pkcY := v.curve.ScalarMult(publicKey.X, publicKey.Y, c.Bytes())
	ux, uy := v.curve.Add(gsX, gsY, pkcX, pkcY)

	// Verify: V = H^s * γ^c
	hsX, hsY := v.curve.ScalarMult(hx, hy, s.Bytes())
	gcX, gcY := v.curve.ScalarMult(gammaX, gammaY, c.Bytes())
	vx, vy := v.curve.Add(hsX, hsY, gcX, gcY)

	// Recompute challenge
	cPrime := v.computeChallenge(
		v.curve.Params().Gx, v.curve.Params().Gy,
		hx, hy,
		publicKey.X, publicKey.Y,
		gammaX, gammaY,
		ux, uy,
		vx, vy,
	)

	// Verify c == c'
	if c.Cmp(cPrime) != 0 {
		return false, nil
	}

	output := v.hashPoint(gammaX, gammaY)

	return true, output
}

func (v *VRF) hashToCurve(input []byte) (*big.Int, *big.Int) {
	for ctr := uint32(0); ctr < 256; ctr++ {
		h := sha256.New()
		h.Write(input)
		h.Write([]byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)})
		hash := h.Sum(nil)

		// Try to interpret as x coordinate
		x := new(big.Int).SetBytes(hash)
		x.Mod(x, v.curve.Params().P)

		// Check if x is on curve and compute y
		y := v.computeY(x)
		if y != nil {
			return x, y
		}
	}

	// just a fallback (should not happen in general)
	return v.curve.Params().Gx, v.curve.Params().Gy
}

// computeY computes y coordinate for given x on the curve
func (v *VRF) computeY(x *big.Int) *big.Int {
	// y² = x³ - 3x + b (for P-256)
	p := v.curve.Params().P

	// x^3
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	// 3x
	threeX := new(big.Int).Mul(x, big.NewInt(3))

	// x^3 - 3x
	y2 := new(big.Int).Sub(x3, threeX)

	// + b
	y2.Add(y2, v.curve.Params().B)
	y2.Mod(y2, p)

	// Square root
	y := new(big.Int).ModSqrt(y2, p)
	return y
}

func (v *VRF) computeChallenge(points ...*big.Int) *big.Int {
	h := sha256.New()
	for _, p := range points {
		if p != nil {
			h.Write(p.Bytes())
		}
	}
	hash := h.Sum(nil)

	c := new(big.Int).SetBytes(hash)
	c.Mod(c, v.curve.Params().N)
	return c
}

// hashPoint hashes a curve point to produce VRF output
func (v *VRF) hashPoint(x, y *big.Int) []byte {
	h := sha256.New()
	h.Write([]byte("VRF_OUTPUT"))
	h.Write(x.Bytes())
	h.Write(y.Bytes())
	return h.Sum(nil)
}

func (v *VRF) encodeProof(gammaX, gammaY, c, s *big.Int) []byte {
	// simple encoding: 32 bytes each for gammaX, gammaY, c, s
	proof := make([]byte, 128)

	gxBytes := gammaX.Bytes()
	gyBytes := gammaY.Bytes()
	cBytes := c.Bytes()
	sBytes := s.Bytes()

	copy(proof[32-len(gxBytes):32], gxBytes)
	copy(proof[64-len(gyBytes):64], gyBytes)
	copy(proof[96-len(cBytes):96], cBytes)
	copy(proof[128-len(sBytes):128], sBytes)

	return proof
}

func (v *VRF) decodeProof(proof []byte) (*big.Int, *big.Int, *big.Int, *big.Int) {
	if len(proof) < 128 {
		return nil, nil, nil, nil
	}

	gammaX := new(big.Int).SetBytes(proof[0:32])
	gammaY := new(big.Int).SetBytes(proof[32:64])
	c := new(big.Int).SetBytes(proof[64:96])
	s := new(big.Int).SetBytes(proof[96:128])

	return gammaX, gammaY, c, s
}

// CompareVRFOutputs compares two VRF outputs for leader election
// Returns:
//
//	 1: if a > b
//	-1: if a < b
//	 0: if a == b
func CompareVRFOutputs(a, b []byte) int {
	aInt := new(big.Int).SetBytes(a)
	bInt := new(big.Int).SetBytes(b)
	return aInt.Cmp(bInt)
}
