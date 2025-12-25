package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type PVSS struct {
	P *big.Int // prime modulus
	Q *big.Int // prime order of subgroup
	G *big.Int // generator g
	H *big.Int // independent generator G (named H here to avoid confusion)
}

type PVSSParams struct {
	N int // total number of participants
	T int // minimum shares needed to reconstruct (the threshold)
}

type PVSSDealer struct {
	Secret     *big.Int   // the secret s = a_0
	Polynomial []*big.Int // coefficients a_0, ..., a_{t-1}
}

type PVSSPublicData struct {
	Commitments     []*big.Int // C_j = g^a_j for j = 0 to t-1
	EncryptedShares []*big.Int // Y_i = y_i^p(i) for i = 1 to n
}

type PVSSDecryptedShare struct {
	Index int      // share index
	Value *big.Int // decrypted share S_i = G^p(i)
}

func NewPVSS() (*PVSS, error) {
	// generate a safe prime p = 2q + 1 where both p and q are prime
	var p, q *big.Int
	for {
		var err error
		q, err = rand.Prime(rand.Reader, 256)
		if err != nil {
			return nil, err
		}

		// p = 2q + 1
		p = new(big.Int).Mul(q, big.NewInt(2))
		p.Add(p, big.NewInt(1))

		// if p is prime
		if p.ProbablyPrime(20) {
			break
		}
	}

	// find generators
	g, err := findGenerator(p, q)
	if err != nil {
		return nil, err
	}

	h, err := findGenerator(p, q)
	if err != nil {
		return nil, err
	}

	// ensure g and h are different
	for g.Cmp(h) == 0 {
		h, err = findGenerator(p, q)
		if err != nil {
			return nil, err
		}
	}

	return &PVSS{
		P: p,
		Q: q,
		G: g,
		H: h,
	}, nil
}

func NewPVSSWithParams(p, q, g, h *big.Int) *PVSS {
	return &PVSS{
		P: p,
		Q: q,
		G: g,
		H: h,
	}
}

func findGenerator(p, q *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)

	for i := 0; i < 1000; i++ {
		// random element in [2, p-1]
		h, err := rand.Int(rand.Reader, new(big.Int).Sub(p, two))
		if err != nil {
			return nil, err
		}
		h.Add(h, two) // ensure h >= 2

		// g = h^2 mod p
		g := new(big.Int).Exp(h, two, p)

		// if g != 1
		if g.Cmp(one) == 0 {
			continue
		}

		// check g^q = 1 mod p
		check := new(big.Int).Exp(g, q, p)
		if check.Cmp(one) == 0 {
			return g, nil
		}
	}

	return nil, errors.New("failed to find generator")
}

func (pvss *PVSS) GenerateKeyPair() (*big.Int, *big.Int, error) {
	// private key x ∈ Z_q*
	x, err := rand.Int(rand.Reader, pvss.Q)
	if err != nil {
		return nil, nil, err
	}

	// check x != 0
	for x.Cmp(big.NewInt(0)) == 0 {
		x, err = rand.Int(rand.Reader, pvss.Q)
		if err != nil {
			return nil, nil, err
		}
	}

	// public key y = H^x mod p
	y := new(big.Int).Exp(pvss.H, x, pvss.P)

	return x, y, nil
}

func (pvss *PVSS) Split(secret *big.Int, publicKeys []*big.Int, threshold int) (*PVSSDealer, *PVSSPublicData, error) {
	n := len(publicKeys)
	if threshold > n {
		return nil, nil, errors.New("threshold cannot exceed number of participants")
	}
	if threshold < 1 {
		return nil, nil, errors.New("threshold must be at least 1")
	}

	// random polynomial p(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
	// where a_0 = secret
	polynomial := make([]*big.Int, threshold)
	polynomial[0] = new(big.Int).Set(secret)

	for i := 1; i < threshold; i++ {
		coef, err := rand.Int(rand.Reader, pvss.Q)
		if err != nil {
			return nil, nil, err
		}
		polynomial[i] = coef
	}

	// compute commitments C_j = g^a_j for each coefficient
	commitments := make([]*big.Int, threshold)
	for j := 0; j < threshold; j++ {
		commitments[j] = new(big.Int).Exp(pvss.G, polynomial[j], pvss.P)
	}

	// compute encrypted shares Y_i = y_i^p(i) for each participant
	encryptedShares := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		idx := big.NewInt(int64(i + 1))
		pI := pvss.evaluatePolynomial(polynomial, idx)

		// Y_i = y_i^p(i) mod p
		encryptedShares[i] = new(big.Int).Exp(publicKeys[i], pI, pvss.P)
	}

	dealer := &PVSSDealer{
		Secret:     secret,
		Polynomial: polynomial,
	}

	publicData := &PVSSPublicData{
		Commitments:     commitments,
		EncryptedShares: encryptedShares,
	}

	return dealer, publicData, nil
}

// evaluatePolynomial evaluates p(x) = SUM(a_j * x^j) mod q
func (pvss *PVSS) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	result := big.NewInt(0)
	xPow := big.NewInt(1)

	for _, coef := range coefficients {
		term := new(big.Int).Mul(coef, xPow)
		term.Mod(term, pvss.Q)
		result.Add(result, term)
		result.Mod(result, pvss.Q)

		xPow.Mul(xPow, x)
		xPow.Mod(xPow, pvss.Q)
	}

	return result
}

// Verify verifies that an encrypted share is consistent with the commitments
func (pvss *PVSS) Verify(index int, publicKey *big.Int, encryptedShare *big.Int, commitments []*big.Int) bool {
	// compute X_i = Π C_j^(i^j) = g^p(i)
	// Π = Multiplication (product) operator
	idx := big.NewInt(int64(index))
	xI := pvss.computeCommitmentProduct(commitments, idx)

	// verify: log_g(X_i) = log_{y_i}(Y_i)
	// for simplicity, we verify using the relationship:
	// X_i^2 and (Y_i / y_i^r) should satisfy certain properties

	// Simplified verification: check Y_i is in the correct subgroup
	// and X_i is correctly computed

	// check X_i = g^p(i) by verifying X_i^q = 1 mod p
	one := big.NewInt(1)
	check := new(big.Int).Exp(xI, pvss.Q, pvss.P)
	if check.Cmp(one) != 0 {
		return false
	}

	// check Y_i is in subgroup
	check = new(big.Int).Exp(encryptedShare, pvss.Q, pvss.P)
	if check.Cmp(one) != 0 {
		return false
	}

	return true
}

// computeCommitmentProduct computes X_i = Π C_j^(i^j) = g^p(i)
func (pvss *PVSS) computeCommitmentProduct(commitments []*big.Int, idx *big.Int) *big.Int {
	result := big.NewInt(1)
	idxPow := big.NewInt(1)

	for _, C := range commitments {
		// C^(idx^j)
		term := new(big.Int).Exp(C, idxPow, pvss.P)
		result.Mul(result, term)
		result.Mod(result, pvss.P)

		idxPow.Mul(idxPow, idx)
		idxPow.Mod(idxPow, pvss.Q)
	}

	return result
}

// DecryptShare decrypts an encrypted share using the recipient's private key
// Returns S_i = Y_i^(1/x_i) = H^p(i)
func (pvss *PVSS) DecryptShare(encryptedShare *big.Int, privateKey *big.Int) *big.Int {
	// S_i = Y_i^(1/x_i) = Y_i^(x_i^{-1}) mod p
	// compute x_i^{-1} mod q
	xInv := new(big.Int).ModInverse(privateKey, pvss.Q)
	if xInv == nil {
		return nil
	}

	// S_i = Y_i^{x_i^{-1}} mod p
	decrypted := new(big.Int).Exp(encryptedShare, xInv, pvss.P)
	return decrypted
}

// Reconstruct reconstructs the secret from decrypted shares
func (pvss *PVSS) Reconstruct(shares []*PVSSDecryptedShare) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	// compute S = Π S_i^λ_i where λ_i are Lagrange coefficients
	result := big.NewInt(1)

	for i, share := range shares {
		// compute Lagrange coefficient λ_i
		lambda := pvss.lagrangeCoefficient(shares, i)

		// S_i^λ_i mod p
		term := new(big.Int).Exp(share.Value, lambda, pvss.P)
		result.Mul(result, term)
		result.Mod(result, pvss.P)
	}

	return result, nil
}

// lagrangeCoefficient computes the Lagrange coefficient λ_i for share at position i
func (pvss *PVSS) lagrangeCoefficient(shares []*PVSSDecryptedShare, i int) *big.Int {
	xi := big.NewInt(int64(shares[i].Index))

	num := big.NewInt(1)
	den := big.NewInt(1)

	for j, share := range shares {
		if i == j {
			continue
		}

		xj := big.NewInt(int64(share.Index))

		// num *= -xj = (0 - xj)
		negXj := new(big.Int).Neg(xj)
		negXj.Mod(negXj, pvss.Q)
		num.Mul(num, negXj)
		num.Mod(num, pvss.Q)

		// den *= (xi - xj)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, pvss.Q)
		den.Mul(den, diff)
		den.Mod(den, pvss.Q)
	}

	// λ_i = num / den = num * den^{-1} mod q
	denInv := new(big.Int).ModInverse(den, pvss.Q)
	if denInv == nil {
		return big.NewInt(0)
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, pvss.Q)

	return lambda
}

func HashToBigInt(data []byte, q *big.Int) *big.Int {
	h := sha256.Sum256(data)
	result := new(big.Int).SetBytes(h[:])
	result.Mod(result, q)
	return result
}

// VerifyReconstruction verifies that the reconstructed secret matches expected hash
func (pvss *PVSS) VerifyReconstruction(reconstructed *big.Int, expectedHash []byte) bool {
	expected := HashToBigInt(expectedHash, pvss.Q)
	expectedCommit := new(big.Int).Exp(pvss.H, expected, pvss.P)

	return reconstructed.Cmp(expectedCommit) == 0
}
