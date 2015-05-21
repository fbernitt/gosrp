package gosrp

import (
	"fmt"
	"math/big"
	"reflect"
)

type Verifier struct {
	srp              *Srp
	passwordVerifier PasswordVerifier
	k                *big.Int
	A                *big.Int
	B                *big.Int
	b                []byte
}

func NewVerifier(srp *Srp, passwordVerifier PasswordVerifier) *Verifier {
	k := new(big.Int).SetBytes(srp.Hash(srp.cyclicGroup.Prime.Bytes(), srp.cyclicGroup.Generator.Bytes()))

	return &Verifier{srp: srp, passwordVerifier: passwordVerifier, k: k}
}

func (verifier *Verifier) StartAuthentication(ABytes []byte) error {
	A, err := verifier.validateA(ABytes)
	if err != nil {
		return err
	}

	verifier.A = A
	return nil
}

func (verifier *Verifier) Challenge() (bytesSalt []byte, bytesM []byte, err error) {
	return verifier.passwordVerifier.Salt, verifier.B.Bytes(), nil
}

func (verifier *Verifier) calculateS(a, u, v *big.Int) *big.Int {
	c1 := new(big.Int).Mul(a, new(big.Int).Exp(v, u, verifier.srp.cyclicGroup.Prime))
	return new(big.Int).Exp(c1, bytesToInt(verifier.b), verifier.srp.cyclicGroup.Prime)
}

func (verifier *Verifier) VerifySession(MBytes []byte) (hAMK []byte, err error) {
	u, err := verifier.srp.calculateU(verifier.A.Bytes(), verifier.B.Bytes())
	if err != nil {
		return nil, err
	}
	S := verifier.calculateS(verifier.A, u, bytesToInt(verifier.passwordVerifier.Verifier))
	K := verifier.srp.calculateK(S)
	M := verifier.srp.calculateM(verifier.passwordVerifier.Username, verifier.passwordVerifier.Salt, verifier.A.Bytes(), verifier.B.Bytes(), K)
	hAMK = verifier.srp.calculateH_AMK(verifier.A.Bytes(), M, K)
	//FIXME compare in constant time
	if reflect.DeepEqual(M, MBytes) {
		return hAMK, nil
	} else {
		return nil, fmt.Errorf("Verification of M failed")
	}
	return hAMK, nil
}

func bytesToInt(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}

// validateA does a safety check A is multiple of the group prime N (see SRP-6a safety check)
func (verifier *Verifier) validateA(ABytes []byte) (*big.Int, error) {
	var q big.Int

	if len(ABytes) != verifier.srp.primeByteSize {
		return nil, fmt.Errorf("Expected 128 bytes bot got: %d", len(ABytes))
	}
	a := bytesToInt(ABytes)

	q.Mod(a, verifier.srp.cyclicGroup.Prime)
	if q.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("SRP-6a safety check for A failed")
	} else {
		verifier.b, verifier.B = verifier.calculateRandomB()
		return a, nil
	}
}

func (verifier *Verifier) calculateRandomB() ([]byte, *big.Int) {
	//FIXME err on random function fail currently ignored
	randomB, _ := verifier.srp.Random(32)

	// self.B = (k*v + exp(g, self.b, N)) % N
	v := bytesToInt(verifier.passwordVerifier.Verifier)
	b := bytesToInt(randomB)

	intermediate := new(big.Int).Exp(verifier.srp.cyclicGroup.Generator, b, verifier.srp.cyclicGroup.Prime)

	B := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(verifier.k, v), intermediate), verifier.srp.cyclicGroup.Prime)

	return randomB, B
}
