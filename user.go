package gosrp

import (
	"fmt"
	"math/big"
	"reflect"
)

type User struct {
	srp              *Srp
	username         string
	password         []byte
	ephemeralSecretA []byte
	a                []byte
	A                *big.Int
	k                *big.Int
	hAMK             []byte
}

const EPHEMERAL_SECRET_BYTE_LENGTH = 32

// https://github.com/cocagne/pysrp/blob/master/srp/_pysrp.py
func NewUser(srp *Srp, username string, password []byte) *User {

	k := new(big.Int).SetBytes(srp.Hash(srp.cyclicGroup.Prime.Bytes(), srp.cyclicGroup.Generator.Bytes()))

	a, _ := srp.Random(EPHEMERAL_SECRET_BYTE_LENGTH)
	aAsBigInt := new(big.Int).SetBytes(a)
	A := new(big.Int).Exp(srp.cyclicGroup.Generator, aAsBigInt, srp.cyclicGroup.Prime)
	return &User{srp: srp, username: username, password: password, a: a, A: A, k: k}
}

func (user *User) StartAuthentication() ([]byte, error) {
	return user.A.Bytes(), nil
}

func (user *User) ProcessChallenge(bytesSalt, bytesB []byte) ([]byte, error) {
	bytesA := user.A.Bytes()
	b, err := user.validateB(bytesB)
	if err != nil {
		return nil, err
	}
	u, err := user.srp.calculateU(bytesA, bytesB)
	if err != nil {
		return nil, err
	}

	x := user.srp.calculateX(bytesSalt, []byte(user.username), user.password)
	v := user.srp.calculateV(x)

	S := user.srp.calculateS(bytesToInt(user.a), b, user.k, u, v, x)
	K := user.srp.calculateK(S)
	M := user.srp.calculateM(user.username, bytesSalt, bytesA, bytesB, K)
	H_AMK := user.srp.calculateH_AMK(bytesA, M, K)

	user.hAMK = H_AMK
	return M, nil
}

func (user *User) VerifySession(hAMK []byte) error {
	if reflect.DeepEqual(user.hAMK, hAMK) {
		return nil
	} else {
		return fmt.Errorf("Session verification of hAMK value failed. Server lied to us!")
	}
}

func (user *User) Authenticated() bool {
	return false
}

func (user *User) UserName() string {
	return user.username
}

// validateB does a safety check B is multiple of the group prime N (see SRP-6a safety check)
func (user *User) validateB(BBytes []byte) (*big.Int, error) {
	var q big.Int

	if len(BBytes) != 128 {
		return nil, fmt.Errorf("Expected 32 bytes bot got: %d", len(BBytes))
	}
	b := bytesToInt(BBytes)

	q.Mod(b, user.srp.cyclicGroup.Prime)
	if q.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("SRP-6a safety check for A failed")
	} else {
		return b, nil
	}
}
