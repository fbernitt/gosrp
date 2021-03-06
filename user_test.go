package gosrp

import (
	"fmt"
	"testing"

	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"math/big"
)

type UserTestSuite struct {
	suite.Suite
}

func (suite *UserTestSuite) TestCalculatesSameValueForKasPythonSrp() {
	// salt := []byte{0xef, 0x9e, 0xa0, 0x13}
	// verifier := []byte{0x71, 0xee, 0xca, 0xcd, 0x52, 0x8b, 0x08, 0x41, 0x9f, 0xda, 0xa0, 0x6a, 0xfe, 0xcf, 0xa6, 0x61, 0xc4, 0x04, 0x2d, 0x54, 0x47, 0xd8, 0xc5, 0x9f, 0xf2, 0xa6, 0xca, 0xa4, 0x80, 0x76, 0x68, 0x1a, 0xfa, 0x2f, 0xd7, 0xbe, 0xf9, 0x87, 0x41, 0x41, 0x91, 0x7e, 0xec, 0x8f, 0x02, 0xa7, 0x0d, 0x43, 0xd3, 0x8a, 0xfa, 0x0e, 0x6f, 0x2b, 0x48, 0xb6, 0xff, 0xdf, 0x23, 0xbe, 0x31, 0x4e, 0xab, 0x38, 0x60, 0x23, 0x8e, 0xdc, 0xd8, 0x5d, 0x36, 0x24, 0x6a, 0x36, 0x0b, 0x1d, 0x8b, 0x46, 0xfc, 0x7f, 0x5f, 0xfe, 0x82, 0xcc, 0x3a, 0x44, 0x61, 0xf8, 0x17, 0x49, 0x3a, 0x6b, 0x40, 0xf8, 0xa7, 0x7b, 0x67, 0x17, 0x1e, 0xba, 0x9c, 0xd5, 0xb2, 0xf4, 0xe4, 0x8c, 0xcb, 0x7d, 0xda, 0xb6, 0xaf, 0x6f, 0x43, 0x01, 0x27, 0x7f, 0xba, 0x94, 0x34, 0x00, 0x97, 0xf9, 0x97, 0x84, 0xc7, 0x6d, 0x82, 0x89}

	expected_k := new(big.Int)
	kStr := "86573327224338306107651058129804478514389186525412459359309666303778337427184"
	fmt.Sscan(kStr, expected_k)

	srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)
	user := NewUser(srp, "username", []byte("password"))

	assert.Equal(suite.T(), expected_k, user.k)
}

func (suite *UserTestSuite) TestEphemeralSecretAIsRandom() {
	a := []byte{0x87, 0x3e, 0x59, 0x9b, 0x83, 0x56, 0x39, 0x48, 0x8a, 0x3c, 0x46, 0xa1, 0x75, 0x75, 0x10, 0x5c, 0x87, 0xac, 0x1b, 0x21, 0xe5, 0xad, 0xee, 0xce, 0x7d, 0x8c, 0x5a, 0x78, 0x4f, 0x76, 0xf3, 0x7e}
	A := new(big.Int).SetBytes([]byte{0x83, 0xa5, 0xb4, 0x44, 0x9e, 0xf6, 0x82, 0xc6, 0xdf, 0x0c, 0x48, 0x4c, 0x89, 0x53, 0x52, 0x1e, 0xf4, 0x46, 0x0f, 0xca, 0x0b, 0xae, 0x01, 0x6c, 0x1e, 0x1a, 0x43, 0xc5, 0x36, 0xb2, 0x30, 0x68, 0x35, 0x3b, 0x43, 0x19, 0xce, 0x10, 0xd8, 0xdb, 0xa7, 0x4c, 0x93, 0x40, 0x0e, 0xc5, 0xf7, 0x15, 0xa6, 0x61, 0x8c, 0x72, 0xe0, 0x45, 0xcb, 0x3f, 0xd9, 0x39, 0xff, 0xb1, 0xb8, 0x04, 0xd8, 0x7f, 0x75, 0x89, 0x7e, 0x7c, 0xd9, 0x9f, 0xb7, 0x67, 0x06, 0xe5, 0xa5, 0x57, 0x04, 0x08, 0x9b, 0x97, 0xed, 0xd0, 0x50, 0x42, 0x5c, 0x94, 0x6a, 0x15, 0x7e, 0x71, 0x91, 0xeb, 0x8a, 0xe2, 0x69, 0x59, 0x5a, 0xf6, 0x37, 0xf2, 0xfe, 0x91, 0xa6, 0xd0, 0x39, 0xc3, 0x90, 0xff, 0xdf, 0x5f, 0xe0, 0x71, 0x55, 0x71, 0xd5, 0xd8, 0x12, 0x66, 0xb0, 0x5b, 0x0b, 0x46, 0xfd, 0xe3, 0xe5, 0xfe, 0xe2, 0x37})

	srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)

	srp.Random = FixedRandomFunc(a)

	user := NewUser(srp, "username", []byte("password"))

	assert.Equal(suite.T(), a, user.a)
	assert.Equal(suite.T(), A, user.A)
}

func (suite *UserTestSuite) TestStartAuthentication() {
	a := []byte{0x87, 0x3e, 0x59, 0x9b, 0x83, 0x56, 0x39, 0x48, 0x8a, 0x3c, 0x46, 0xa1, 0x75, 0x75, 0x10, 0x5c, 0x87, 0xac, 0x1b, 0x21, 0xe5, 0xad, 0xee, 0xce, 0x7d, 0x8c, 0x5a, 0x78, 0x4f, 0x76, 0xf3, 0x7e}
	A := new(big.Int).SetBytes([]byte{0x83, 0xa5, 0xb4, 0x44, 0x9e, 0xf6, 0x82, 0xc6, 0xdf, 0x0c, 0x48, 0x4c, 0x89, 0x53, 0x52, 0x1e, 0xf4, 0x46, 0x0f, 0xca, 0x0b, 0xae, 0x01, 0x6c, 0x1e, 0x1a, 0x43, 0xc5, 0x36, 0xb2, 0x30, 0x68, 0x35, 0x3b, 0x43, 0x19, 0xce, 0x10, 0xd8, 0xdb, 0xa7, 0x4c, 0x93, 0x40, 0x0e, 0xc5, 0xf7, 0x15, 0xa6, 0x61, 0x8c, 0x72, 0xe0, 0x45, 0xcb, 0x3f, 0xd9, 0x39, 0xff, 0xb1, 0xb8, 0x04, 0xd8, 0x7f, 0x75, 0x89, 0x7e, 0x7c, 0xd9, 0x9f, 0xb7, 0x67, 0x06, 0xe5, 0xa5, 0x57, 0x04, 0x08, 0x9b, 0x97, 0xed, 0xd0, 0x50, 0x42, 0x5c, 0x94, 0x6a, 0x15, 0x7e, 0x71, 0x91, 0xeb, 0x8a, 0xe2, 0x69, 0x59, 0x5a, 0xf6, 0x37, 0xf2, 0xfe, 0x91, 0xa6, 0xd0, 0x39, 0xc3, 0x90, 0xff, 0xdf, 0x5f, 0xe0, 0x71, 0x55, 0x71, 0xd5, 0xd8, 0x12, 0x66, 0xb0, 0x5b, 0x0b, 0x46, 0xfd, 0xe3, 0xe5, 0xfe, 0xe2, 0x37})

	srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)

	srp.Random = FixedRandomFunc(a)

	user := NewUser(srp, "username", []byte("password"))

	actualA, _ := user.StartAuthentication()

	assert.Equal(suite.T(), "username", user.UserName())
	assert.Equal(suite.T(), A.Bytes(), actualA)
}

func (suite *UserTestSuite) TestProcessChallenge() {
	salt := []byte{0x86, 0x27, 0x9c, 0x78}
	a := []byte{0x9a, 0xc8, 0x93, 0xd9, 0x74, 0xb1, 0xd0, 0x93, 0x7b, 0xc4, 0x0c, 0x2d, 0x70, 0xb5, 0xf0, 0x92, 0xde, 0x7f, 0x24, 0x1e, 0x44, 0xc1, 0xb6, 0xba, 0x6b, 0x22, 0xcc, 0x8d, 0xf0, 0x64, 0xec, 0x8e}
	expectedB := new(big.Int).SetBytes([]byte{0x37, 0xc3, 0x3f, 0x07, 0xc5, 0x7b, 0x3b, 0x6f, 0x67, 0xd1, 0x74, 0x3e, 0x24, 0xa7, 0xd0, 0xe5, 0x99, 0x97, 0xf6, 0x98, 0x2d, 0xf3, 0xdb, 0x4b, 0x6c, 0xea, 0x4c, 0xa6, 0x9a, 0x2f, 0x83, 0xc8, 0x54, 0x4e, 0x9c, 0x93, 0x67, 0x7a, 0x08, 0x8f, 0x3f, 0xe7, 0x2b, 0x3a, 0xaf, 0x8d, 0x2b, 0x31, 0x41, 0x8f, 0x16, 0xa2, 0xae, 0xd1, 0x4e, 0xf0, 0x28, 0xd7, 0x53, 0xeb, 0x8c, 0xec, 0xd4, 0xde, 0xd9, 0x59, 0x50, 0x7b, 0xc9, 0x86, 0xb4, 0xe8, 0x1c, 0xc4, 0xed, 0x79, 0x7c, 0x1d, 0xda, 0xaf, 0x7c, 0x9d, 0xc4, 0x5d, 0x34, 0x46, 0x18, 0x60, 0xcb, 0xcc, 0xbd, 0xfb, 0x9a, 0xaa, 0x02, 0x5f, 0x70, 0x6f, 0x98, 0x42, 0x70, 0x3c, 0xd2, 0x70, 0x43, 0xd4, 0x5f, 0xcf, 0x74, 0x14, 0x71, 0xf4, 0xe5, 0x80, 0x95, 0xc2, 0x69, 0x84, 0xc0, 0x4d, 0xf1, 0x50, 0xa8, 0xdc, 0xb9, 0xf1, 0xc0, 0xa2})
	expectedM := []byte{0x91, 0xcb, 0x75, 0x91, 0xf5, 0x22, 0x16, 0x1f, 0x40, 0x31, 0x43, 0xb9, 0xc9, 0xaa, 0x8d, 0x8f, 0x23, 0xf2, 0x3b, 0xb7, 0x55, 0xfb, 0x44, 0xea, 0x3d, 0x95, 0xa6, 0x8c, 0x99, 0xab, 0x7c, 0x1e}

	expectedHAMK := []byte{0x4b, 0x45, 0xdd, 0xb4, 0x5b, 0x31, 0x36, 0x8e, 0x88, 0x2e, 0x70, 0xce, 0xc4, 0xbc, 0x03, 0xda, 0xaa, 0xb8, 0x6f, 0x08, 0x1a, 0xd3, 0x11, 0xe4, 0xf3, 0x46, 0xd9, 0x23, 0xc0, 0xdd, 0x53, 0x33}

	srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)
	srp.Random = FixedRandomFunc(a)

	user := NewUser(srp, "username", []byte("password"))

	M, err := user.ProcessChallenge(salt, expectedB.Bytes())

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), M)
	assert.Equal(suite.T(), expectedM, M)
	assert.Equal(suite.T(), expectedHAMK, user.hAMK)
}

func TestUserTestSuite(t *testing.T) {
	suite.Run(t, new(UserTestSuite))
}
