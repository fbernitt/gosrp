package gosrp

import (
	"testing"

	"crypto/sha256"
	"crypto/sha512"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AcceptanceTestSuite struct {
	suite.Suite
}

func (suite *AcceptanceTestSuite) TestClientServer() {
	srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)

	passwordVerifier, err := srp.CreateSaltedVerificationKey("username", []byte("password"))

	client_srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)
	server_srp, _ := NewSrp(RFC5054_GROUP_1024, sha256.New)

	user := NewUser(client_srp, "username", []byte("password"))
	verifier := NewVerifier(server_srp, *passwordVerifier)

	A, _ := user.StartAuthentication()
	verifier.StartAuthentication(A)

	salt, B, _ := verifier.Challenge()

	M, _ := user.ProcessChallenge(salt, B)

	hAMK, _ := verifier.VerifySession(M)

	err = user.VerifySession(hAMK)

	assert.NoError(suite.T(), err)
}

func (suite *AcceptanceTestSuite) TestClientServerLargerValues() {
	srp, _ := NewSrp(RFC5054_GROUP_4096, sha512.New)

	passwordVerifier, err := srp.CreateSaltedVerificationKey("username", []byte("password"))
	assert.NoError(suite.T(), err)

	client_srp, _ := NewSrp(RFC5054_GROUP_4096, sha512.New)
	server_srp, _ := NewSrp(RFC5054_GROUP_4096, sha512.New)

	user := NewUser(client_srp, "username", []byte("password"))
	verifier := NewVerifier(server_srp, *passwordVerifier)

	A, err := user.StartAuthentication()
	assert.NoError(suite.T(), err)

	err = verifier.StartAuthentication(A)
	assert.NoError(suite.T(), err)

	salt, B, _ := verifier.Challenge()

	M, _ := user.ProcessChallenge(salt, B)

	hAMK, _ := verifier.VerifySession(M)

	err = user.VerifySession(hAMK)

	assert.NoError(suite.T(), err)
}

func TestAcceptanceTestSuite(t *testing.T) {
	suite.Run(t, new(AcceptanceTestSuite))
}
