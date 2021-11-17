package pblind

import (
	"errors"
)

var (
	ErrorPointNotOnCurve       = errors.New("Point not on curve")
	ErrorInvalidSignerState    = errors.New("Signer is in invalid state")
	ErrorInvalidRequesterState = errors.New("Signer is in invalid state")
	ErrorInvalidSignature      = errors.New("Signature is invalid")
	ErrorInvalidScalar         = errors.New("Scalar is too large")
	ErrorInvalidPublicKey      = errors.New("Public key is invalid")
)
