package pblind

import (
	"errors"
)

var ErrorPointNotOnCurve error = errors.New("Point not on curve")
var ErrorInvalidSignerState error = errors.New("Signer is in invalid state")
var ErrorInvalidRequesterState error = errors.New("Signer is in invalid state")
var ErrorInvalidSignature error = errors.New("Signature is invalid")
