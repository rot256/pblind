package pblind

import (
	"crypto/elliptic"
	"math/big"
)

func CheckSignature(curve elliptic.Curve, pk PublicKey, sig Signature) bool {

	params := curve.Params()

	lhs := big.NewInt(0)
	lhs.Add(sig.w, sig.g)
	lhs.Mod(lhs, params.N)

	return false

}
