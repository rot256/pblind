package pblind

import (
	"crypto/elliptic"
	"crypto/subtle"
	"math/big"
)

func (pk PublicKey) Check(sig Signature, info Info, msg []byte) bool {

	curve := pk.curve
	params := curve.Params()

	lhs := big.NewInt(0)
	lhs.Add(sig.W, sig.G)
	lhs.Mod(lhs, params.N)

	hin := make([]byte, 0, 1024)

	// || p*g + w*y

	func() {
		x1, y1 := curve.ScalarBaseMult(sig.P.Bytes())
		x2, y2 := curve.ScalarMult(pk.x, pk.y, sig.W.Bytes())
		x3, y3 := curve.Add(x1, y1, x2, y2)
		hin = append(hin, elliptic.Marshal(curve, x3, y3)...)
	}()

	// || o*g + g*z

	func() {
		x1, y1 := curve.ScalarBaseMult(sig.O.Bytes())
		x2, y2 := curve.ScalarMult(info.x, info.y, sig.G.Bytes())
		x3, y3 := curve.Add(x1, y1, x2, y2)
		hin = append(hin, elliptic.Marshal(curve, x3, y3)...)
	}()

	// || z || msg

	hin = append(hin, elliptic.Marshal(curve, info.x, info.y)...)
	hin = append(hin, msg...)

	hsh := hashToScalar(curve, hin)
	cmp := subtle.ConstantTimeCompare(lhs.Bytes(), hsh.Bytes())

	return cmp == 1
}
